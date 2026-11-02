"""Read-only, authenticated dashboard for the independently running collector.

The intended deployment is one Gunicorn worker on loopback, reached through an
SSH tunnel. Login throttling is process-local; this is deliberately not an
Internet-facing identity service. No request can train a model or execute a
command. All storage access here is explicitly read-only.
"""

from __future__ import annotations

import hmac
import json
import math
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.exceptions import SecurityError
from werkzeug.security import check_password_hash

from . import __version__
from .config import AppConfig, load_config
from .storage import Repository

DETECTORS = {
    "ssh.failed_burst": "Mange fejlede forsøg",
    "ssh.preauth_burst": "Gentagne afbrud før login",
    "ssh.user_spray": "Flere brugernavne",
    "ssh.unexpected_success": "Uventet login",
    "ssh.isolation_forest": "Isolation Forest",
    "network.tcp_port_scan": "Mulig TCP-portscanning",
}
PERIODS = (
    (1, "Seneste time"),
    (6, "Seneste 6 timer"),
    (24, "Seneste døgn"),
    (168, "Seneste 7 dage"),
    (720, "Seneste 30 dage"),
)


class DataUnavailable(RuntimeError):
    """Database is not readable; never silently display made-up zero values."""


class LoginThrottle:
    """Bounded per-process login throttle, based on the actual peer address."""

    def __init__(self, limit: int = 8, interval: int = 300) -> None:
        self.limit, self.interval = limit, interval
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _recent(self, peer: str, now: float) -> deque[float]:
        times = self._attempts.setdefault(peer, deque())
        while times and times[0] <= now - self.interval:
            times.popleft()
        self._attempts.move_to_end(peer)
        while len(self._attempts) > 1024:
            self._attempts.popitem(last=False)
        return times

    def wait(self, peer: str) -> int:
        with self._lock:
            now = time.monotonic()
            times = self._recent(peer, now)
            return (
                max(1, math.ceil(times[0] + self.interval - now)) if len(times) >= self.limit else 0
            )

    def failed(self, peer: str) -> None:
        with self._lock:
            self._recent(peer, time.monotonic()).append(time.monotonic())

    def clear(self, peer: str) -> None:
        with self._lock:
            self._attempts.pop(peer, None)


def _credentials(path: Path) -> dict[str, str]:
    try:
        if path.stat().st_size > 16384:
            raise ValueError("credential file is too large")
        data = json.loads(path.read_text(encoding="utf-8"))
        key, hashed = data["secret_key"], data["password_hash"]
        if not isinstance(key, str) or len(key) < 32 or len(key) > 512:
            raise ValueError("secret_key must contain at least 32 characters")
        if not isinstance(hashed, str) or len(hashed) > 2048:
            raise ValueError("invalid password hash")
        if not hashed.startswith(("scrypt:", "pbkdf2:sha256:")) or hashed.count("$") != 2:
            raise ValueError("unsupported password hash")
        return {"secret_key": key, "password_hash": hashed}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(
            "Dashboardets adgangsoplysninger mangler eller er ugyldige. "
            "Kør 'yggdrasil-ids credentials --config …' før webserveren startes."
        ) from exc


def create_app(config: AppConfig | None = None) -> Flask:
    cfg = config or load_config()
    credentials = _credentials(Path(cfg.credentials_path))
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=credentials["secret_key"],
        SESSION_COOKIE_NAME="yggdrasil_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # Loopback HTTP travels inside the SSH tunnel. HTTPS deployments need a
        # separate access design and Secure cookies, not a public HTTP bind.
        SESSION_COOKIE_SECURE=False,
        SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=cfg.web.session_minutes),
        TRUSTED_HOSTS=list(cfg.web.trusted_hosts),
        MAX_CONTENT_LENGTH=8192,
        MAX_FORM_MEMORY_SIZE=8192,
        MAX_FORM_PARTS=8,
        JSON_SORT_KEYS=False,
    )
    repo = Repository(cfg.database_path, readonly=True)
    app.extensions["ids_repository"] = repo
    app.extensions["ids_config"] = cfg
    throttle = LoginThrottle()
    app.extensions["ids_login_throttle"] = throttle
    local_zone = ZoneInfo(cfg.timezone)

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def csrf_valid() -> bool:
        received = request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not (
            isinstance(received, str)
            and isinstance(expected, str)
            and 0 < len(received) <= 128
            and expected
        ):
            return False
        origin = request.headers.get("Origin")
        if origin:
            parsed = urlsplit(origin)
            if (parsed.scheme, parsed.netloc) != (request.scheme, request.host):
                return False
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            return False
        return hmac.compare_digest(received, expected)

    def query_int(name: str, default: int, low: int, high: int) -> int:
        raw = request.args.get(name)
        if raw is None:
            return default
        if len(request.args.getlist(name)) != 1 or not raw.isascii() or not raw.isdigit():
            abort(400, description=f"Ugyldig værdi for {name}.")
        if len(raw) > 8:
            abort(400, description=f"Ugyldig værdi for {name}.")
        value = int(raw)
        if not low <= value <= high:
            abort(400, description=f"{name} skal være mellem {low} og {high}.")
        return value

    def query_text(name: str, max_length: int = 128) -> str:
        raw = request.args.get(name, "").strip()
        if (
            len(request.args.getlist(name)) > 1
            or len(raw) > max_length
            or any(ord(c) < 32 for c in raw)
        ):
            abort(400, description=f"Ugyldig værdi for {name}.")
        return raw

    def hours() -> int:
        return query_int("hours", 24, 1, 720)

    def paging() -> dict[str, int]:
        return {
            "page": query_int("page", 1, 1, 100000),
            "per_page": query_int("per_page", 25, 10, 100),
        }

    def call(method: str, **kwargs: Any) -> Any:
        try:
            return getattr(app.extensions["ids_repository"], method)(**kwargs)
        except (sqlite3.Error, OSError, ValueError) as exc:
            app.logger.warning("Read-only repository unavailable: %s", type(exc).__name__)
            raise DataUnavailable from exc

    def status_view(status: dict[str, Any]) -> dict[str, Any]:
        collector = status.get("collector") or {}
        model = status.get("model") or {}
        state = collector.get("state", "unknown")
        heartbeat = collector.get("heartbeat_at")
        age = None
        if isinstance(heartbeat, (int, float)) and math.isfinite(heartbeat):
            age = max(0, time.time() - heartbeat)
        stale = state == "running" and (
            age is None or age > max(30, cfg.collector.heartbeat_seconds * 3)
        )
        if stale:
            state = "stale"
        labels = {
            "running": ("Collector aktiv", "good"),
            "replay": ("Genafspillede data", "info"),
            "starting": ("Collector starter", "warning"),
            "stopped": ("Collector stoppet", "warning"),
            "error": ("Collector har en fejl", "danger"),
            "stale": ("Collector svarer ikke", "danger"),
            "unknown": ("Collector ikke startet", "warning"),
        }
        label, tone = labels.get(state, ("Ukendt collectorstatus", "warning"))
        ml_labels = {
            "ready": ("Model indlæst", "good"),
            "untrained": ("Model ikke trænet", "warning"),
            "error": ("Modelfejl", "danger"),
        }
        ml_label, ml_tone = ml_labels.get(model.get("state"), ("Model ikke indlæst", "warning"))
        return {
            "collector_label": label,
            "collector_tone": tone,
            "collector_state": state,
            "collector_age": age,
            "model_label": ml_label,
            "model_tone": ml_tone,
            "collector": collector,
            "model": model,
            "counters": status.get("counters") or {},
            "data_gap": status.get("data_gap"),
            "data_quality": status.get("data_quality"),
            "analysis_error": status.get("analysis_error"),
        }

    def read_status() -> dict[str, Any]:
        raw = call("status")
        if raw.get("mode") is not None and raw["mode"] != cfg.mode:
            raise DataUnavailable("Database and dashboard belong to different environments")
        g.ids_status = status_view(raw)
        return raw

    @app.template_filter("localtime")
    def localtime(value: Any, short: bool = False) -> str:
        if not isinstance(value, (str, int, float)):
            return "—"
        try:
            if isinstance(value, str) and ("T" in value):
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.utcoffset() is None:
                    return "—"
                dt = dt.astimezone(local_zone)
            else:
                dt = datetime.fromtimestamp(float(value), timezone.utc).astimezone(local_zone)
            return dt.strftime("%H:%M:%S" if short else "%d.%m.%Y · %H:%M:%S")
        except (ValueError, TypeError, OverflowError, OSError):
            return "—"

    @app.template_filter("score")
    def score(value: Any) -> str:
        if not isinstance(value, (str, int, float)):
            return "—"
        try:
            v = float(value)
            return f"{v:.3f}" if math.isfinite(v) else "—"
        except (ValueError, TypeError):
            return "—"

    @app.template_filter("number")
    def number(value: Any) -> str:
        if not isinstance(value, (str, int, float)):
            return "—"
        try:
            return f"{int(value):,}".replace(",", ".")
        except (ValueError, TypeError, OverflowError):
            return "—"

    @app.context_processor
    def template_context() -> dict[str, Any]:
        def page_url(page: int) -> str:
            args = request.args.to_dict()
            args["page"] = str(page)
            return url_for(request.endpoint or "overview", **args)

        return {
            "app_cfg": cfg,
            "app_version": __version__,
            "csrf_token": csrf_token,
            "periods": PERIODS,
            "detector_names": DETECTORS,
            "page_url": page_url,
            "view_status": getattr(g, "ids_status", status_view({})),
            "authenticated": bool(session.get("authenticated")),
        }

    @app.before_request
    def authenticate() -> Any:
        # Host validation can leave Flask without a URL adapter. Do not render a
        # template or construct redirects until the request has a trusted host.
        if isinstance(request.routing_exception, SecurityError):
            return app.response_class("Ugyldigt værtsnavn.", status=400, mimetype="text/plain")
        if request.endpoint in {"static", "login"}:
            return None
        if session.get("authenticated"):
            started = session.get("authenticated_at", 0)
            if (
                isinstance(started, (int, float))
                and 0 <= time.time() - started <= cfg.web.session_minutes * 60
            ):
                return None
            session.clear()
        if request.path.startswith(("/api/", "/assets/")) or request.path == "/healthz":
            return jsonify(
                error="authentication_required", message="Log ind igen for at fortsætte."
            ), 401
        return redirect(url_for("login"))

    @app.after_request
    def security_headers(response: Any) -> Any:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Chromium turns a form POST's Origin into "null" under no-referrer,
        # including same-origin login/logout forms. Keep same-origin provenance
        # for CSRF validation without sending referrers to other origins.
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if session.get("authenticated") and request.method == "GET":
            started = session.get("authenticated_at", 0)
            if (
                isinstance(started, (int, float))
                and 0 <= time.time() - started <= cfg.web.session_minutes * 60
            ):
                return redirect(url_for("overview"))
            session.clear()
        if request.method == "GET":
            return render_template("login.html", error=None)
        if not csrf_valid():
            return render_template("login.html", error="Formularen er udløbet. Prøv igen."), 400
        peer = request.remote_addr or "unknown"
        wait = throttle.wait(peer)
        if wait:
            response = app.make_response(
                (
                    render_template(
                        "login.html",
                        error="For mange loginforsøg. Vent nogle minutter, og prøv igen.",
                    ),
                    429,
                )
            )
            response.headers["Retry-After"] = str(wait)
            return response
        password = request.form.get("password", "")
        valid = False
        if 0 < len(password) <= 1024:
            try:
                valid = check_password_hash(credentials["password_hash"], password)
            except (ValueError, TypeError):
                valid = False
        if not valid:
            throttle.failed(peer)
            return render_template("login.html", error="Adgangskoden er ikke korrekt."), 401
        throttle.clear(peer)
        session.clear()
        session["authenticated"] = True
        session["authenticated_at"] = time.time()
        session.permanent = True
        csrf_token()
        return redirect(url_for("overview"))

    @app.post("/logout")
    def logout() -> Any:
        if not csrf_valid():
            abort(400, description="Formularen er udløbet. Opdatér siden, og prøv igen.")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def overview() -> Any:
        period = hours()
        read_status()
        data = call("dashboard", hours=period)
        return render_template("overview.html", data=data, hours=period)

    @app.get("/events")
    def events() -> Any:
        period = hours()
        outcome = query_text("outcome", 16)
        if outcome not in {"", "success", "failure"}:
            abort(400, description="Ukendt loginresultat.")
        source, user = query_text("source", 64), query_text("user")
        read_status()
        result = call(
            "list_events", hours=period, outcome=outcome, source=source, user=user, **paging()
        )
        return render_template(
            "events.html", result=result, hours=period, outcome=outcome, source=source, user=user
        )

    @app.get("/network")
    def network() -> Any:
        period = hours()
        source, protocol = query_text("source", 64), query_text("protocol", 16)
        if protocol not in {"", "TCP", "UDP", "IGMP", "ICMP", "ICMPV6"}:
            abort(400, description="Ukendt netværksprotokol.")
        raw = read_status()
        result = call("list_firewall", hours=period, source=source, protocol=protocol, **paging())
        summary = call("firewall_summary", hours=period)
        return render_template(
            "network.html",
            result=result,
            summary=summary,
            hours=period,
            source=source,
            protocol=protocol,
            network_error=raw.get("network_analysis_error"),
        )

    @app.get("/api/network-charts")
    def api_network_charts() -> Any:
        period = hours()
        read_status()
        return jsonify(
            data=call("firewall_charts", hours=period),
            hours=period,
            server_time=time.time(),
        )

    @app.get("/preauth")
    def preauth() -> Any:
        period = hours()
        read_status()
        result = call("list_preauth", hours=period, **paging())
        return render_template("preauth.html", result=result, hours=period)

    @app.get("/alerts")
    def alerts() -> Any:
        period, detector = hours(), query_text("detector", 64)
        if detector and detector not in DETECTORS:
            abort(400, description="Ukendt detektor.")
        read_status()
        result = call("list_alerts", hours=period, detector=detector, **paging())
        return render_template("alerts.html", result=result, hours=period, detector=detector)

    @app.get("/alerts/<int:alert_id>")
    def alert_detail(alert_id: int) -> Any:
        if alert_id > 9223372036854775807:
            abort(404)
        read_status()
        alert = call("alert_detail", alert_id=alert_id)
        if alert is None:
            abort(404)
        return render_template("alert_detail.html", alert=alert)

    @app.get("/model")
    def model() -> Any:
        period = hours()
        raw = read_status()
        result = call("list_observations", hours=period, **paging())
        return render_template(
            "model.html", result=result, hours=period, model=raw.get("model") or {}
        )

    @app.get("/status")
    def system_status() -> Any:
        raw = read_status()
        return render_template("status.html", raw=raw)

    @app.get("/api/overview")
    def api_overview() -> Any:
        period = hours()
        raw = read_status()
        return jsonify(
            data=call("dashboard", hours=period),
            status=g.ids_status,
            mode=cfg.mode,
            hours=period,
            server_time=time.time(),
            timezone=cfg.timezone,
            source_kind=raw.get("source_kind"),
        )

    @app.get("/api/status")
    def api_status() -> Any:
        read_status()
        return jsonify(status=g.ids_status, mode=cfg.mode, server_time=time.time())

    @app.get("/healthz")
    def health() -> Any:
        read_status()
        ready = g.ids_status["collector_state"] in {"running", "replay"}
        return jsonify(
            ready=ready, collector=g.ids_status["collector_state"]
        ), 200 if ready else 503

    @app.get("/assets/plotly.min.js")
    def plotly_asset() -> Any:
        import plotly

        asset = Path(plotly.__file__).parent / "package_data" / "plotly.min.js"
        return send_file(asset, mimetype="application/javascript", conditional=True)

    @app.errorhandler(DataUnavailable)
    def unavailable(_error: Any) -> Any:
        if request.path.startswith("/api/") or request.path == "/healthz":
            return jsonify(
                error="data_unavailable",
                message="Historikken kan ikke læses. Kontrollér database og adgangsrettigheder.",
            ), 503
        return render_template(
            "error.html",
            code=503,
            title="Historikken er ikke tilgængelig",
            message="Databasen kan ikke læses. Kontrollér collectorens opsætning og webprocessens læseadgang. Der vises ingen tal, før data kan læses.",
        ), 503

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    def request_error(error: Any) -> Any:
        code = error.code
        message = {
            400: "Forespørgslen indeholder en ugyldig værdi.",
            404: "Siden eller alarmen findes ikke.",
            405: "Denne handling understøttes ikke.",
            413: "Forespørgslen er for stor.",
        }.get(code, "Forespørgslen kunne ikke behandles.")
        if request.path.startswith("/api/"):
            return jsonify(error="invalid_request", message=message), code
        # For malformed/untrusted hosts, never build absolute links from that host.
        return render_template(
            "error.html", code=code, title="Forespørgslen kunne ikke behandles", message=message
        ), code

    @app.errorhandler(500)
    def internal_error(_error: Any) -> Any:
        if request.path.startswith("/api/"):
            return jsonify(error="internal_error", message="Der opstod en intern fejl."), 500
        return render_template(
            "error.html",
            code=500,
            title="Der opstod en intern fejl",
            message="Prøv igen om lidt. Se webtjenestens log, hvis fejlen fortsætter.",
        ), 500

    return app
