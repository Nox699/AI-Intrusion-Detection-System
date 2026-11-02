"""HTTP boundary tests using the real read-only SQLite repository.

These tests verify user-visible data, authentication, request boundaries and
failure states. They do not contact a Pi or a third-party service.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import replace
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest
from werkzeug.security import generate_password_hash

from yggdrasil_ids.config import AppConfig
from yggdrasil_ids.domain import Finding, SSHEvent
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.web import create_app


class RenderedPage(HTMLParser):
    """Inspect controls and actual rows, rather than only checking HTTP 200."""

    def __init__(self, html):
        super().__init__()
        self.options = {}
        self.links = []
        self.rows = []
        self._select = None
        self._tbody = False
        self._row = None
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "select":
            self._select = attributes.get("id")
            self.options[self._select] = []
        elif tag == "option" and self._select is not None:
            self.options[self._select].append((attributes.get("value"), "selected" in attributes))
        elif tag == "a":
            self.links.append(attributes.get("href", ""))
        elif tag == "tbody":
            self._tbody = True
        elif tag == "tr" and self._tbody:
            self._row = []

    def handle_endtag(self, tag):
        if tag == "select":
            self._select = None
        elif tag == "tbody":
            self._tbody = False
        elif tag == "tr" and self._row is not None:
            self.rows.append(" ".join(self._row))
            self._row = None

    def handle_data(self, data):
        if self._row is not None and data.strip():
            self._row.append(data.strip())

    def pagination_links(self, path):
        return {
            int(parse_qs(urlsplit(href).query)["page"][0]): href
            for href in self.links
            if urlsplit(href).path == path and "page" in parse_qs(urlsplit(href).query)
        }


@pytest.fixture
def configured(tmp_path):
    credentials = tmp_path / "web.json"
    credentials.write_text(
        json.dumps(
            {
                "password_hash": generate_password_hash(
                    "correct-test-password", method="pbkdf2:sha256:1000"
                ),
                "secret_key": "a-test-secret-of-more-than-thirty-two-characters",
            }
        )
    )
    cfg = AppConfig(
        database_path=tmp_path / "events.sqlite3",
        model_path=tmp_path / "model.json",
        credentials_path=credentials,
        mode="live",
    )
    repo = Repository(cfg.database_path)
    repo.initialize()
    now = time.time() - 10
    event = SSHEvent(
        "event-a",
        now,
        "192.0.2.1",
        "labuser",
        "success",
        "publickey",
        "yggdrasil",
        "Accepted publickey for labuser",
        "1234",
        "cursor-a",
    )
    with repo.transaction() as db:
        repo.insert_event(db, event)
        repo.add_finding(
            db,
            Finding(
                "ssh.unexpected_success",
                "Uventet login",
                "medium",
                "Kilden er uden for den forventede liste.",
                event.source_ip,
                event.event_id,
                event.timestamp,
                {"source": event.source_ip},
            ),
            300,
        )
    repo.set_state("mode", "live")
    repo.set_state(
        "collector", {"state": "running", "heartbeat_at": time.time(), "last_record_at": now}
    )
    repo.set_state("model", {"state": "untrained", "message": "Ingen model endnu"})
    repo.set_state("counters", {"records": 2, "events": 1, "ignored": 1})
    return cfg, repo


@pytest.fixture
def paginated_history(configured):
    repo = configured[1]
    now = time.time() - 100
    with repo.transaction() as db:
        for index in range(31):
            event = SSHEvent(
                f"page-event-{index:02d}",
                now + index,
                "192.0.2.77",
                "qa-user",
                "failure",
                "password",
                "yggdrasil",
                f"Failed password for qa-user; event {index:02d}",
            )
            repo.insert_event(db, event)
            repo.add_finding(
                db,
                Finding(
                    "ssh.failed_burst",
                    f"Kontrolleret alarm {index:02d}",
                    "medium",
                    "Testhistorik med flere sider.",
                    event.source_ip,
                    event.event_id,
                    event.timestamp,
                ),
                cooldown=0,
            )
            db.execute(
                "INSERT INTO observations(event_id,timestamp,source_ip,features,state) "
                "VALUES(?,?,?,?,?)",
                (
                    event.event_id,
                    event.timestamp,
                    event.source_ip,
                    json.dumps({"test_marker": index}),
                    "untrained",
                ),
            )
    return repo


@pytest.fixture
def app(configured):
    application = create_app(configured[0])
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    response = client.get("/login")
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, response.data
    return match.group(1).decode()


def login(client):
    response = client.post(
        "/login", data={"csrf_token": csrf(client), "password": "correct-test-password"}
    )
    assert response.status_code == 302
    return response


@pytest.mark.parametrize(
    "path", ["/", "/events", "/network", "/alerts", "/alerts/1", "/model", "/status"]
)
def test_sensitive_pages_require_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert response.location == "/login"
    assert "192.0.2.1" not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    "path", ["/api/overview", "/api/status", "/healthz", "/assets/plotly.min.js"]
)
def test_machine_endpoints_return_401_without_leaking_data(client, path):
    response = client.get(path)
    assert response.status_code == 401
    assert response.json["error"] == "authentication_required"
    assert "192.0.2.1" not in response.get_data(as_text=True)


def test_login_requires_csrf_and_correct_password(client):
    assert client.post("/login", data={"password": "correct-test-password"}).status_code == 400
    token = csrf(client)
    assert client.post("/login", data={"csrf_token": token, "password": "wrong"}).status_code == 401
    assert client.get("/api/overview").status_code == 401
    login(client)
    result = client.get("/api/overview")
    assert result.status_code == 200
    assert result.json["data"]["totals"] == {"success": 1, "failure": 0, "events": 1, "alerts": 1}


def test_login_does_not_follow_untrusted_next_redirect(client):
    result = client.post(
        "/login?next=https://evil.example",
        data={"csrf_token": csrf(client), "password": "correct-test-password"},
    )
    assert result.location == "/"


@pytest.mark.parametrize("origin", ["https://evil.example", "null"])
def test_cross_origin_login_is_rejected_even_with_token(client, origin):
    response = client.post(
        "/login",
        data={"csrf_token": csrf(client), "password": "correct-test-password"},
        headers={"Origin": origin},
    )
    assert response.status_code == 400
    assert client.get("/api/overview").status_code == 401


@pytest.mark.parametrize("base_url", ["http://localhost:8765", "http://127.0.0.1:8765"])
def test_browser_same_origin_login_and_logout(client, base_url):
    page = client.get("/login", base_url=base_url)
    # no-referrer makes Chromium send Origin: null even on its own HTML form.
    # The policy must preserve same-origin provenance for the strict CSRF check.
    assert page.headers["Referrer-Policy"] == "same-origin"
    token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
    headers = {"Origin": base_url, "Sec-Fetch-Site": "same-origin"}
    response = client.post(
        "/login",
        base_url=base_url,
        data={"csrf_token": token, "password": "correct-test-password"},
        headers=headers,
    )
    assert response.status_code == 302
    assert client.get("/api/overview", base_url=base_url).status_code == 200
    page = client.get("/", base_url=base_url)
    token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
    response = client.post(
        "/logout", base_url=base_url, data={"csrf_token": token}, headers=headers
    )
    assert response.status_code == 302
    assert client.get("/api/overview", base_url=base_url).status_code == 401


def test_cross_site_fetch_metadata_rejected_even_with_same_origin_header(client):
    response = client.post(
        "/login",
        data={"csrf_token": csrf(client), "password": "correct-test-password"},
        headers={"Origin": "http://localhost", "Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 400
    assert client.get("/api/overview").status_code == 401


def test_untrusted_host_rejected(client):
    response = client.get("/login", headers={"Host": "evil.example"})
    assert response.status_code == 400


def test_rate_limit_throttles_wrong_passwords(client):
    token = csrf(client)
    for _ in range(8):
        assert (
            client.post("/login", data={"csrf_token": token, "password": "wrong"}).status_code
            == 401
        )
    result = client.post("/login", data={"csrf_token": token, "password": "correct-test-password"})
    assert result.status_code == 429
    assert 0 < int(result.headers["Retry-After"]) <= 300


def test_session_expiration_and_logout_csrf(app, client):
    login(client)
    assert client.get("/logout").status_code == 405
    assert client.post("/logout").status_code == 400
    assert client.get("/api/overview").status_code == 200
    with client.session_transaction() as s:
        token = s["csrf"]
    assert client.post("/logout", data={"csrf_token": token}).status_code == 302
    assert client.get("/api/overview").status_code == 401
    login(client)
    with client.session_transaction() as s:
        s["authenticated_at"] = time.time() - 61 * 60
    assert client.get("/api/overview").status_code == 401


def test_secure_headers_and_cookie_flags(client):
    response = client.get("/login")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "'unsafe-eval'" not in response.headers["Content-Security-Policy"]


@pytest.mark.parametrize(
    "path", ["/", "/events", "/network", "/alerts", "/alerts/1", "/model", "/status"]
)
def test_all_readonly_pages_render_real_repository_data(client, path):
    login(client)
    response = client.get(path)
    assert response.status_code == 200
    assert b"Yggdrasil" in response.data
    assert "data er laboratoriedata" not in response.get_data(as_text=True).lower()


@pytest.mark.parametrize(
    "query",
    [
        "hours=0",
        "hours=721",
        "hours=-1",
        "hours=abc",
        "hours=1&hours=2",
        "hours=999999999999999999999",
    ],
)
def test_query_period_is_bounded(client, query):
    login(client)
    assert client.get("/api/overview?" + query).status_code == 400


@pytest.mark.parametrize(
    "url",
    [
        "/events?outcome=bad",
        "/events?page=0",
        "/events?per_page=1000",
        "/events?source=%00x",
        "/events?user=" + "x" * 129,
        "/alerts?detector=unknown",
    ],
)
def test_filters_reject_invalid_values(client, url):
    login(client)
    assert client.get(url).status_code == 400


def test_filters_and_pagination_are_functional(client):
    login(client)
    expected = client.get("/events?source=192.0.2.1&user=labuser&outcome=success")
    assert expected.status_code == 200 and b"Accepted publickey for labuser" in expected.data
    other = client.get("/events?source=192.0.2.99")
    assert "Ingen hændelser matcher" in other.get_data(as_text=True)
    assert b"Accepted publickey for labuser" not in other.data
    injection = client.get("/events", query_string={"user": "' OR 1=1 --"})
    assert injection.status_code == 200
    assert b"Accepted publickey for labuser" not in injection.data


def test_outcome_filter_renders_three_selectable_options(client):
    login(client)
    page = RenderedPage(client.get("/events?outcome=success").get_data(as_text=True))
    assert page.options["outcome"] == [("", False), ("success", True), ("failure", False)]


@pytest.mark.parametrize("path", ["/", "/events", "/alerts", "/model"])
def test_every_period_control_renders_real_options_and_selection(client, path):
    login(client)
    response = client.get(path, query_string={"hours": 168})
    assert response.status_code == 200
    page = RenderedPage(response.get_data(as_text=True))
    assert page.options["period"] == [
        ("1", False),
        ("6", False),
        ("24", False),
        ("168", True),
        ("720", False),
    ]


def test_custom_period_remains_selected_with_standard_choices(client):
    login(client)
    page = RenderedPage(client.get("/events?hours=2").get_data(as_text=True))
    assert len(page.options["period"]) == 6
    assert [option for option in page.options["period"] if option[1]] == [("2", True)]


@pytest.mark.parametrize(
    ("path", "filters"),
    [
        (
            "/events",
            {"source": "192.0.2.77", "user": "qa-user", "outcome": "failure"},
        ),
        ("/alerts", {"detector": "ssh.failed_burst"}),
        ("/model", {}),
    ],
)
def test_real_multipage_history_links_preserve_filters_and_distinct_rows(
    client, paginated_history, path, filters
):
    login(client)
    query = {"hours": "1", "per_page": "10", **filters}
    response = client.get(path, query_string=query)
    seen_rows = set()
    for page_number, expected_rows in enumerate((10, 10, 10, 1), start=1):
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert f"Side {page_number} af 4" in body
        rendered = RenderedPage(body)
        assert len(rendered.rows) == expected_rows
        assert not seen_rows.intersection(rendered.rows)
        seen_rows.update(rendered.rows)
        links = rendered.pagination_links(path)
        expected_links = set()
        if page_number > 1:
            expected_links.add(page_number - 1)
        if page_number < 4:
            expected_links.add(page_number + 1)
        assert set(links) == expected_links
        for linked_page, href in links.items():
            assert parse_qs(urlsplit(href).query) == {
                **{key: [value] for key, value in query.items()},
                "page": [str(linked_page)],
            }
        if page_number < 4:
            response = client.get(links[page_number + 1])
    assert len(seen_rows) == 31


def test_missing_database_is_an_error_not_empty_data(client, configured):
    login(client)
    configured[0].database_path.unlink()
    response = client.get("/api/overview")
    assert response.status_code == 503 and response.json["error"] == "data_unavailable"
    response = client.get("/")
    assert response.status_code == 503
    assert "Historikken er ikke tilgængelig" in response.get_data(as_text=True)
    assert not configured[0].database_path.exists()


def test_web_repository_is_enforced_readonly(app):
    with pytest.raises(PermissionError):
        app.extensions["ids_repository"].set_state("injected", "value")


def test_stale_collector_is_not_green(client, configured):
    configured[1].set_state("collector", {"state": "running", "heartbeat_at": time.time() - 600})
    login(client)
    response = client.get("/api/overview")
    assert response.json["status"]["collector_state"] == "stale"
    assert response.json["status"]["collector_tone"] == "danger"


def test_demo_data_is_never_misrepresented_as_live(client, configured):
    configured[1].set_state("mode", "demo")
    login(client)
    assert client.get("/api/overview").status_code == 503
    demo = create_app(replace(configured[0], mode="demo")).test_client()
    login(demo)
    page = demo.get("/").get_data(as_text=True)
    assert "Demonstrationsmiljø" in page
    assert "Denne visning overvåger ikke din Pi" in page


def test_log_content_is_escaped(client, configured):
    attack = '<img src=x onerror="alert(1)">'
    with configured[1].transaction() as db:
        db.execute("UPDATE events SET username=?,message=?", (attack, attack))
        db.execute("UPDATE alerts SET title=?,reason=?", (attack, attack))
    login(client)
    for route in ("/", "/events", "/alerts", "/alerts/1"):
        body = client.get(route).get_data(as_text=True)
        assert attack not in body
        assert "&lt;img" in body


def test_unscored_or_late_observations_never_claim_normality(client, configured):
    with configured[1].transaction() as db:
        db.execute(
            "INSERT INTO observations VALUES(?,?,?,?,NULL,NULL,NULL,NULL,?)",
            ("event-a", time.time() - 10, "192.0.2.1", "{}", "late"),
        )
    login(client)
    page = client.get("/model").get_data(as_text=True)
    assert "Forsinket hændelse" in page
    assert "Inden for grænsen" not in page


def test_analysis_error_observation_is_presented_as_error(client, configured):
    with configured[1].transaction() as db:
        db.execute(
            "INSERT INTO observations VALUES(?,?,?,?,NULL,NULL,NULL,NULL,?)",
            ("event-a", time.time() - 10, "192.0.2.1", "{}", "error"),
        )
    login(client)
    page = client.get("/model").get_data(as_text=True)
    assert "Analysefejl" in page
    assert "Inden for grænsen" not in page


def test_chart_explains_missing_observations(client):
    login(client)
    page = client.get("/").get_data(as_text=True)
    assert "Tynde streger forbinder målte prikker" in page
    assert "stiplede streger angiver manglende observationer" in page
    assert "Registrerede SSH-hændelser pr. 30 minutter" in page
    assert "Afbrud før login" in page
    assert "Afbrud før login er ikke fejlede autentificeringer." in page


def test_model_iso_timestamp_and_analysis_errors_are_visible(client, configured):
    configured[1].set_state(
        "model",
        {
            "state": "ready",
            "metadata": {
                "version": "test-model",
                "sample_count": 80,
                "trained_at": "2026-10-31T12:00:00+00:00",
                "provenance": "Testdata",
                "threshold": 0.6,
            },
        },
    )
    configured[1].set_state(
        "analysis_error", {"message": "Kontrolleret analysefejl", "at": time.time()}
    )
    login(client)
    page = client.get("/model").get_data(as_text=True)
    assert "31.10.2026 · 13:00:00" in page
    assert "Kontrolleret analysefejl" in page


def test_missing_or_invalid_credentials_fail_closed(configured):
    cfg = configured[0]
    cfg.credentials_path.unlink()
    with pytest.raises(RuntimeError, match="adgangsoplysninger"):
        create_app(cfg)
    cfg.credentials_path.write_text('{"password_hash":"plaintext","secret_key":"short"}')
    with pytest.raises(RuntimeError, match="adgangsoplysninger"):
        create_app(cfg)


def test_plotly_is_local_and_requires_authentication(client):
    assert client.get("/assets/plotly.min.js").status_code == 401
    login(client)
    response = client.get("/assets/plotly.min.js")
    assert response.status_code == 200
    assert "javascript" in response.content_type
    assert len(response.data) > 100000
    page = client.get("/").get_data(as_text=True)
    assert "cdn.plot.ly" not in page and "fonts.googleapis" not in page


def test_activity_chart_connects_positive_markers_without_inventing_samples():
    """Solid/dashed guide lines must never create fake events or zero samples."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "yggdrasil_ids"
    script = (root / "static" / "app.js").read_text(encoding="utf-8")
    style = (root / "static" / "app.css").read_text(encoding="utf-8")

    assert 'type: "scatter", mode: "markers"' in script
    assert "const observed = plotRows.filter(row => row[field] > 0);" in script
    assert "observed.map(row => row[field])" in script
    assert 'dots("Vellykkede", "success", "#68d8b6", "circle")' in script
    assert 'dots("Fejlede", "failure", "#ef6b6b", "diamond")' in script
    assert 'dots("Afbrud før login", "preauth", "#e8ad70", "square")' in script
    assert 'uirevision: "ssh-activity-connected-dots"' in script
    assert 'mode: "lines+markers"' not in script
    assert 'type: "scatter", mode: "lines"' in script
    assert "distance <= bucketSeconds ? solid : dashed" in script
    assert "if (distance > 6 * 3600) continue;" in script
    assert "segment.x.push((previous.left + previous.right) * 500" in script
    assert "segment.y.push(previous[field], current[field], null)" in script
    assert 'dash: "dot"' in script
    assert 'hoverinfo: "skip", showlegend: false' in script
    assert '...connectors("preauth", "#e8ad70")' in script
    assert ".legend-dot.success{background:#68d8b6}" in style
    assert ".legend-dot.failure{background:#ef6b6b}" in style
    assert ".legend-dot.preauth{background:#e8ad70}" in style


def test_network_charts_are_authenticated_local_and_bounded(configured, client):
    assert client.get("/api/network-charts").status_code == 401
    login(client)
    html = client.get("/network").get_data(as_text=True)
    assert "Blokerede TCP SYN over tid" in html
    assert "Højst 10 porte" in html
    assert "/assets/plotly.min.js" in html
    assert "/static/network.js" in html
    assert "cdn.plot.ly" not in html

    response = client.get("/api/network-charts?hours=1")
    assert response.status_code == 200
    report = response.get_json()["data"]
    assert report["total_packets"] == 0
    assert report["top_ports"] == []
    assert report["other_ports_packets"] == 0
    assert report["series"] == []
    assert "source_ip" not in json.dumps(report)
    assert client.get("/api/network-charts?hours=0").status_code == 400
    assert client.get("/api/network-charts?hours=721").status_code == 400
    assert client.get("/api/network-charts?hours=1&hours=2").status_code == 400


def test_network_charts_js_limits_visible_ports():
    from pathlib import Path

    script = (
        Path(__file__).resolve().parents[1] / "src" / "yggdrasil_ids" / "static" / "network.js"
    ).read_text(encoding="utf-8")
    assert ".slice(0, 10)" in script
    assert 'labels.push("Øvrige porte")' in script
    assert "/api/network-charts?hours=" in script
    assert "newPlot(ports" in script


def test_authenticated_network_page_displays_firewall_history_and_scan_alert(configured, client):
    from yggdrasil_ids.firewall import UFWParser
    from yggdrasil_ids.network_rules import TCPPortScanDetector

    _cfg, repo = configured
    recorded = []
    timestamp = time.time() - 20
    for index in range(6):
        record = {
            "_TRANSPORT": "kernel",
            "__CURSOR": f"network-web-{index}",
            "__REALTIME_TIMESTAMP": str(int((timestamp + index) * 1_000_000)),
            "MESSAGE": (
                "[UFW BLOCK] IN=wlan0 OUT= SRC=192.0.2.55 DST=192.0.2.92 "
                f"LEN=60 PROTO=TCP SPT=40000 DPT={3000 + index} SYN"
            ),
        }
        parsed = UFWParser().parse(record, namespace="live")
        assert parsed.event is not None
        recorded.append(parsed.event)
    with repo.transaction() as db:
        for item in recorded:
            assert repo.insert_firewall_event(db, item)
        finding = TCPPortScanDetector().evaluate(recorded[-1], recorded)
        assert finding is not None
        incident = repo.add_network_alert(db, finding, cooldown=300)
    login(client)
    response = client.get("/network")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Netværkshændelser" in body
    assert "192.0.2.55:40000" in body
    assert "192.0.2.92:3005" in body
    assert "6 logposter" in body
    assert "Netværksindsamling er ikke aktiveret" in body
    assert client.get("/network?source=192.0.2.55&protocol=TCP").status_code == 200
    assert "192.0.2.92:3005" not in client.get("/network?source=192.0.2.55&protocol=UDP").get_data(
        as_text=True
    )
    assert client.get("/network?protocol=bogus").status_code == 400
    alerts = client.get("/alerts?detector=network.tcp_port_scan")
    assert alerts.status_code == 200
    assert "Mulig TCP-portscanning" in alerts.get_data(as_text=True)
    detail = client.get(f"/alerts/{incident}")
    assert detail.status_code == 200
    detail_html = detail.get_data(as_text=True)
    assert "Se registrerede firewallhændelser" in detail_html
    assert "6 forskellige" in detail_html
    assert "/network?source=192.0.2.55" in detail_html
    assert repo.list_events()["total"] == 1


def test_network_page_displays_data_quality_error_without_exposing_raw_journal(configured, client):
    _cfg, repo = configured
    repo.set_state(
        "network_analysis_error",
        {"at": time.time(), "message": "Netværkshistorikken er for stor til pålidelig analyse"},
    )
    login(client)
    html = client.get("/network").get_data(as_text=True)
    assert "Netværksanalysen kræver opmærksomhed" in html
    assert "Netværkshistorikken er for stor" in html
    assert "SRC=" not in html
