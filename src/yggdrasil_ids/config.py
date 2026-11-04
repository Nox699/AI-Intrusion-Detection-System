"""Strict TOML configuration. Paths are anchored to the configuration file."""

from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass(frozen=True)
class RulesConfig:
    window_seconds: int = 300
    failure_threshold: int = 5
    username_threshold: int = 4
    preauth_threshold: int = 5
    cooldown_seconds: int = 300
    expected_sources: tuple[str, ...] = ()
    expected_users: tuple[str, ...] = ()


@dataclass(frozen=True)
class MLConfig:
    window_seconds: int = 300
    min_samples: int = 80
    contamination: float = 0.03
    n_estimators: int = 128
    random_state: int = 42
    alert_mode: str = "alert"


@dataclass(frozen=True)
class CollectorConfig:
    initial_history_hours: int = 24
    heartbeat_seconds: int = 5
    max_record_bytes: int = 65536
    executable: str = "journalctl"


@dataclass(frozen=True)
class NetworkConfig:
    # Explicit opt-in: upgrading the package never widens journal collection.
    enabled: bool = False
    window_seconds: int = 60
    distinct_ports_threshold: int = 6


@dataclass(frozen=True)
class SudoConfig:
    enabled: bool = False
    window_seconds: int = 300
    failure_process_threshold: int = 3
    cooldown_seconds: int = 300


@dataclass(frozen=True)
class WebConfig:
    bind: str = "127.0.0.1"
    port: int = 8765
    poll_seconds: int = 5
    session_minutes: int = 60
    trusted_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "[::1]")


@dataclass(frozen=True)
class AppConfig:
    database_path: Path = Path(".local/events.sqlite3")
    model_path: Path = Path(".local/model.json")
    credentials_path: Path = Path(".local/web-secrets.json")
    sudo_database_path: Path = Path(".local/sudo-private/sudo.sqlite3")
    sudo_public_directory: Path = Path(".local/sudo-public")
    mode: str = "live"
    host_label: str = "Yggdrasil"
    timezone: str = "Europe/Copenhagen"
    rules: RulesConfig = field(default_factory=RulesConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    sudo: SudoConfig = field(default_factory=SudoConfig)
    web: WebConfig = field(default_factory=WebConfig)
    retention_days: int = 30
    max_database_mb: int = 512


def _section(data: dict, name: str, allowed: set[str]) -> dict:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"{name} skal være en TOML-sektion")
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"Ukendte felter i {name}: {', '.join(sorted(unknown))}")
    return dict(value)


def _int(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} skal være et heltal mellem {low} og {high}")
    return value


def load_config(path: Path | str | None = None) -> AppConfig:
    path = Path(path or os.environ.get("YGGDRASIL_CONFIG", "config.toml")).resolve()
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    allowed = {"app", "paths", "rules", "ml", "collector", "network", "sudo", "web", "storage"}
    if set(data) - allowed:
        raise ValueError("Ukendte konfigurationssektioner: " + ", ".join(set(data) - allowed))
    app = _section(data, "app", {"mode", "host_label", "timezone"})
    paths = _section(
        data,
        "paths",
        {"database", "model", "credentials", "sudo_database", "sudo_public_directory"},
    )
    rules = _section(data, "rules", set(RulesConfig.__dataclass_fields__))
    ml = _section(data, "ml", set(MLConfig.__dataclass_fields__))
    collector = _section(data, "collector", set(CollectorConfig.__dataclass_fields__))
    network = _section(data, "network", set(NetworkConfig.__dataclass_fields__))
    sudo = _section(data, "sudo", set(SudoConfig.__dataclass_fields__))
    web = _section(data, "web", set(WebConfig.__dataclass_fields__))
    storage = _section(data, "storage", {"retention_days", "max_database_mb"})
    if app.get("mode", "live") != "live":
        raise ValueError("Produktionsversionen kræver app.mode='live'")
    for key in ("host_label", "timezone"):
        if key in app and (not isinstance(app[key], str) or not 1 <= len(app[key]) <= 100):
            raise ValueError(f"app.{key} skal være en kort tekst")
    try:
        ZoneInfo(app.get("timezone", "Europe/Copenhagen"))
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("Ukendt tidszone") from exc
    for key, default, low, high in [
        ("window_seconds", 300, 10, 3600),
        ("failure_threshold", 5, 2, 10000),
        ("username_threshold", 4, 2, 10000),
        ("preauth_threshold", 5, 2, 10000),
        ("cooldown_seconds", 300, 10, 86400),
    ]:
        rules[key] = _int(rules.get(key, default), f"rules.{key}", low, high)
    for key in ("expected_sources", "expected_users"):
        value = rules.get(key, [])
        if (
            not isinstance(value, list)
            or len(value) > 1000
            or any(not isinstance(x, str) or not x or len(x) > 256 for x in value)
        ):
            raise ValueError(f"rules.{key} skal være en liste af korte tekster")
        rules[key] = tuple(value)
    for expected_network in rules["expected_sources"]:
        ipaddress.ip_network(expected_network, strict=False)
    for key, default, low, high in [
        ("window_seconds", 300, 10, 3600),
        ("min_samples", 80, 20, 10000),
        ("n_estimators", 128, 16, 512),
        ("random_state", 42, 0, 2**31 - 1),
    ]:
        ml[key] = _int(ml.get(key, default), f"ml.{key}", low, high)
    contamination = ml.get("contamination", 0.03)
    if type(contamination) not in {int, float} or not 0 < contamination <= 0.5:
        raise ValueError("ml.contamination skal være større end 0 og højst 0.5")
    ml["contamination"] = float(contamination)
    if ml.get("alert_mode", "alert") != "alert":
        raise ValueError("Produktionsversionen kræver ml.alert_mode='alert'")
    ml["alert_mode"] = ml.get("alert_mode", "alert")
    for key, default, low, high in [
        ("initial_history_hours", 24, 1, 168),
        ("heartbeat_seconds", 5, 1, 30),
        ("max_record_bytes", 65536, 1024, 1048576),
    ]:
        collector[key] = _int(collector.get(key, default), f"collector.{key}", low, high)
    if type(network.get("enabled", False)) is not bool:
        raise ValueError("network.enabled skal være true eller false")
    network["enabled"] = network.get("enabled", False)
    network["window_seconds"] = _int(
        network.get("window_seconds", 60), "network.window_seconds", 10, 3600
    )
    network["distinct_ports_threshold"] = _int(
        network.get("distinct_ports_threshold", 6), "network.distinct_ports_threshold", 2, 64
    )
    if type(sudo.get("enabled", False)) is not bool:
        raise ValueError("sudo.enabled skal være true eller false")
    sudo["enabled"] = sudo.get("enabled", False)
    for key, default, low, high in (
        ("window_seconds", 300, 60, 3600),
        ("failure_process_threshold", 3, 2, 20),
        ("cooldown_seconds", 300, 60, 3600),
    ):
        sudo[key] = _int(sudo.get(key, default), f"sudo.{key}", low, high)
    executable = collector.get("executable", "journalctl")
    if not isinstance(executable, str) or not executable or "\x00" in executable:
        raise ValueError("collector.executable skal være en sti eller et programnavn")
    for key, default, low, high in [
        ("port", 8765, 1024, 65535),
        ("poll_seconds", 5, 2, 60),
        ("session_minutes", 60, 5, 480),
    ]:
        web[key] = _int(web.get(key, default), f"web.{key}", low, high)
    bind = web.get("bind", "127.0.0.1")
    if not isinstance(bind, str) or bind not in {"127.0.0.1", "::1"}:
        raise ValueError("Dashboardet kræver loopback-adgang: web.bind 127.0.0.1 eller ::1")
    hosts = web.get("trusted_hosts", ["localhost", "127.0.0.1", "[::1]"])
    if (
        not isinstance(hosts, list)
        or not hosts
        or any(
            not isinstance(host, str) or host not in {"localhost", "127.0.0.1", "[::1]"}
            for host in hosts
        )
    ):
        raise ValueError("web.trusted_hosts skal indeholde lokale værtsnavne")
    web["trusted_hosts"] = tuple(hosts)
    retention = _int(storage.get("retention_days", 30), "storage.retention_days", 1, 365)
    budget = _int(storage.get("max_database_mb", 512), "storage.max_database_mb", 16, 65536)

    def local(key: str, fallback: str) -> Path:
        value = paths.get(key, fallback)
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError(f"paths.{key} skal være en sti")
        p = Path(value).expanduser()
        return p.resolve() if p.is_absolute() else (path.parent / p).resolve()

    database_path = local("database", ".local/events.sqlite3")
    model_path = local("model", ".local/model.json")
    credentials_path = local("credentials", ".local/web-secrets.json")
    sudo_database_path = local("sudo_database", ".local/sudo-private/sudo.sqlite3")
    sudo_public_directory = local("sudo_public_directory", ".local/sudo-public")
    private_files = {database_path, model_path, credentials_path, sudo_database_path}
    if len(private_files) != 4 or sudo_public_directory in private_files:
        raise ValueError(
            "Databaser, model, loginoplysninger og offentlig eksport skal have forskellige stier"
        )
    if (
        sudo_database_path.parent == database_path.parent
        or sudo_database_path.is_relative_to(sudo_public_directory)
        or sudo_public_directory.is_relative_to(sudo_database_path.parent)
        or any(p.is_relative_to(sudo_public_directory) for p in private_files)
    ):
        raise ValueError(
            "Privat sudo-database skal ligge adskilt fra produktionsdatabasen og offentlig eksport"
        )
    return AppConfig(
        database_path=database_path,
        model_path=model_path,
        credentials_path=credentials_path,
        sudo_database_path=sudo_database_path,
        sudo_public_directory=sudo_public_directory,
        **app,
        rules=RulesConfig(**rules),
        ml=MLConfig(**ml),
        collector=CollectorConfig(**collector),
        network=NetworkConfig(**network),
        sudo=SudoConfig(**sudo),
        web=WebConfig(**web),
        retention_days=retention,
        max_database_mb=budget,
    )
