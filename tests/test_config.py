"""Configuration mistakes must fail before touching live data or binding a port."""

from pathlib import Path

import pytest

from yggdrasil_ids.config import load_config


def config_file(tmp_path, text=""):
    path = tmp_path / "settings" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_default_paths_are_anchored_to_configuration_not_working_directory(tmp_path, monkeypatch):
    path = config_file(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    config = load_config(path)
    assert config.database_path == path.parent / ".local/events.sqlite3"
    assert config.model_path == path.parent / ".local/model.json"
    assert config.credentials_path == path.parent / ".local/web-secrets.json"
    assert config.web.bind == "127.0.0.1"
    assert config.rules.expected_sources == ()


def test_explicit_path_wins_over_environment_and_relative_paths_resolve(tmp_path, monkeypatch):
    path = config_file(tmp_path, '[paths]\ndatabase="../data/ssh.sqlite3"\n')
    monkeypatch.setenv("YGGDRASIL_CONFIG", str(tmp_path / "missing.toml"))
    config = load_config(path)
    assert config.database_path == tmp_path / "data/ssh.sqlite3"
    monkeypatch.setenv("YGGDRASIL_CONFIG", str(path))
    assert load_config().database_path == config.database_path


def test_valid_profile_preserves_explicit_networks_users_and_timezone(tmp_path):
    path = config_file(
        tmp_path,
        """
[app]
mode = "demo"
timezone = "UTC"
[rules]
expected_sources = ["192.0.2.0/24", "2001:db8::/32"]
expected_users = ["labuser"]
[web]
bind = "::1"
trusted_hosts = ["[::1]"]
""",
    )
    config = load_config(path)
    assert config.mode == "demo"
    assert config.timezone == "UTC"
    assert config.rules.expected_sources == ("192.0.2.0/24", "2001:db8::/32")
    assert config.rules.expected_users == ("labuser",)
    assert config.web.trusted_hosts == ("[::1]",)


@pytest.mark.parametrize(
    "text",
    [
        '[databse]\npath="wrong.sqlite3"',
        '[paths]\ndatabse="wrong.sqlite3"',
        'rules="not-a-section"',
        '[app]\nmode="production"',
        '[app]\ntimezone="Mars/Olympus"',
        "[rules]\nfailure_threshold=true",
        "[rules]\nwindow_seconds=0",
        '[rules]\nexpected_sources=["192.0.2.0/99"]',
        "[rules]\nexpected_users=[42]",
        "[ml]\nmin_samples=true",
        "[ml]\ncontamination=nan",
        "[ml]\ncontamination=0.9",
        '[web]\nbind="0.0.0.0"',
        '[web]\ntrusted_hosts=["*"]',
        "[web]\ntrusted_hosts=[]",
        "[collector]\nheartbeat_seconds=0",
        "[storage]\nretention_days=false",
        "[paths]\ndatabase=false",
    ],
)
def test_invalid_configuration_is_rejected_with_a_configuration_error(tmp_path, text):
    with pytest.raises(ValueError):
        load_config(config_file(tmp_path, text))


@pytest.mark.parametrize(
    "text",
    [
        '[app]\nmode=["live"]',
        '[web]\nbind=["127.0.0.1"]',
        '[web]\ntrusted_hosts=[["localhost"]]',
    ],
)
def test_unexpected_toml_types_produce_valueerror_not_uncaught_typeerror(tmp_path, text):
    with pytest.raises(ValueError):
        load_config(config_file(tmp_path, text))


@pytest.mark.parametrize(
    "text",
    [
        '[paths]\ndatabase="./state"\nmodel="state"',
        '[paths]\ndatabase="./state"\ncredentials="state"',
        '[paths]\nmodel="./state"\ncredentials="state"',
    ],
)
def test_data_model_and_credentials_must_not_alias_the_same_file(tmp_path, text):
    with pytest.raises(ValueError):
        load_config(config_file(tmp_path, text))


def test_existing_symlink_alias_is_rejected_before_writing(tmp_path):
    actual = tmp_path / "events.sqlite3"
    actual.touch()
    alias = tmp_path / "model.json"
    alias.symlink_to(actual)
    path = config_file(tmp_path, f'[paths]\ndatabase="{actual}"\nmodel="{alias}"')
    with pytest.raises(ValueError):
        load_config(path)
    assert actual.read_bytes() == b""


def test_absolute_paths_remain_absolute(tmp_path):
    absolute = (tmp_path / "db/events.sqlite3").resolve()
    config = load_config(config_file(tmp_path, f'[paths]\ndatabase="{absolute}"'))
    assert isinstance(config.database_path, Path)
    assert config.database_path == absolute


def test_network_logging_is_opt_in_and_configured_separately(tmp_path):
    assert load_config(config_file(tmp_path)).network.enabled is False
    config = load_config(
        config_file(
            tmp_path,
            "[network]\nenabled=true\nwindow_seconds=120\ndistinct_ports_threshold=8\n",
        )
    )
    assert config.network.enabled is True
    assert config.network.window_seconds == 120
    assert config.network.distinct_ports_threshold == 8


@pytest.mark.parametrize(
    "text",
    [
        "[network]\nenabled=1\n",
        '[network]\nenabled="true"\n',
        "[network]\nwindow_seconds=true\n",
        "[network]\nwindow_seconds=0\n",
        "[network]\ndistinct_ports_threshold=1\n",
        "[network]\ndistinct_ports_threshold=65\n",
        "[network]\nunknown=1\n",
    ],
)
def test_invalid_network_config_is_rejected(tmp_path, text):
    with pytest.raises(ValueError):
        load_config(config_file(tmp_path, text))


def test_ml_shadow_mode_is_explicit_and_type_checked(tmp_path):
    assert load_config(config_file(tmp_path)).ml.alert_mode == "alert"
    shadow = load_config(config_file(tmp_path, '[ml]\nalert_mode="shadow"\n'))
    assert shadow.ml.alert_mode == "shadow"
    for value in ['"unknown"', "false", '["shadow"]']:
        with pytest.raises(ValueError):
            load_config(config_file(tmp_path, f"[ml]\nalert_mode={value}\n"))
