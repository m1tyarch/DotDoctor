from pathlib import Path

import pytest

from dotdoctor.infrastructure.config_loader import ConfigError, load_config


def test_load_config_xdg_home(monkeypatch, tmp_path: Path) -> None:
    xdg_dir = tmp_path / "xdg_config"
    config_dir = xdg_dir / "dotdoctor"
    config_dir.mkdir(parents=True)
    config_file = config_dir / "config.yml"
    config_file.write_text("disabled_checks: [sys.firmware]\n", encoding="utf-8")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)

    loaded = load_config()
    assert loaded.disabled_checks == ["sys.firmware"]


def test_load_config_home_fallback(monkeypatch, tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    config_dir = fake_home / ".config" / "dotdoctor"
    config_dir.mkdir(parents=True)
    config_file = config_dir / "config.yaml"
    config_file.write_text("disabled_checks: [sys.disk]\n", encoding="utf-8")

    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.chdir(tmp_path)

    loaded = load_config()
    assert loaded.disabled_checks == ["sys.disk"]


def test_load_config_cwd_ignored_by_default(monkeypatch, tmp_path: Path) -> None:
    xdg_dir = tmp_path / "xdg_config"
    (xdg_dir / "dotdoctor").mkdir(parents=True)
    xdg_cfg = xdg_dir / "dotdoctor" / "config.yml"
    xdg_cfg.write_text("disabled_checks: [from_xdg]\n", encoding="utf-8")

    local_file = tmp_path / "dotdoctor.yml"
    local_file.write_text("disabled_checks: [from_local]\n", encoding="utf-8")

    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    monkeypatch.chdir(tmp_path)

    # By default, local cwd dotdoctor.yml is ignored for security
    loaded = load_config()
    assert loaded.disabled_checks == ["from_xdg"]

    # When explicitly provided, local file is loaded
    explicit_loaded = load_config(local_file)
    assert explicit_loaded.disabled_checks == ["from_local"]


def test_load_config_env_overrides(monkeypatch, tmp_path: Path) -> None:
    local_file = tmp_path / "dotdoctor.yml"
    local_file.write_text("disabled_checks: [sys.cache]\n", encoding="utf-8")

    monkeypatch.setenv("DOTDOCTOR_CONFIG", str(local_file))
    monkeypatch.setenv("DOTDOCTOR_DISABLE_CHECKS", "sys.packages, sys.aur")
    monkeypatch.chdir(tmp_path)

    loaded = load_config()
    assert set(loaded.disabled_checks) == {"sys.cache", "sys.packages", "sys.aur"}


def test_load_config_unreadable_raises_config_error(monkeypatch, tmp_path: Path) -> None:
    config_file = tmp_path / "dotdoctor.yml"
    config_file.write_text("disabled_checks: []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def fake_read_text(*args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    with pytest.raises(ConfigError, match="Invalid config"):
        load_config(config_file)
