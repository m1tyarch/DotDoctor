import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from dotdoctor.domain.config import DotDoctorConfig, default_config


class ConfigError(Exception):
    pass


def load_config(config_path: Path | None = None) -> DotDoctorConfig:
    if config_path is None:
        env_path = os.environ.get("DOTDOCTOR_CONFIG")
        if env_path:
            config_path = Path(env_path)
        else:
            xdg_config = os.environ.get("XDG_CONFIG_HOME")
            base_dir = Path(xdg_config) if xdg_config else Path.home() / ".config"
            candidates = [
                Path("dotdoctor.yml"),
                Path("dotdoctor.yaml"),
                base_dir / "dotdoctor" / "config.yml",
                base_dir / "dotdoctor" / "config.yaml",
            ]
            for cand in candidates:
                if cand.exists():
                    config_path = cand
                    break
            if config_path is None:
                config_path = Path("dotdoctor.yml")

    config = default_config()

    if config_path.exists():
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            if raw is None:
                raw = {}
            config = DotDoctorConfig.model_validate(raw)
        except (yaml.YAMLError, ValidationError) as exc:
            raise ConfigError(f"Invalid config at {config_path}: {exc}") from exc

    return apply_env_overrides(config)


def apply_env_overrides(config: DotDoctorConfig) -> DotDoctorConfig:
    disabled_checks_raw = os.environ.get("DOTDOCTOR_DISABLE_CHECKS", "").strip()
    if not disabled_checks_raw:
        return config

    disabled_checks = set(config.disabled_checks)
    disabled_checks.update(item.strip() for item in disabled_checks_raw.split(",") if item.strip())
    return config.model_copy(update={"disabled_checks": sorted(disabled_checks)})
