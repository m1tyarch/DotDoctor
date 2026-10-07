from typing import Annotated, Literal

from pydantic import BaseModel, Field


class TimerConfig(BaseModel):
    unit: str = Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.@\\-]*\.timer$")
    scope: Literal["system", "user"] = "system"
    max_age_days: int = Field(default=7, ge=1, le=365)


class BackupConfig(BaseModel):
    service: str = Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.@\\-]*\.service$")
    scope: Literal["system", "user"] = "system"
    # An existing backup tool/adapter must report completed_at and verified as JSON.
    # Commands are argument arrays, never shell strings.
    status_command: list[Annotated[str, Field(min_length=1)]] = Field(min_length=1)
    max_age_days: int = Field(default=7, ge=1, le=365)
    required_before_upgrade: bool = False


class MaintenanceConfig(BaseModel):
    keyring_packages: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9@_+][A-Za-z0-9@_.+\-]*$")]] = (
        Field(default_factory=lambda: ["archlinux-keyring"], min_length=1)
    )
    timers: list[TimerConfig] = Field(default_factory=list)
    backup: BackupConfig | None = None
    scrub_max_age_days: int = Field(default=30, ge=1, le=365)
    integrity_timeout_seconds: int = Field(default=60, ge=1, le=600)


class DotDoctorConfig(BaseModel):
    disabled_checks: list[str] = Field(default_factory=list)
    maintenance: MaintenanceConfig = Field(default_factory=MaintenanceConfig)


def default_config() -> DotDoctorConfig:
    return DotDoctorConfig()
