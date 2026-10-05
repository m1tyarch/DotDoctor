from pydantic import BaseModel, Field


class DotDoctorConfig(BaseModel):
    disabled_checks: list[str] = Field(default_factory=list)


def default_config() -> DotDoctorConfig:
    return DotDoctorConfig()
