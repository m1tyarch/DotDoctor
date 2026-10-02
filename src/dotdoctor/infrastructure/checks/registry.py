from dotdoctor.domain.config import ProfileConfig
from dotdoctor.domain.ports import EnvironmentCheck
from dotdoctor.infrastructure.checks.core import (
    BinaryCheck,
    PathIntegrityCheck,
    PermissionsCheck,
    ShellConfigCheck,
)


def normalize_check_id(check_id: str) -> str:
    """Normalize legacy colon-based IDs (e.g. sys:packages -> sys.packages) to category.name."""
    return check_id.replace(":", ".")


def resolve_checks(
    profile: ProfileConfig,
    disabled_checks: set[str] | None = None,
) -> list[EnvironmentCheck]:
    raw_disabled = disabled_checks or set()
    disabled = {normalize_check_id(c) for c in raw_disabled} | set(raw_disabled)

    binary_checks = {
        f"binary.{requirement.name}": BinaryCheck(requirement)
        for requirement in profile.required_binaries
    }
    available_checks: dict[str, EnvironmentCheck] = {
        **binary_checks,
        "path.integrity": PathIntegrityCheck(),
        "shell.config": ShellConfigCheck(profile),
        "permissions.dev_dirs": PermissionsCheck(profile),
    }

    checks: list[EnvironmentCheck] = []
    for check_id in profile.enabled_checks:
        norm_id = normalize_check_id(check_id)
        if norm_id in disabled or check_id in disabled:
            continue

        check = available_checks.get(norm_id) or available_checks.get(check_id)
        if check is not None:
            checks.append(check)

    return checks
