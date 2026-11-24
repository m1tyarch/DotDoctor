"""Disk space status checking and formatting utilities."""

import shutil
from dataclasses import dataclass
from pathlib import Path

from dotdoctor.domain.models import Severity


@dataclass(frozen=True)
class DiskSpaceStatus:
    root_free_bytes: int
    boot_free_bytes: int
    severity: Severity
    message: str
    remediation: str | None


def _format_bytes(bytes_count: int) -> str:
    if bytes_count >= 1024 * 1024 * 1024:
        return f"{bytes_count / (1024**3):.1f} GiB"
    if bytes_count >= 1024 * 1024:
        return f"{bytes_count / (1024**2):.1f} MiB"
    return f"{bytes_count / 1024:.1f} KiB"


def detect_disk_space_status(
    root_path: str | Path = "/",
    boot_path: str | Path = "/boot",
    min_root_warn_bytes: int = 2 * 1024 * 1024 * 1024,  # 2 GiB
    min_root_crit_bytes: int = 500 * 1024 * 1024,  # 500 MiB
    min_boot_warn_bytes: int = 150 * 1024 * 1024,  # 150 MiB
    min_boot_crit_bytes: int = 50 * 1024 * 1024,  # 50 MiB
) -> DiskSpaceStatus:
    try:
        root_free = shutil.disk_usage(root_path).free
    except OSError:
        root_free = 0

    try:
        boot_free = shutil.disk_usage(boot_path).free if Path(boot_path).exists() else root_free
    except OSError:
        raise OSError("free space on /boot could not be verified") from None

    root_str = _format_bytes(root_free)
    boot_str = _format_bytes(boot_free)

    same_fs = False
    try:
        root_p = Path(root_path)
        boot_p = Path(boot_path)
        if root_p.exists() and boot_p.exists():
            same_fs = root_p.stat().st_dev == boot_p.stat().st_dev
    except OSError:
        same_fs = False

    if same_fs:
        free_desc = f"{root_str} free on / and /boot"
    else:
        free_desc = f"/ {root_str} free \u00b7 /boot {boot_str} free"

    if root_free < min_root_crit_bytes or boot_free < min_boot_crit_bytes:
        return DiskSpaceStatus(
            root_free_bytes=root_free,
            boot_free_bytes=boot_free,
            severity=Severity.FAIL,
            message=f"critically low disk space ({free_desc})",
            remediation="free up disk space immediately before updating packages",
        )

    if root_free < min_root_warn_bytes or boot_free < min_boot_warn_bytes:
        return DiskSpaceStatus(
            root_free_bytes=root_free,
            boot_free_bytes=boot_free,
            severity=Severity.WARN,
            message=f"low disk space ({free_desc})",
            remediation="clean package caches (paccache -r) before updating",
        )

    return DiskSpaceStatus(
        root_free_bytes=root_free,
        boot_free_bytes=boot_free,
        severity=Severity.PASS,
        message=free_desc,
        remediation=None,
    )


__all__ = [
    "DiskSpaceStatus",
    "_format_bytes",
    "detect_disk_space_status",
]
