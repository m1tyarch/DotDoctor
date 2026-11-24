"""System reboot status detection and critical packages analysis."""

import platform
import re
import time
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class RebootStatus:
    required: bool
    reason: str | None
    running_kernel: str
    installed_kernels: list[str]
    packages: list[str] = field(default_factory=list)


CRITICAL_REBOOT_PACKAGES: frozenset[str] = frozenset(
    {
        # Kernels and firmware
        "linux",
        "linux-lts",
        "linux-zen",
        "linux-hardened",
        "linux-firmware",
        "intel-ucode",
        "amd-ucode",
        # Core system & C library
        "glibc",
        "musl",
        "systemd",
        "systemd-libs",
        "dbus",
        "dbus-broker",
        # Graphics drivers & display stack
        "mesa",
        "mesa-amber",
        "vulkan-intel",
        "vulkan-radeon",
        "vulkan-mesa-layers",
        "vulkan-mesa-implicit-layers",
        "vulkan-nouveau",
        "nvidia",
        "nvidia-utils",
        "nvidia-lts",
        "nvidia-open",
        "nvidia-open-dkms",
        "nvidia-dkms",
        # Display servers & compositors
        "wayland",
        "hyprland",
        "sway",
        "mutter",
        "kwin",
        "xorg-server",
        "xorg-xwayland",
        # Core audio/multimedia
        "pipewire",
        "wireplumber",
    }
)

CRITICAL_PACKAGE_PREFIXES: tuple[str, ...] = (
    "vulkan-",
    "nvidia-",
    "mesa-",
    "xf86-video-",
)

_CRITICAL_LIBRARY_SUBSTRINGS: tuple[str, ...] = (
    "libc.so",
    "libm.so",
    "libsystemd.so",
    "libdbus-",
    "libGLX_mesa.so",
    "libEGL_mesa.so",
    "iris_dri.so",
    "radeonsi_dri.so",
    "nouveau_dri.so",
    "nvidia",
    "libdrm.so",
    "libwayland-client.so",
    "libwayland-server.so",
    "libpipewire-",
)

_EXCLUDED_MAPPED_PREFIXES: tuple[str, ...] = (
    "/dev/",
    "/memfd:",
    "/run/",
    "/tmp/",  # nosec: B108
    "/SYSV",
    "/etc/ld.so",
    "/home/",
    "/root/",
)

_LIBRARY_DIR_PREFIXES: tuple[str, ...] = (
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/opt/",
)

_PACMAN_ALPM_PATTERN = re.compile(
    r"^\[([^\]]+)\]\s+\[ALPM\]\s+(upgraded|installed|reinstalled)\s+([a-zA-Z0-9@_+\.\-]+)\s+\("
)


def is_critical_reboot_package(name: str, extra_packages: Collection[str] = ()) -> bool:
    normalized = name.strip().lower()
    if normalized in extra_packages:
        return True
    if normalized in CRITICAL_REBOOT_PACKAGES:
        return True
    if normalized.endswith("-dkms"):
        return True
    if normalized.startswith("linux-") and normalized.endswith("-headers"):
        return False
    if normalized.startswith(("linux-", "nvidia-")):
        return True
    return normalized.startswith(CRITICAL_PACKAGE_PREFIXES)


def get_system_boot_time() -> float | None:
    try:
        proc_stat = Path("/proc/stat")
        if proc_stat.exists():
            for line in proc_stat.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("btime "):
                    parts = line.split()
                    if len(parts) >= 2:
                        return float(parts[1])
    except (OSError, ValueError, IndexError):
        pass

    try:
        proc_uptime = Path("/proc/uptime")
        if proc_uptime.exists():
            uptime_sec = float(proc_uptime.read_text(encoding="utf-8", errors="ignore").split()[0])
            return time.time() - uptime_sec
    except (OSError, ValueError, IndexError):
        pass

    return None


def find_pacman_critical_upgrades(
    pacman_log: Path,
    since_timestamp: float,
    extra_packages: Collection[str] = (),
) -> list[str]:
    if not pacman_log.exists() or not pacman_log.is_file():
        return []

    try:
        size = pacman_log.stat().st_size
        max_read = 2 * 1024 * 1024
        if size > max_read:
            with pacman_log.open("rb") as f:
                f.seek(size - max_read)
                f.readline()
                content = f.read().decode("utf-8", errors="replace")
        else:
            content = pacman_log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    found_packages: set[str] = set()
    for line in reversed(content.splitlines()):
        match = _PACMAN_ALPM_PATTERN.match(line)
        if not match:
            continue
        ts_str, _, pkg_name = match.groups()
        try:
            ts = datetime.fromisoformat(ts_str).timestamp()
        except (ValueError, TypeError):
            continue

        if ts < since_timestamp:
            break

        if is_critical_reboot_package(pkg_name, extra_packages=extra_packages):
            found_packages.add(pkg_name)

    return sorted(found_packages)


def find_processes_with_deleted_libraries(
    proc_dir: Path = Path("/proc"),
) -> list[str]:
    if not proc_dir.exists() or not proc_dir.is_dir():
        return []

    processes: set[str] = set()
    try:
        entries = list(proc_dir.iterdir())
    except OSError:
        return []

    for pid_dir in entries:
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue

        maps_file = pid_dir / "maps"
        try:
            with maps_file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "(deleted)" not in line:
                        continue
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    mapped_path = parts[-2]
                    if mapped_path.startswith(_EXCLUDED_MAPPED_PREFIXES):
                        continue
                    if mapped_path.startswith(_LIBRARY_DIR_PREFIXES) and any(
                        sub in mapped_path for sub in _CRITICAL_LIBRARY_SUBSTRINGS
                    ):
                        comm_file = pid_dir / "comm"
                        comm = (
                            comm_file.read_text(encoding="utf-8", errors="ignore").strip()
                            if comm_file.exists()
                            else pid_dir.name
                        )
                        if comm:
                            processes.add(comm)
                        break
        except (OSError, PermissionError):
            continue

    return sorted(processes)


def detect_reboot_status(
    modules_dir: Path = Path("/usr/lib/modules"),
    running_kernel: str | None = None,
    marker_paths: tuple[str, ...] = ("/run/reboot-required", "/var/run/reboot-required"),
    pacman_log: Path | None = Path("/var/log/pacman.log"),
    boot_time: float | None = None,
    proc_dir: Path | None = Path("/proc"),
    extra_critical_packages: Sequence[str] = (),
) -> RebootStatus:
    current_kernel = running_kernel or platform.release()
    installed: list[str] = []

    if modules_dir.exists() and modules_dir.is_dir():
        try:
            installed = sorted(
                [d.name for d in modules_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
            )
        except OSError:
            installed = []

    reasons: list[str] = []
    affected_packages: set[str] = set()

    for marker in marker_paths:
        marker_path = Path(marker)
        if marker_path.exists():
            pkg_file = marker_path.with_suffix(".pkgs")
            if pkg_file.exists():
                try:
                    pkgs = [
                        p.strip()
                        for p in pkg_file.read_text(encoding="utf-8").splitlines()
                        if p.strip()
                    ]
                    if pkgs:
                        affected_packages.update(pkgs)
                        reasons.append(
                            f"Reboot required by system packages ({', '.join(sorted(pkgs))})."
                        )
                        break
                except OSError:
                    pass
            reasons.append(f"Reboot marker file '{marker}' detected.")
            break

    if installed and current_kernel not in installed:
        reasons.append(
            f"Running kernel ({current_kernel}) differs from "
            f"installed kernel ({', '.join(installed)})."
        )

    if pacman_log is not None:
        effective_boot_time = boot_time if boot_time is not None else get_system_boot_time()
        if effective_boot_time is not None:
            critical_upgrades = find_pacman_critical_upgrades(
                pacman_log,
                effective_boot_time,
                extra_packages=extra_critical_packages,
            )
            if critical_upgrades:
                affected_packages.update(critical_upgrades)
                reasons.append(
                    f"Critical system packages updated since boot ({', '.join(critical_upgrades)})."
                )

    if proc_dir is not None:
        procs_with_deleted = find_processes_with_deleted_libraries(proc_dir)
        if procs_with_deleted:
            reasons.append(
                f"Processes holding deleted shared libraries ({', '.join(procs_with_deleted)})."
            )

    if reasons:
        return RebootStatus(
            required=True,
            reason=" ".join(reasons),
            running_kernel=current_kernel,
            installed_kernels=installed,
            packages=sorted(affected_packages),
        )

    return RebootStatus(
        required=False,
        reason=None,
        running_kernel=current_kernel,
        installed_kernels=installed,
        packages=[],
    )


__all__ = [
    "CRITICAL_PACKAGE_PREFIXES",
    "CRITICAL_REBOOT_PACKAGES",
    "RebootStatus",
    "detect_reboot_status",
    "find_pacman_critical_upgrades",
    "find_processes_with_deleted_libraries",
    "get_system_boot_time",
    "is_critical_reboot_package",
]
