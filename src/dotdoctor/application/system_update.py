"""Facade module providing backwards-compatible imports for system update & audit."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path

import typer
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from dotdoctor.application.checks import (
    ALL_CHECK_IDS,
    FIX_CHECK_IDS,
    HTTPS_TARGETS,
    UPDATE_CHECK_IDS,
    SystemCheckTask,
    SystemDryRunService,
    _detect_oh_my_zsh_updates,
    _ExecResult,
    _resolve_oh_my_zsh_path,
    _result_for_count,
    _run_capture,
    _unverified,
    detect_aur_helper,
    detect_pacnew_files,
    is_online,
)
from dotdoctor.application.disk import (
    DiskSpaceStatus,
    _format_bytes,
    detect_disk_space_status,
)
from dotdoctor.application.maintenance import (
    PACKAGE_RE,
    POSTFLIGHT_IDS,
    PREFLIGHT_IDS,
    MaintenanceChecks,
    privileged,
)
from dotdoctor.application.parsers import (
    _AUR_FLAGGED_RE,
    _NETWORK_FAILURE_PATTERNS,
    _detect_step_updates,
    _is_mirror_failure,
    _parse_fwupdmgr_updates,
    parse_package_update_line,
)
from dotdoctor.application.reboot import (
    CRITICAL_PACKAGE_PREFIXES,
    CRITICAL_REBOOT_PACKAGES,
    RebootStatus,
    detect_reboot_status,
    find_pacman_critical_upgrades,
    find_processes_with_deleted_libraries,
    get_system_boot_time,
    is_critical_reboot_package,
)
from dotdoctor.application.upgrade import (
    SystemUpgradeService,
    detect_snapshot_tool,
)
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure.audit_processes import AuditCancelled, AuditSession, check_cancelled
from dotdoctor.infrastructure.audit_processes import capture as capture_command
from dotdoctor.infrastructure.maintenance import MaintenanceState, capture

_ORIGINAL_SUBPROCESS_RUN = subprocess.run

__all__ = [
    "ALL_CHECK_IDS",
    "CRITICAL_PACKAGE_PREFIXES",
    "CRITICAL_REBOOT_PACKAGES",
    "FIRST_COMPLETED",
    "FIX_CHECK_IDS",
    "HTTPS_TARGETS",
    "PACKAGE_RE",
    "POSTFLIGHT_IDS",
    "PREFLIGHT_IDS",
    "UPDATE_CHECK_IDS",
    "_AUR_FLAGGED_RE",
    "_NETWORK_FAILURE_PATTERNS",
    "_ORIGINAL_SUBPROCESS_RUN",
    "AuditCancelled",
    "AuditSession",
    "CheckResult",
    "Console",
    "DiskSpaceStatus",
    "DotDoctorConfig",
    "Future",
    "Live",
    "MaintenanceChecks",
    "MaintenanceState",
    "Path",
    "RebootStatus",
    "ScanContext",
    "ScanReport",
    "Severity",
    "Spinner",
    "SystemCheckTask",
    "SystemDryRunService",
    "SystemUpgradeService",
    "Table",
    "Text",
    "ThreadPoolExecutor",
    "_ExecResult",
    "_detect_oh_my_zsh_updates",
    "_detect_step_updates",
    "_format_bytes",
    "_is_mirror_failure",
    "_parse_fwupdmgr_updates",
    "_resolve_oh_my_zsh_path",
    "_result_for_count",
    "_run_capture",
    "_unverified",
    "capture",
    "capture_command",
    "check_cancelled",
    "detect_aur_helper",
    "detect_disk_space_status",
    "detect_pacnew_files",
    "detect_reboot_status",
    "detect_snapshot_tool",
    "escape",
    "find_pacman_critical_upgrades",
    "find_processes_with_deleted_libraries",
    "get_system_boot_time",
    "is_critical_reboot_package",
    "is_online",
    "os",
    "parse_package_update_line",
    "privileged",
    "shutil",
    "subprocess",
    "time",
    "typer",
    "wait",
]
