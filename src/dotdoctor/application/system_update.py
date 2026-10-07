import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import textwrap
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import typer
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.spinner import Spinner
from rich.table import Table

from dotdoctor.application.maintenance import (
    PACKAGE_RE,
    POSTFLIGHT_IDS,
    PREFLIGHT_IDS,
    MaintenanceChecks,
)
from dotdoctor.cli.theme import (
    GAP,
    INDENT,
    STATUS_DONE,
    STATUS_FAIL,
    STATUS_SKIP,
    STATUS_WIDTH,
    format_status_line,
    format_sysup_summary,
)
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure.audit_processes import AuditCancelled, AuditSession, check_cancelled
from dotdoctor.infrastructure.audit_processes import capture as capture_command
from dotdoctor.infrastructure.maintenance import MaintenanceState, capture

_ORIGINAL_SUBPROCESS_RUN = subprocess.run


def is_online(
    targets: tuple[tuple[str, int], ...] = (
        ("1.1.1.1", 53),
        ("8.8.8.8", 53),
        ("9.9.9.9", 53),
    ),
    timeout: float = 1.5,
) -> bool:
    """Check if the system has an active internet connection."""
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, TimeoutError):
            continue
    return False


@dataclass(frozen=True)
class _ExecResult:
    completed: subprocess.CompletedProcess[str] | None
    timed_out: bool = False


def _unverified(check_id: str, message: str, remediation: str | None = None) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        severity=Severity.WARN,
        message=message,
        remediation=remediation,
        details={"verified": False},
    )


@dataclass(frozen=True)
class RebootStatus:
    required: bool
    reason: str | None
    running_kernel: str
    installed_kernels: list[str]


def detect_reboot_status(
    modules_dir: Path = Path("/usr/lib/modules"),
    running_kernel: str | None = None,
    marker_paths: tuple[str, ...] = ("/run/reboot-required", "/var/run/reboot-required"),
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
                        return RebootStatus(
                            required=True,
                            reason=f"Reboot required by system packages ({', '.join(pkgs)}).",
                            running_kernel=current_kernel,
                            installed_kernels=installed,
                        )
                except OSError:
                    pass
            return RebootStatus(
                required=True,
                reason=f"Reboot marker file '{marker}' detected.",
                running_kernel=current_kernel,
                installed_kernels=installed,
            )

    if installed:
        if current_kernel not in installed:
            return RebootStatus(
                required=True,
                reason=(
                    f"Running kernel ({current_kernel}) differs from "
                    f"installed kernel ({', '.join(installed)})."
                ),
                running_kernel=current_kernel,
                installed_kernels=installed,
            )

    return RebootStatus(
        required=False,
        reason=None,
        running_kernel=current_kernel,
        installed_kernels=installed,
    )


@dataclass(frozen=True)
class DiskSpaceStatus:
    root_free_bytes: int
    boot_free_bytes: int
    severity: Severity
    message: str
    remediation: str | None


def _format_bytes(bytes_count: int) -> str:
    if bytes_count >= 1024 * 1024 * 1024:
        return f"{bytes_count / (1024 ** 3):.1f} GiB"
    if bytes_count >= 1024 * 1024:
        return f"{bytes_count / (1024 ** 2):.1f} MiB"
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


def detect_aur_helper(which_fn: Callable[[str], str | None] | None = None) -> str | None:
    fn = which_fn or shutil.which
    for helper in ("paru", "yay"):
        if fn(helper) is not None:
            return helper
    return None


def _run_capture(
    command: list[str],
    timeout: int,
    input_str: str | None = None,
) -> _ExecResult:
    try:
        return _ExecResult(
            completed=capture_command(command, timeout, input_str, {**os.environ, "LC_ALL": "C"}),
        )
    except subprocess.TimeoutExpired:
        return _ExecResult(completed=None, timed_out=True)
    except (OSError, subprocess.SubprocessError):
        return _ExecResult(completed=None, timed_out=False)


def detect_pacnew_files() -> list[str]:
    pacdiff_bin = shutil.which("pacdiff")
    if pacdiff_bin is not None:
        res = _run_capture([pacdiff_bin, "-o"], timeout=15)
        if res.completed and res.completed.returncode == 0:
            return [line.strip() for line in res.completed.stdout.splitlines() if line.strip()]

    files: list[str] = []
    etc_dir = Path("/etc")
    if etc_dir.exists():

        def inaccessible(error: OSError) -> None:
            raise error

        for directory, _, names in os.walk(etc_dir, onerror=inaccessible):
            check_cancelled()
            files.extend(
                str(Path(directory) / name)
                for name in names
                if name.endswith((".pacnew", ".pacsave"))
            )
    return sorted(files)


UPDATE_CHECK_IDS: frozenset[str] = frozenset(
    {
        "sys.packages",
        "sys.aur",
        "sys.flatpak",
        "sys.firmware",
        "sys.shell-omz",
        "sys.keyring",
        "sys.news",
        "sys.security",
        "sys.rebuild",
        *PREFLIGHT_IDS,
    }
)

FIX_CHECK_IDS: frozenset[str] = frozenset(
    {
        "sys.orphans",
        "sys.cache",
        "sys.flatpak-unused",
        "sys.pacnew",
        "sys.journal",
        "sys.services",
        "sys.disk",
        "sys.reboot",
        "sys.backup",
        "sys.timers",
        "sys.trim",
        "sys.btrfs",
        "sys.integrity",
    }
)


@dataclass(frozen=True)
class SystemCheckTask:
    check_id: str
    label: str
    runner: Callable[[], CheckResult | None]


class SystemDryRunService:
    """Runs parallel dry-run checks for package update availability and system hygiene."""

    def __init__(
        self,
        is_online_fn: Callable[[], bool] = is_online,
        aur_helper_fn: Callable[[], str | None] = detect_aur_helper,
        config: DotDoctorConfig | None = None,
    ) -> None:
        self._is_online_fn = is_online_fn
        self._aur_helper_fn = aur_helper_fn
        self.config = config or DotDoctorConfig()

    def build_tasks(
        self,
        context: ScanContext,
        disabled_checks: set[str] | list[str] | None = None,
        include_checks: set[str] | list[str] | frozenset[str] | None = None,
    ) -> list[SystemCheckTask]:
        tasks: list[SystemCheckTask] = []
        disabled: set[str] = {*self.config.disabled_checks, *(disabled_checks or [])}
        env_disabled = os.environ.get("DOTDOCTOR_DISABLE_CHECKS", "")
        if env_disabled:
            disabled.update(item.strip() for item in env_disabled.split(",") if item.strip())

        includes: set[str] | None = set(include_checks) if include_checks is not None else None

        def _is_disabled(cid: str) -> bool:
            return (
                cid in disabled
                or cid.replace(".", ":") in disabled
                or cid.replace(":", ".") in disabled
            )

        network_checks = {
            "sys.packages",
            "sys.aur",
            "sys.flatpak",
            "sys.firmware",
            "sys.shell-omz",
            "sys.news",
            "sys.security",
        }

        def _is_included(cid: str) -> bool:
            if includes is None:
                return True
            if cid == "sys.network":
                return any(_is_included(c) for c in network_checks)
            return (
                cid in includes
                or cid.replace(".", ":") in includes
                or cid.replace(":", ".") in includes
            )

        def _add_task(task: SystemCheckTask) -> None:
            if _is_included(task.check_id) and not _is_disabled(task.check_id):
                tasks.append(task)

        needs_network = any(_is_included(c) and not _is_disabled(c) for c in network_checks)
        online = self._is_online_fn() if needs_network else True

        if not online:
            _add_task(
                SystemCheckTask(
                    check_id="sys.network",
                    label="Network connection",
                    runner=lambda: CheckResult(
                        check_id="sys.network",
                        severity=Severity.FAIL,
                        message="no active internet connection",
                        remediation="connect to the internet and retry",
                    ),
                )
            )
        else:
            if shutil.which("pacman") or shutil.which("checkupdates"):
                _add_task(
                    SystemCheckTask(
                        check_id="sys.packages",
                        label="Packages",
                        runner=lambda: self._check_arch_packages(context),
                    )
                )

            aur_helper = self._aur_helper_fn()
            if aur_helper is not None:
                _add_task(
                    SystemCheckTask(
                        check_id="sys.aur",
                        label=f"AUR ({aur_helper})",
                        runner=lambda: self._check_aur_packages(context, aur_helper),
                    )
                )

            if shutil.which("flatpak") is not None:
                _add_task(
                    SystemCheckTask(
                        check_id="sys.flatpak",
                        label="Flatpak packages",
                        runner=lambda: self._check_flatpak(context),
                    )
                )

            if shutil.which("fwupdmgr") is not None:
                _add_task(
                    SystemCheckTask(
                        check_id="sys.firmware",
                        label="Firmware updates",
                        runner=lambda: self._check_firmware(context),
                    )
                )

            omz_path = _resolve_oh_my_zsh_path(context)
            if omz_path is not None:
                _add_task(
                    SystemCheckTask(
                        check_id="sys.shell-omz",
                        label="Oh-My-Zsh updates",
                        runner=lambda: self._check_oh_my_zsh(omz_path),
                    )
                )

        _add_task(
            SystemCheckTask(
                check_id="sys.reboot",
                label="Reboot status",
                runner=lambda: self._check_reboot(context),
            )
        )
        _add_task(
            SystemCheckTask(
                check_id="sys.disk",
                label="Disk space",
                runner=lambda: self._check_disk_space(context),
            )
        )

        if shutil.which("pacman") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.orphans",
                    label="Orphan packages",
                    runner=lambda: self._check_orphans(context),
                )
            )

        if shutil.which("pacman") is not None or shutil.which("paccache") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.cache",
                    label="Pacman cache",
                    runner=lambda: self._check_pacman_cache(context),
                )
            )

        if shutil.which("flatpak") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.flatpak-unused",
                    label="Unused Flatpaks",
                    runner=lambda: self._check_flatpak_unused(context),
                )
            )

        if shutil.which("pacdiff") is not None or shutil.which("pacman") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.pacnew",
                    label=".pacnew files",
                    runner=lambda: self._check_pacnew(context),
                )
            )

        if shutil.which("systemctl") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.services",
                    label="Failed services",
                    runner=lambda: self._check_failed_services(context),
                )
            )

        if shutil.which("journalctl") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.journal",
                    label="Journal disk usage",
                    runner=lambda: self._check_journal(context),
                )
            )

        for cid, label, runner in MaintenanceChecks(self.config).registrations(context):
            if not online and cid in {"sys.news", "sys.security"}:

                def offline_result(check_id: str = cid) -> CheckResult:
                    return CheckResult(
                        check_id=check_id,
                        severity=Severity.WARN,
                        message="not verified: internet connection unavailable",
                        details={"verified": False},
                    )

                runner = offline_result
            _add_task(SystemCheckTask(check_id=cid, label=label, runner=runner))
        return tasks

    def run(
        self,
        context: ScanContext,
        disabled_checks: set[str] | list[str] | None = None,
        include_checks: set[str] | list[str] | frozenset[str] | None = None,
    ) -> ScanReport:
        return self.run_with_progress(
            context,
            disabled_checks=disabled_checks,
            include_checks=include_checks,
        )

    def run_with_progress(
        self,
        context: ScanContext,
        on_task_complete: Callable[[str], None] | None = None,
        disabled_checks: set[str] | list[str] | None = None,
        include_checks: set[str] | list[str] | frozenset[str] | None = None,
        tasks: list[SystemCheckTask] | None = None,
        on_task_result: Callable[[str, CheckResult | None], None] | None = None,
    ) -> ScanReport:
        if tasks is None:
            tasks = self.build_tasks(
                context,
                disabled_checks=disabled_checks,
                include_checks=include_checks,
            )
        results = self._run_tasks(
            tasks, on_task_complete=on_task_complete, on_task_result=on_task_result
        )
        return ScanReport(profile=context.profile, results=results)

    def _run_tasks(
        self,
        tasks: list[SystemCheckTask],
        on_task_complete: Callable[[str], None] | None,
        on_task_result: Callable[[str, CheckResult | None], None] | None = None,
    ) -> list[CheckResult]:
        if not tasks:
            return []

        ordered_results: dict[str, CheckResult | None] = {}
        session = AuditSession()
        pool = ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="dotdoctor-audit")

        def execute(task: SystemCheckTask) -> CheckResult | None:
            with session.bind():
                return task.runner()

        interrupted = False
        try:
            futures: dict[Future[CheckResult | None], SystemCheckTask] = {
                pool.submit(execute, task): task for task in tasks
            }
            pending = set(futures.keys())
            try:
                while pending:
                    done, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                    for future in done:
                        task = futures[future]
                        try:
                            ordered_results[task.check_id] = future.result()
                        except (OSError, ValueError, subprocess.SubprocessError) as exc:
                            ordered_results[task.check_id] = CheckResult(
                                check_id=task.check_id,
                                severity=Severity.WARN,
                                message=f"check could not be completed: {str(exc)[:160]}",
                                details={"verified": False},
                            )
                        if on_task_result is not None:
                            on_task_result(task.check_id, ordered_results[task.check_id])
                        if on_task_complete is not None:
                            on_task_complete(task.check_id)
            except (KeyboardInterrupt, AuditCancelled):
                interrupted = True
                session.cancel()
                for f in pending:
                    f.cancel()
                raise KeyboardInterrupt() from None
        except BaseException:
            if not interrupted:
                interrupted = True
                session.cancel()
            raise
        finally:
            pool.shutdown(wait=not interrupted, cancel_futures=interrupted)

        collected_results: list[CheckResult] = []
        for task in tasks:
            result = ordered_results.get(task.check_id)
            if result is not None:
                collected_results.append(result)
        return collected_results

    def _check_arch_packages(self, context: ScanContext) -> CheckResult:
        if shutil.which("checkupdates") is None:
            if shutil.which("pacman") is None:
                return _unverified("sys.packages", "pacman not installed")
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN,
                message="checkupdates not installed",
                remediation="sudo pacman -S pacman-contrib",
            )

        result = _run_capture(["checkupdates"], timeout=60)
        if result.timed_out:
            return _unverified("sys.packages", "package check timed out", "checkupdates")
        if result.completed is None:
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN,
                message="could not run checkupdates",
                remediation="checkupdates",
            )
        completed = result.completed
        lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if completed.returncode == 2:
            return _result_for_count("sys.packages", 0)

        if completed.returncode not in {0, 2}:
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.FAIL,
                message="package check failed",
                remediation="dotdoctor --sysup",
            )

        if not lines:
            return _result_for_count("sys.packages", 0)

        pkg_entries: list[str] = []
        critical_pkgs: list[str] = []
        for line in lines:
            parsed = parse_package_update_line(line)
            if parsed:
                pkg_name, old_v, new_v = parsed
                pkg_entries.append(f"{pkg_name} {old_v} -> {new_v}")
                if pkg_name in CRITICAL_PACKAGES:
                    critical_pkgs.append(pkg_name)
            else:
                pkg_name = line.split()[0] if line.split() else line
                pkg_entries.append(line)
                if pkg_name in CRITICAL_PACKAGES:
                    critical_pkgs.append(pkg_name)

        count = len(lines)
        unique_critical = sorted(set(critical_pkgs))
        noun = "update" if count == 1 else "updates"
        if unique_critical:
            crit_str = ", ".join(unique_critical)
            msg = f"{count} {noun} available (reboot required: {crit_str})"
        else:
            msg = f"{count} {noun} available"

        return CheckResult(
            check_id="sys.packages",
            severity=Severity.OUTD,
            message=msg,
            remediation="dotdoctor --sysup",
            details={
                "updates": count,
                "packages": pkg_entries,
                "critical": unique_critical,
            },
        )

    def _check_flatpak(self, context: ScanContext) -> CheckResult:
        if shutil.which("flatpak") is None:
            return _unverified("sys.flatpak", "flatpak not installed")

        result = _run_capture(["flatpak", "remote-ls", "--updates"], timeout=60)
        if result.timed_out:
            return _unverified(
                "sys.flatpak", "Flatpak check timed out", "flatpak remote-ls --updates"
            )
        if result.completed is None:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.WARN,
                message="could not run Flatpak check",
                remediation="flatpak remote-ls --updates",
            )
        if result.completed.returncode != 0:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.FAIL,
                message=f"flatpak check failed (exit={result.completed.returncode})",
                remediation="check Flatpak remote configuration",
            )
        lines = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        if not lines:
            return _result_for_count("sys.flatpak", 0)

        count = len(lines)
        noun = "update" if count == 1 else "updates"
        return CheckResult(
            check_id="sys.flatpak",
            severity=Severity.OUTD,
            message=f"{count} {noun} available",
            remediation="dotdoctor --sysup",
            details={"updates": count, "packages": lines},
        )

    def _check_firmware(self, context: ScanContext) -> CheckResult:
        if shutil.which("fwupdmgr") is None:
            return _unverified("sys.firmware", "fwupd not installed")

        refresh = _run_capture(["fwupdmgr", "refresh"], timeout=90)
        if refresh.timed_out:
            return _unverified("sys.firmware", "fwupdmgr refresh timed out", "fwupdmgr refresh")
        if refresh.completed is None:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.WARN,
                message="could not refresh firmware metadata",
                remediation="fwupdmgr refresh",
            )
        if refresh.completed.returncode not in {0, 2}:
            return _unverified(
                "sys.firmware",
                "firmware metadata refresh failed; updates not verified",
                "fwupdmgr refresh",
            )

        updates_result = _run_capture(["fwupdmgr", "get-updates"], timeout=90)
        if updates_result.timed_out:
            return _unverified(
                "sys.firmware", "fwupdmgr get-updates timed out", "fwupdmgr get-updates"
            )
        if updates_result.completed is None:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.WARN,
                message="could not run firmware update check",
                remediation="fwupdmgr get-updates",
            )
        completed = updates_result.completed

        if completed.returncode == 2:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.PASS,
                message="no firmware updates",
                remediation=None,
                details={"updates": 0},
            )

        update_count = _parse_fwupdmgr_updates(completed.stdout)
        if completed.returncode not in {0, 2} and update_count == 0:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.WARN,
                message="firmware check returned unexpected exit code",
                remediation="fwupdmgr get-updates",
            )

        if update_count == 0:
            lines = [line for line in completed.stdout.splitlines() if line.strip()]
            no_update_heading = re.compile(
                r"^Devices with (?:the latest available firmware version|"
                r"no available firmware updates):$"
            )
            if any(no_update_heading.fullmatch(line) for line in lines) and all(
                no_update_heading.fullmatch(line) or line[0].isspace() for line in lines
            ):
                return _result_for_count("sys.firmware", 0)
            return _unverified(
                "sys.firmware",
                "firmware update output could not be verified",
                "fwupdmgr get-updates",
            )

        return _result_for_count("sys.firmware", update_count)

    def _check_oh_my_zsh(self, omz_path: str) -> CheckResult:
        update_count = _detect_oh_my_zsh_updates(omz_path)
        if update_count is None:
            return _unverified(
                "sys.shell-omz",
                "Oh-My-Zsh updates could not be verified",
                f"git -C {shlex.quote(omz_path)} status",
            )
        if update_count > 0:
            return CheckResult(
                check_id="sys.shell-omz",
                severity=Severity.OUTD,
                message=f"{update_count} update{'s' if update_count != 1 else ''} available",
                remediation="dotdoctor --sysup",
                details={"updates": update_count},
            )

        return CheckResult(
            check_id="sys.shell-omz",
            severity=Severity.PASS,
            message="up to date",
            remediation=None,
            details={"updates": 0},
        )

    def _check_reboot(self, context: ScanContext) -> CheckResult:
        status = detect_reboot_status()
        if status.required:
            reason = (status.reason or "reboot required").rstrip(".")
            return CheckResult(
                check_id="sys.reboot",
                severity=Severity.WARN,
                message=f"reboot required: {reason}",
                remediation="systemctl reboot",
                details={
                    "running_kernel": status.running_kernel,
                    "installed_kernels": status.installed_kernels,
                    "reboot_required": True,
                },
            )

        if not status.installed_kernels:
            return _unverified(
                "sys.reboot",
                "installed kernels unavailable; reboot state not verified",
                "ls /usr/lib/modules",
            )

        return CheckResult(
            check_id="sys.reboot",
            severity=Severity.PASS,
            message="no reboot required",
            remediation=None,
            details={
                "running_kernel": status.running_kernel,
                "installed_kernels": status.installed_kernels,
                "reboot_required": False,
            },
        )

    def _check_disk_space(self, context: ScanContext) -> CheckResult:
        status = detect_disk_space_status()
        return CheckResult(
            check_id="sys.disk",
            severity=status.severity,
            message=status.message,
            remediation=status.remediation,
            details={
                "root_free_bytes": status.root_free_bytes,
                "boot_free_bytes": status.boot_free_bytes,
            },
        )

    def _check_aur_packages(self, context: ScanContext, aur_helper: str = "yay") -> CheckResult:
        result = _run_capture([aur_helper, "-Qua"], timeout=60)
        if result.timed_out:
            return _unverified(
                "sys.aur", f"{aur_helper} update check timed out", f"{aur_helper} -Qua"
            )
        if result.completed is None:
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.WARN,
                message=f"could not run {aur_helper} -Qua",
                remediation=f"{aur_helper} -Qua",
            )
        lines = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        no_matches = (
            result.completed.returncode == 1
            and not lines
            and not getattr(result.completed, "stderr", "").strip()
        )
        # Pacman-compatible query helpers use exit 1 for an empty selection.
        # Output accompanying that code can instead describe a real failure.
        if result.completed.returncode != 0 and not no_matches:
            return _unverified(
                "sys.aur",
                f"{aur_helper} update check failed (exit={result.completed.returncode})",
                f"{aur_helper} -Qua",
            )
        flagged = [line for line in lines if _AUR_FLAGGED_RE.search(line)]
        regular = [line for line in lines if line not in flagged]

        if not lines:
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.PASS,
                message="up to date",
                remediation=None,
                details={"updates": 0, "flagged": 0, "packages": [], "critical": []},
            )

        aur_entries: list[str] = []
        critical_aur: list[str] = []
        for line in lines:
            parts = line.split()
            pkg_name = parts[0]
            if pkg_name.startswith("aur/"):
                pkg_name = pkg_name[4:]
            parsed = parse_package_update_line(line)
            if parsed:
                _, old_v, new_v = parsed
                aur_entries.append(f"{pkg_name} {old_v} -> {new_v}")
            else:
                aur_entries.append(line)
            if pkg_name in CRITICAL_PACKAGES:
                critical_aur.append(pkg_name)

        count = len(lines)
        unique_crit = sorted(set(critical_aur))
        noun = "update" if count == 1 else "updates"
        crit_suffix = f" (reboot required: {', '.join(unique_crit)})" if unique_crit else ""
        if flagged:
            msg = f"{count} AUR {noun} available ({len(flagged)} flagged out-of-date){crit_suffix}"
        else:
            msg = f"{len(regular)} AUR {noun} available{crit_suffix}"

        return CheckResult(
            check_id="sys.aur",
            severity=Severity.OUTD,
            message=msg,
            remediation="dotdoctor --sysup",
            details={
                "updates": len(regular),
                "flagged": len(flagged),
                "packages": aur_entries,
                "critical": unique_crit,
            },
        )

    def _check_pacman_cache(
        self,
        context: ScanContext,
        cache_dir: Path = Path("/var/cache/pacman/pkg"),
    ) -> CheckResult:
        try:
            cache_dir.stat()
        except FileNotFoundError:
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.PASS,
                message="pacman cache clean",
                remediation=None,
            )
        except OSError:
            return _unverified(
                "sys.cache", "pacman cache could not be inspected", "du -sh /var/cache/pacman/pkg"
            )

        total_bytes = 0
        try:
            with os.scandir(cache_dir) as it:
                for entry in it:
                    check_cancelled()
                    if entry.is_file(follow_symlinks=False):
                        total_bytes += entry.stat().st_size
        except OSError:
            return _unverified(
                "sys.cache", "pacman cache could not be inspected", "du -sh /var/cache/pacman/pkg"
            )

        total_str = _format_bytes(total_bytes)
        candidates = 0
        saved_str = ""

        if shutil.which("paccache") is not None:
            res = _run_capture(["paccache", "-d"], timeout=20)
            if res.completed is None or res.completed.returncode != 0:
                return _unverified(
                    "sys.cache",
                    f"{total_str} in cache; cleanup candidates not verified",
                    "paccache -d",
                )
            if res.completed and res.completed.returncode == 0:
                match = re.search(
                    r"finished dry run:\s*(\d+)\s*candidates\s*\(disk space saved:\s*([^)]+)\)",
                    res.completed.stdout,
                )
                if match:
                    candidates = int(match.group(1))
                    saved_str = match.group(2).strip()
                elif re.search(
                    r"^\s*(?:==>\s*)?no candidate packages found for pruning\s*$",
                    res.completed.stdout + "\n" + getattr(res.completed, "stderr", ""),
                    re.MULTILINE,
                ):
                    candidates = 0
                else:
                    return _unverified(
                        "sys.cache",
                        f"{total_str} in cache; cleanup output not recognized",
                        "paccache -d",
                    )

        if candidates > 0 and (total_bytes > 2 * 1024**3 or candidates >= 10):
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.WARN,
                message=f"{total_str} in pacman cache ({saved_str} reclaimable)",
                remediation="sudo paccache -rk2",
                details={"total_bytes": total_bytes, "candidates": candidates, "saved": saved_str},
            )

        if total_bytes > 5 * 1024**3:
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.WARN,
                message=f"{total_str} in pacman cache",
                remediation="sudo paccache -rk2",
                details={"total_bytes": total_bytes},
            )

        return CheckResult(
            check_id="sys.cache",
            severity=Severity.PASS,
            message=f"{total_str} in pacman cache (clean)",
            remediation=None,
            details={"total_bytes": total_bytes, "candidates": candidates},
        )

    def _check_orphans(self, context: ScanContext) -> CheckResult:
        if shutil.which("pacman") is None:
            return _unverified("sys.orphans", "pacman not installed")

        result = _run_capture(["pacman", "-Qtdq"], timeout=15)
        if result.timed_out:
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="orphan check timed out",
                remediation="pacman -Qtdq",
            )
        if result.completed is None or result.completed.returncode not in {0, 1}:
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="could not check orphan packages",
                remediation="pacman -Qtdq",
            )
        if result.completed.returncode == 1 and getattr(result.completed, "stderr", "").strip():
            return _unverified("sys.orphans", "orphan package query failed", "pacman -Qtdq")

        orphans = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        if orphans:
            count = len(orphans)
            noun = "package" if count == 1 else "packages"
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message=f"{count} orphan {noun} found",
                remediation="sudo pacman -Rns $(pacman -Qtdq)",
                details={"orphans": orphans},
            )

        return CheckResult(
            check_id="sys.orphans",
            severity=Severity.PASS,
            message="no orphan packages",
            remediation=None,
            details={"orphans": []},
        )

    def _check_pacnew(self, context: ScanContext) -> CheckResult:
        files = detect_pacnew_files()
        if files:
            count = len(files)
            noun = "file" if count == 1 else "files"
            names = ", ".join(Path(f).name for f in files[:2])
            return CheckResult(
                check_id="sys.pacnew",
                severity=Severity.WARN,
                message=f"{count} .pacnew {noun} found ({names})",
                remediation="pacdiff -s",
                details={"files": files},
            )

        return CheckResult(
            check_id="sys.pacnew",
            severity=Severity.PASS,
            message="no .pacnew files",
            remediation=None,
            details={"files": []},
        )

    def _check_failed_services(self, context: ScanContext) -> CheckResult:
        if shutil.which("systemctl") is None:
            return _unverified("sys.services", "systemctl not installed")

        failed_units: list[str] = []
        unavailable: list[str] = []
        sys_res = _run_capture(
            ["systemctl", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if sys_res.completed and sys_res.completed.returncode == 0:
            for line in sys_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    failed_units.append(parts[0])
        else:
            unavailable.append("system")

        user_res = _run_capture(
            ["systemctl", "--user", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if user_res.completed and user_res.completed.returncode == 0:
            for line in user_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    failed_units.append(f"{parts[0]} (user)")
        else:
            unavailable.append("user")

        if failed_units:
            count = len(failed_units)
            noun = "unit" if count == 1 else "units"
            sample = ", ".join(failed_units[:2])
            first_unit = failed_units[0].split()[0]
            return CheckResult(
                check_id="sys.services",
                severity=Severity.FAIL,
                message=f"{count} failed {noun} ({sample})",
                remediation=f"systemctl status {first_unit}",
                details={
                    "failed_units": failed_units,
                    "unavailable_scopes": unavailable,
                    "verified": not unavailable,
                },
            )

        if unavailable:
            return _unverified(
                "sys.services",
                f"failed units not verified ({', '.join(unavailable)} manager unavailable)",
                "systemctl --failed; systemctl --user --failed",
            )

        return CheckResult(
            check_id="sys.services",
            severity=Severity.PASS,
            message="no failed units",
            remediation=None,
            details={"failed_units": []},
        )

    def _check_flatpak_unused(self, context: ScanContext) -> CheckResult:
        if shutil.which("flatpak") is None:
            return _unverified("sys.flatpak-unused", "flatpak not installed")

        res = _run_capture(
            ["flatpak", "uninstall", "--unused"],
            timeout=15,
            input_str="n\n",
        )
        if res.timed_out or res.completed is None:
            return _unverified(
                "sys.flatpak-unused",
                "could not check unused flatpaks",
                "flatpak uninstall --unused",
            )

        runtime_lines = [
            line for line in res.completed.stdout.splitlines() if re.match(r"^\s*\d+\.\s+", line)
        ]
        if runtime_lines:
            count = len(runtime_lines)
            noun = "runtime" if count == 1 else "runtimes"
            return CheckResult(
                check_id="sys.flatpak-unused",
                severity=Severity.WARN,
                message=f"{count} unused {noun} found",
                remediation="flatpak uninstall --unused",
                details={"unused_count": count},
            )

        if res.completed.returncode != 0:
            return _unverified(
                "sys.flatpak-unused",
                "unused Flatpak runtime check failed",
                "flatpak uninstall --unused",
            )
        if (
            res.completed.stdout.strip()
            and "Nothing unused to uninstall" not in res.completed.stdout
        ):
            return _unverified(
                "sys.flatpak-unused",
                "unused Flatpak runtime output not recognized",
                "flatpak uninstall --unused",
            )

        return CheckResult(
            check_id="sys.flatpak-unused",
            severity=Severity.PASS,
            message="no unused runtimes",
            remediation=None,
            details={"unused_count": 0},
        )

    def _check_journal(self, context: ScanContext) -> CheckResult:
        if shutil.which("journalctl") is None:
            return _unverified("sys.journal", "journalctl not installed")

        res = _run_capture(["journalctl", "--disk-usage"], timeout=10)
        if res.completed and res.completed.returncode == 0:
            if re.search(
                r"not seeing messages|permission denied", getattr(res.completed, "stderr", ""), re.I
            ):
                return _unverified(
                    "sys.journal",
                    "journal is only partially accessible",
                    "sudo journalctl --disk-usage",
                )
            match = re.search(
                r"take up\s+([\d.]+\s*[KMGT]?i?B?)\s+in",
                res.completed.stdout,
                re.IGNORECASE,
            )
            if match:
                size_str = match.group(1).strip()
                value = re.fullmatch(r"([\d.]+)\s*([KMGT]?)I?B?", size_str.upper())
                if value is None:
                    return _unverified(
                        "sys.journal", "unsupported journal size format", "journalctl --disk-usage"
                    )
                size_bytes = float(value[1]) * 1024 ** (" KMGT".index(value[2]) if value[2] else 0)
                is_large = size_bytes >= 4 * 1024**3

                return CheckResult(
                    check_id="sys.journal",
                    severity=Severity.WARN if is_large else Severity.PASS,
                    message=f"{size_str} in journal logs",
                    remediation="sudo journalctl --vacuum-size=1G" if is_large else None,
                    details={"disk_usage": size_str},
                )

        return _unverified(
            "sys.journal", "journal size could not be verified", "journalctl --disk-usage"
        )


def _result_for_count(check_id: str, updates: int) -> CheckResult:
    if updates > 0:
        return CheckResult(
            check_id=check_id,
            severity=Severity.OUTD,
            message=f"{updates} update{'s' if updates != 1 else ''} available",
            remediation="dotdoctor --sysup",
            details={"updates": updates},
        )

    msg = "no firmware updates" if check_id.endswith("firmware") else "up to date"
    return CheckResult(
        check_id=check_id,
        severity=Severity.PASS,
        message=msg,
        remediation=None,
        details={"updates": 0},
    )


CRITICAL_PACKAGES: frozenset[str] = frozenset(
    {
        "linux",
        "linux-zen",
        "linux-lts",
        "linux-hardened",
        "linux-cachyos",
        "linux-cachyos-bore",
        "linux-cachyos-lto",
        "linux-firmware",
        "nvidia",
        "nvidia-open",
        "nvidia-lts",
        "nvidia-utils",
        "nvidia-dkms",
        "mesa",
        "vulkan-radeon",
        "vulkan-intel",
        "systemd",
        "systemd-libs",
        "glibc",
        "cryptsetup",
        "mkinitcpio",
        "dracut",
        "grub",
    }
)


def parse_package_update_line(line: str) -> tuple[str, str, str] | None:
    """Parse 'pkgname old_version -> new_version' from package managers."""
    parts = line.split()
    if len(parts) >= 4 and parts[2] in {"->", "→"}:
        return parts[0], parts[1], parts[3]
    if len(parts) == 3 and parts[0] not in {"->", "→"}:
        return parts[0], parts[1], parts[2]
    return None


def detect_snapshot_tool() -> str | None:
    """Detect available and configured snapshot tool: 'snapper' or 'timeshift'."""
    if shutil.which("snapper") is not None:
        try:
            res = subprocess.run(
                ["snapper", "list-configs"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and len(res.stdout.strip().splitlines()) > 1:
                return "snapper"
        except (OSError, subprocess.SubprocessError):
            pass

    if shutil.which("timeshift") is not None:
        return "timeshift"

    return None


_NETWORK_FAILURE_PATTERNS: frozenset[str] = frozenset(
    {
        "failed to retrieve",
        "failed to synchronize",
        "couldn't connect to server",
        "connection timed out",
        "download library error",
        "error: failed to update",
        "failed to download",
        "curl error",
        "resolving timed out",
        "failed to get",
        "could not connect",
    }
)

_AUR_FLAGGED_RE = re.compile(
    r"\[(?:out[- ]of[- ]date|flagged[- ]out[- ]of[- ]date)\b",
    re.IGNORECASE,
)


def _is_mirror_failure(output: str) -> bool:
    lowered = output.lower()
    return any(pattern in lowered for pattern in _NETWORK_FAILURE_PATTERNS)


def _detect_step_updates(command: list[str], stdout: str, stderr: str) -> bool:
    """Detect whether a maintenance step actually applied updates or changes."""
    cmd_str = " ".join(command).lower()
    combined = f"{stdout}\n{stderr}".lower()

    if any(helper in cmd_str for helper in ("yay", "paru", "pacman")) and any(
        arg in cmd_str for arg in ("-syu", "-u")
    ):
        if "there is nothing to do" in combined or "nothing to do" in combined:
            return False
        if any(
            marker in combined
            for marker in ("total installed size", "upgraded", "packages (", "installing")
        ):
            return True
        return "there is nothing to do" not in combined and len(stdout.strip()) > 0

    if "flatpak" in cmd_str and "update" in cmd_str:
        if any(
            marker in combined
            for marker in ("nothing to do", "nothing to update", "nothing to install")
        ):
            return False
        if any(marker in combined for marker in ("updating", "installing", "changes:")):
            return True
        return (
            not any(marker in combined for marker in ("nothing to do", "nothing to update"))
            and len(stdout.strip()) > 0
        )

    if "flatpak" in cmd_str and "unused" in cmd_str:
        if "nothing unused to uninstall" in combined:
            return False
        if "uninstalling" in combined:
            return True
        return False

    if "paccache" in cmd_str:
        if "no candidate packages" in combined or "0 packages removed" in combined:
            return False
        match = re.search(r"(\d+)\s+packages removed", combined)
        if match and int(match.group(1)) > 0:
            return True
        return False

    if "upgrade.sh" in cmd_str:
        if "already at the latest version" in combined:
            return False
        if "updating oh my zsh" in combined or "upgraded" in combined:
            return True
        return False

    if "fwupdmgr" in cmd_str and "update" in cmd_str:
        no_update_markers = (
            "no updates available",
            "devices with no available firmware updates",
            "no updatable devices",
            "nothing to do",
            "devices with the latest available firmware version",
        )
        if any(marker in combined for marker in no_update_markers) and not any(
            marker in combined for marker in ("successfully installed", "updating")
        ):
            return False
        if "successfully installed" in combined or "updating" in combined:
            return True
        return False

    return False


def _resolve_oh_my_zsh_path(context: ScanContext) -> str | None:
    zsh_env = os.environ.get("ZSH")
    if zsh_env:
        env_path = os.path.expanduser(zsh_env)
        if os.path.isdir(env_path):
            return env_path

    default_path = context.home / ".oh-my-zsh"
    if default_path.exists() and default_path.is_dir():
        return str(default_path)

    return None


def _detect_oh_my_zsh_updates(omz_path: str) -> int | None:
    if shutil.which("git") is None:
        return None

    git_dir = os.path.join(omz_path, ".git")
    if not os.path.isdir(git_dir):
        return None

    fetched = _run_capture(["git", "-C", omz_path, "fetch", "--quiet", "origin"], timeout=30)
    if fetched.completed is None or fetched.completed.returncode != 0:
        return None
    count_result = _run_capture(
        ["git", "-C", omz_path, "rev-list", "--count", "HEAD..origin/master"],
        timeout=30,
    )
    if count_result.completed is None or count_result.completed.returncode != 0:
        return None

    raw = count_result.completed.stdout.strip()
    if not raw.isdigit():
        return None
    return int(raw)


class SystemUpgradeService:
    """Runs sequential interactive system update commands."""

    def __init__(
        self,
        is_online_fn: Callable[[], bool] = is_online,
        aur_helper_fn: Callable[[], str | None] = detect_aur_helper,
        snapshot_tool_fn: Callable[[], str | None] = detect_snapshot_tool,
        config: DotDoctorConfig | None = None,
    ) -> None:
        self._is_online_fn = is_online_fn
        self._aur_helper_fn = aur_helper_fn
        self._snapshot_tool_fn = snapshot_tool_fn
        self.config = config or DotDoctorConfig()
        self.reinstall_packages: list[str] = []
        self._last_step_output = ""
        self._keyring_steps = 0
        self._keyring_updated = False

    def run(self, context: ScanContext, console: Console) -> int:
        if not self._is_online_fn():
            console.print(
                "[red]FAIL: No active internet connection detected. "
                "Aborting system upgrade.[/red]"
            )
            return 1

        try:
            disk_status = detect_disk_space_status()
        except OSError as exc:
            for line in format_status_line(STATUS_FAIL, f"Update aborted: {exc}"):
                console.print(line)
            return 2
        if disk_status.severity == Severity.FAIL:
            console.print(
                f"[red]FAIL: {disk_status.message} "
                "Aborting update to prevent system corruption.[/red]"
            )
            return 1
        if disk_status.severity == Severity.WARN:
            console.print(
                f"[yellow]Warning: {disk_status.message} Proceeding with caution[/yellow]"
            )

        if not self._maintenance_preflight(context, console):
            return 2

        console.print("  [dim]Caching sudo credentials[/dim]")
        sudo_cache = subprocess.run(["sudo", "true"], check=False)
        if sudo_cache.returncode != 0:
            console.print("[red]Failed to cache sudo credentials. Aborting update phase.[/red]")
            return 3

        # Recheck privileged readers once sudo is cached; an unprivileged WARN
        # must not conceal a disk failure before the package transaction.
        if not self._maintenance_preflight(context, console, frozenset({"sys.smart", "sys.btrfs"})):
            return 2

        had_error = False
        any_updates = False
        done_count = 0
        fail_count = 0
        skip_count = 0
        console_width = getattr(console, "width", 80) or 80

        snap_err, snap_status, created_snap = self._create_pre_update_snapshot(console)
        had_error |= snap_err
        if snap_status == "done":
            done_count += 1
        elif snap_status == "fail":
            fail_count += 1
        else:
            skip_count += 1

        if snap_err:
            console.print(
                format_sysup_summary(done=done_count, failed=fail_count, skipped=skip_count)
            )
            for line in format_status_line(
                STATUS_FAIL, "Update aborted: pre-update snapshot failed"
            ):
                console.print(line)
            return 2

        mirror_err, mirror_status = self._refresh_mirrors(console)
        had_error |= mirror_err
        if mirror_status == "done":
            done_count += 1
        elif mirror_status == "fail":
            fail_count += 1
        else:
            skip_count += 1

        # Prepare a newly available keyring before the full upgrade. Never leave a
        # synchronized database behind and proceed with unrelated package installs.
        if not self._prepare_keyring(console):
            return 2
        done_count += self._keyring_steps
        any_updates |= self._keyring_updated

        aur_helper = self._aur_helper_fn()
        update_cmd: list[str] | None = None
        update_title = "System update"

        if aur_helper == "paru":
            update_cmd = ["paru", "-Syu", "--noconfirm"]
            update_title = "System and AUR update (paru)"
        elif aur_helper == "yay":
            update_cmd = [
                "yay",
                "-Syu",
                "--noconfirm",
                "--sudoloop",
                "--answerclean",
                "None",
                "--answerdiff",
                "None",
            ]
            update_title = "System and AUR update (yay)"
        elif shutil.which("pacman") is not None:
            update_cmd = ["sudo", "pacman", "-Syu", "--noconfirm"]
            update_title = "System update (pacman)"

        if update_cmd is not None:
            if self.reinstall_packages:
                update_cmd += ["--", *self.reinstall_packages]
            aur_error, is_net_failure, aur_updated = self._run_step(
                update_cmd, console, update_title
            )
            if aur_error and re.search(
                r"marginal trust|unknown trust|unknown public key|"
                r"invalid or corrupted package.*signature",
                self._last_step_output,
                re.I,
            ):
                if not self._prepare_keyring(console, force=True):
                    return 2
                done_count += self._keyring_steps
                any_updates |= self._keyring_updated
                aur_error, is_net_failure, aur_updated = self._run_step(
                    update_cmd, console, f"{update_title} (retry after keyring update)"
                )
            if aur_error and is_net_failure:
                console.print(
                    "[yellow]Mirror or network failure detected. "
                    "Attempting mirror recovery[/yellow]"
                )
                mirror_failed, _ = self._refresh_mirrors(console)
                if mirror_failed:
                    console.print(
                        "[red]FAIL: Mirror recovery failed. Package upgrade aborted.[/red]"
                    )
                    return 1
                retry_error, _, retry_updated = self._run_step(
                    update_cmd,
                    console,
                    f"{update_title} (retry after mirror recovery)",
                )
                if retry_error:
                    had_error = True
                    fail_count += 1
                    console.print(
                        "[red]FAIL: Package upgrade aborted — persistent network failure.[/red]"
                    )
                    return 1
                done_count += 1
                if retry_updated:
                    any_updates = True
            elif aur_error:
                had_error = True
                fail_count += 1
                if created_snap:
                    command = (
                        "sudo snapper rollback or select snapshot in bootloader"
                        if created_snap == "snapper"
                        else "sudo timeshift --restore"
                    )
                    console.print(f"  [dim]Rollback available: {command}[/dim]")
                console.print(
                    format_sysup_summary(done=done_count, failed=fail_count, skipped=skip_count)
                )
                return 2
            else:
                done_count += 1
                if aur_updated:
                    any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Package update",
                detail="(no supported package manager installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        if shutil.which("flatpak") is not None:
            flatpak_error, _, flatpak_updated = self._run_step(
                ["flatpak", "update", "-y"], console, "Flatpak update"
            )
            had_error |= flatpak_error
            if flatpak_error:
                fail_count += 1
            else:
                done_count += 1
                if flatpak_updated:
                    any_updates = True

            unused_error, _, unused_updated = self._run_step(
                ["flatpak", "uninstall", "--unused", "-y"],
                console,
                "Flatpak cleanup (unused runtimes)",
            )
            had_error |= unused_error
            if unused_error:
                fail_count += 1
            else:
                done_count += 1
                if unused_updated:
                    any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Flatpak update",
                detail="(not installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        if shutil.which("paccache") is not None:
            cache_error, _, cache_updated = self._run_step(
                ["sudo", "paccache", "-rk2"],
                console,
                "Pacman cache cleanup (keep 2 versions)",
            )
            had_error |= cache_error
            if cache_error:
                fail_count += 1
            else:
                done_count += 1
                if cache_updated:
                    any_updates = True

            uninstalled_error, _, uninstalled_updated = self._run_step(
                ["sudo", "paccache", "-ruk0"],
                console,
                "Pacman cache cleanup (uninstalled packages)",
            )
            had_error |= uninstalled_error
            if uninstalled_error:
                fail_count += 1
            else:
                done_count += 1
                if uninstalled_updated:
                    any_updates = True

        omz_upgrade = context.home / ".oh-my-zsh" / "tools" / "upgrade.sh"
        if omz_upgrade.exists():
            omz_error, _, omz_updated = self._run_step(
                ["sh", str(omz_upgrade)],
                console,
                "Oh-My-Zsh update",
            )
            had_error |= omz_error
            if omz_error:
                fail_count += 1
            else:
                done_count += 1
                if omz_updated:
                    any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Oh-My-Zsh update",
                detail="(not installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        if shutil.which("fwupdmgr") is not None:
            fw_error, _, fw_updated = self._run_step(
                ["fwupdmgr", "update", "-y"], console, "Firmware update"
            )
            had_error |= fw_error
            if fw_error:
                fail_count += 1
            else:
                done_count += 1
                if fw_updated:
                    any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Firmware update",
                detail="(not installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        try:
            pacnew_files = detect_pacnew_files()
        except OSError:
            pacnew_files = []
            for line in format_status_line("WARN", "configuration files could not be verified"):
                console.print(line)
        if pacnew_files:
            console.print(
                f"\n[bold yellow]Note: {len(pacnew_files)} .pacnew "
                "configuration files found:[/bold yellow]"
            )
            for f in pacnew_files[:5]:
                console.print(f"  [yellow]{f}[/yellow]")
            console.print(
                "[yellow]Run 'pacdiff' to review and merge configuration updates.[/yellow]"
            )

        postflight = MaintenanceChecks(self.config).run(context, POSTFLIGHT_IDS)
        for result in postflight:
            if result.severity != Severity.PASS:
                for line in format_status_line(
                    result.severity.value if result.severity != Severity.OUTD else "OLD",
                    result.message,
                ):
                    console.print(line)
            if result.check_id == "sys.rebuild" and result.details.get("rebuild_packages"):
                if not self._offer_rebuilds(result, context, console):
                    had_error = True
                    fail_count += 1
        if any(r.severity == Severity.FAIL for r in postflight):
            had_error = True
        console.print()
        console.print(format_sysup_summary(done=done_count, failed=fail_count, skipped=skip_count))
        if not had_error:
            if not any_updates:
                console.print(
                    "[dim]Nothing to update. All packages and components are up to date.[/dim]"
                )
            else:
                console.print("[dim]All updates completed successfully.[/dim]")
        elif created_snap:
            if created_snap == "snapper":
                console.print(
                    "\n[dim]Rollback available: sudo snapper rollback "
                    "or select snapshot in bootloader[/dim]"
                )
            elif created_snap == "timeshift":
                console.print("\n[dim]Rollback available: sudo timeshift --restore[/dim]")

        reboot_status = detect_reboot_status()
        if reboot_status.required:
            console.print(
                f"\n[bold yellow]System reboot recommended:[/bold yellow] "
                f"[yellow]{reboot_status.reason}[/yellow]"
            )
        return 2 if had_error else 0

    def _maintenance_preflight(
        self, context: ScanContext, console: Console, ids: frozenset[str] = PREFLIGHT_IDS
    ) -> bool:
        checks = MaintenanceChecks(self.config).run(context, ids)
        has_blocking = any(r.details.get("blocks_upgrade") for r in checks)
        for result in checks:
            if result.severity == Severity.PASS:
                continue
            for line in format_status_line(result.severity.value, result.message):
                console.print(line)
            if result.check_id == "sys.news":
                notices = result.details.get("notices", [])
                for item in notices:
                    console.print(f'        {item["title"]}\n        {item["url"]}', markup=False)
                if not has_blocking:
                    prompt = (
                        "Have you read these notices and completed any required steps?"
                        if notices
                        else "Arch notices could not be verified. Continue without reviewing them?"
                    )
                    if not self._confirm(prompt):
                        return False
                    if notices:
                        try:
                            MaintenanceState().acknowledge_news([n["url"] for n in notices])
                        except (OSError, ValueError) as exc:
                            for line in format_status_line(
                                "FAIL", f"Could not save reviewed notices: {exc}"
                            ):
                                console.print(line)
                            return False
            else:
                items = result.details.get("items") or result.details.get("packages")
                if items and isinstance(items, list):
                    for item in items:
                        console.print(f"        [dim]• {escape(str(item))}[/dim]")
            if result.check_id != "sys.news" and result.remediation:
                console.print(f"        [dim]fix: {escape(str(result.remediation))}[/dim]")

        if has_blocking:
            blocking_ids = [r.check_id for r in checks if r.details.get("blocks_upgrade")]
            noun = "check" if len(blocking_ids) == 1 else "checks"
            blocked_str = ", ".join(f"'{cid}'" for cid in blocking_ids)
            console.print(
                f"\n  [bold red]FAIL: Upgrade aborted — "
                f"critical preflight {noun} {blocked_str} failed.[/bold red]\n"
            )
            return False
        return True

    @staticmethod
    def _confirm(prompt: str) -> bool:
        try:
            return typer.confirm(prompt, default=False)
        except (typer.Abort, EOFError):
            return False

    def _prepare_keyring(self, console: Console, force: bool = False) -> bool:
        self._keyring_steps = 0
        self._keyring_updated = False
        if "sys.keyring" in {cid.replace(":", ".") for cid in self.config.disabled_checks}:
            return True
        if not shutil.which("pacman"):
            return True
        if not force and not shutil.which("checkupdates"):
            return True
        try:
            keyrings = self.config.maintenance.keyring_packages
            if not force:
                result = capture(["checkupdates"], 60)
                if result.returncode not in {0, 2}:
                    return True  # The full upgrade will report repository failures.
                available = {line.split()[0] for line in result.stdout.splitlines() if line.split()}
                keyrings = [p for p in keyrings if p in available]
            if not keyrings:
                return True
            if any(not PACKAGE_RE.fullmatch(p) for p in keyrings):
                return False
            err, _, updated = self._run_step(
                ["sudo", "pacman", "-Sy", "--needed", *keyrings],
                console,
                "Package signing key update",
            )
            if err:
                return False
            self._keyring_steps += 1
            self._keyring_updated |= updated
            err, _, updated = self._run_step(
                ["sudo", "pacman", "-Su"], console, "Complete system upgrade after key update"
            )
            if not err:
                self._keyring_steps += 1
                self._keyring_updated |= updated
            return not err
        except (OSError, subprocess.SubprocessError):
            return False

    def _offer_rebuilds(self, result: CheckResult, context: ScanContext, console: Console) -> bool:
        helper = self._aur_helper_fn()
        if helper not in {"paru", "yay"}:
            return True
        successful = True
        for package in result.details["rebuild_packages"]:
            if not PACKAGE_RE.fullmatch(package) or package.endswith("-bin"):
                continue
            if self._confirm(f"Review and rebuild {package} to check library compatibility?"):
                rebuild_flags = ["--rebuild", "yes"] if helper == "paru" else ["--rebuild"]
                error, _, _ = self._run_step(
                    [helper, "-S", *rebuild_flags, "--", package], console, f"Rebuild {package}"
                )
                if not error:
                    refreshed = MaintenanceChecks(self.config).run(
                        context, frozenset({"sys.rebuild"})
                    )
                    if (
                        not refreshed
                        or refreshed[0].details.get("verified") is False
                        or refreshed[0].severity == Severity.FAIL
                        or package in refreshed[0].details.get("rebuild_packages", [])
                    ):
                        for line in format_status_line(
                            "WARN", f"{package} still has compatibility findings"
                        ):
                            console.print(line)
                        successful = False
                else:
                    successful = False
        return successful

    def _create_pre_update_snapshot(self, console: Console) -> tuple[bool, str, str | None]:
        console_width = getattr(console, "width", 80) or 80
        tool = self._snapshot_tool_fn()
        if tool == "snapper":
            cmd = ["sudo", "snapper", "create", "-d", "dotdoctor pre-sysup", "-t", "single", "-p"]
            err, _, _ = self._run_step(cmd, console, "Pre-update snapshot (snapper)")
            if err:
                return True, "fail", None
            return False, "done", "snapper"
        if tool == "timeshift":
            cmd = [
                "sudo",
                "timeshift",
                "--create",
                "--comments",
                "dotdoctor pre-sysup",
                "--tags",
                "D",
            ]
            err, _, _ = self._run_step(cmd, console, "Pre-update snapshot (timeshift)")
            if err:
                return True, "fail", None
            return False, "done", "timeshift"

        for line_text in format_status_line(
            STATUS_SKIP,
            "Pre-update snapshot",
            detail="(no snapshot tool configured)",
            width=console_width,
        ):
            console.print(line_text)
        return False, "skip", None

    def _refresh_mirrors(self, console: Console) -> tuple[bool, str]:
        console_width = getattr(console, "width", 80) or 80
        if shutil.which("cachyos-rate-mirrors") is not None:
            had_error, _, _ = self._run_step(
                ["sudo", "cachyos-rate-mirrors"],
                console,
                "Mirror refresh",
            )
            return had_error, "fail" if had_error else "done"

        if shutil.which("reflector") is not None:
            had_error, _, _ = self._run_step(
                [
                    "sudo",
                    "reflector",
                    "--latest",
                    "5",
                    "--protocol",
                    "https",
                    "--sort",
                    "rate",
                    "--save",
                    "/etc/pacman.d/mirrorlist",
                ],
                console,
                "Mirror refresh",
            )
            return had_error, "fail" if had_error else "done"

        for line_text in format_status_line(
            STATUS_SKIP,
            "Mirror refresh",
            detail="(no supported mirror tool installed)",
            width=console_width,
        ):
            console.print(line_text)
        return False, "skip"

    def _run_streaming_step(
        self,
        command: list[str],
        console: Console,
        title: str,
        console_width: int,
    ) -> SimpleNamespace:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            bufsize=1,
        )

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        current_subline: list[str] = [""]
        spinner = Spinner("dots")
        ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

        def _read_stream(stream: Any, lines_buf: list[str], is_stdout: bool) -> None:
            try:
                for raw_line in iter(stream.readline, ""):
                    lines_buf.append(raw_line)
                    if is_stdout:
                        cleaned = ansi_re.sub("", raw_line).strip()
                        if cleaned:
                            current_subline[0] = cleaned
            except Exception:
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        t_out = threading.Thread(
            target=_read_stream, args=(proc.stdout, stdout_lines, True), daemon=True
        )
        t_err = threading.Thread(
            target=_read_stream, args=(proc.stderr, stderr_lines, False), daemon=True
        )
        t_out.start()
        t_err.start()

        def _build_grid(sub: str = "") -> Table:
            grid = Table.grid(expand=False)
            grid.add_column()
            grid.add_column(width=STATUS_WIDTH)
            grid.add_column()
            grid.add_column()
            grid.add_row(INDENT, spinner, GAP, title)
            if sub:
                prefix_len = 2 + STATUS_WIDTH + 2 + 2
                max_sub_len = max(10, console_width - prefix_len)
                truncated = sub if len(sub) <= max_sub_len else sub[: max_sub_len - 1] + "…"
                grid.add_row(INDENT, "", GAP, f"[dim]↳ {escape(truncated)}[/dim]")
            return grid

        try:
            with Live(
                _build_grid(), console=console, transient=True, refresh_per_second=10
            ) as live:
                while proc.poll() is None:
                    sub = current_subline[0]
                    live.update(_build_grid(sub))
                    time.sleep(0.08)
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise

        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)
        return SimpleNamespace(
            returncode=proc.returncode if proc.returncode is not None else 1,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
        )

    def _run_step(
        self, command: list[str], console: Console, title: str
    ) -> tuple[bool, bool, bool]:
        console_width = getattr(console, "width", 80) or 80
        is_interactive = (
            bool(getattr(console, "is_terminal", False))
            and not os.environ.get("NO_COLOR")
            and not os.environ.get("NO_ANIMATION")
            and not os.environ.get("DOTDOCTOR_NO_ANIMATION")
        )
        needs_input = (
            any(name in command for name in {"pacman", "yay", "paru"})
            and any(flag in command for flag in {"-Sy", "-Su", "-S"})
            and "--noconfirm" not in command
        )
        completed: Any
        try:
            if needs_input:
                # Pacman/AUR review prompts must remain visible and retain stdin.
                # A pipe reader can hide a prompt without a newline and deadlock.
                completed = subprocess.run(command, check=False)
            elif (
                is_interactive
                and hasattr(console, "status")
                and subprocess.run is _ORIGINAL_SUBPROCESS_RUN
            ):
                completed = self._run_streaming_step(command, console, title, console_width)
            else:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                )
        except subprocess.TimeoutExpired:
            for line_text in format_status_line(
                STATUS_FAIL, title, detail="(timed out)", width=console_width
            ):
                console.print(line_text)
            return True, True, False
        except (OSError, subprocess.SubprocessError) as exc:
            for line_text in format_status_line(
                STATUS_FAIL, title, detail=f"(failed to start: {exc})", width=console_width
            ):
                console.print(line_text)
            return True, False, False

        stderr_output = (getattr(completed, "stderr", "") or "").strip()
        stdout_output = (getattr(completed, "stdout", "") or "").strip()
        combined_output = f"{stdout_output}\n{stderr_output}".strip()
        self._last_step_output = combined_output
        is_net_failure = _is_mirror_failure(combined_output)

        if completed.returncode != 0:
            for line_text in format_status_line(
                STATUS_FAIL,
                title,
                detail=f"(exit={completed.returncode})",
                width=console_width,
            ):
                console.print(line_text)
            error_text = stderr_output if stderr_output else stdout_output
            if error_text:
                error_lines = [line.rstrip() for line in error_text.splitlines() if line.strip()]
                prefix = "        │ "
                avail_width = max(15, console_width - len(prefix))
                if len(error_lines) > 10:
                    omitted = len(error_lines) - 10
                    console.print(f"        [dim]│ ({omitted} lines omitted)[/dim]")
                    error_lines = error_lines[-10:]
                for err_line in error_lines:
                    wrapped_err = textwrap.wrap(err_line, width=avail_width) or [err_line]
                    for i, w in enumerate(wrapped_err):
                        p = prefix if i == 0 else "          "
                        console.print(f"[dim]{p}{w}[/dim]")
            return True, is_net_failure, False

        had_updates = needs_input or _detect_step_updates(command, stdout_output, stderr_output)
        for line_text in format_status_line(STATUS_DONE, title, width=console_width):
            console.print(line_text)
        return False, False, had_updates


def _parse_fwupdmgr_updates(output: str) -> int:
    """Count firmware updates only when there are explicit update indicators."""
    lines = [line.rstrip() for line in output.splitlines()]
    normalized = "\n".join(line.lower() for line in lines)

    no_update_markers = (
        "no updates available",
        "no updatable devices",
        "devices with the latest available firmware version",
        "devices with no available firmware updates",
    )
    if any(marker in normalized for marker in no_update_markers):
        # Continue scanning only for explicit updates, but default to 0.
        pass

    version_transition_pattern = re.compile(r"\b\d[\w.-]*\s*(?:->|→)\s*\d[\w.-]*\b")
    explicit_update_pattern = re.compile(
        r"\b(update available for|updates available for|upgrade available for)\b",
    )

    updates = 0
    in_no_update_section = False
    for raw_line in lines:
        line = raw_line.strip()
        lowered = line.lower()
        if not line:
            in_no_update_section = False
            continue

        if lowered.startswith("devices with the latest available firmware version"):
            in_no_update_section = True
            continue

        if lowered.startswith("devices with no available firmware updates"):
            in_no_update_section = True
            continue

        if in_no_update_section:
            continue

        if version_transition_pattern.search(line):
            updates += 1
            continue

        if explicit_update_pattern.search(lowered):
            updates += 1

    return updates
