import os
import platform
import re
import shutil
import socket
import subprocess
import textwrap
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table

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
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


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
        boot_free = root_free

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
            completed=subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_str,
            )
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
        try:
            for p in etc_dir.rglob("*.pacnew"):
                files.append(str(p))
            for p in etc_dir.rglob("*.pacsave"):
                files.append(str(p))
        except OSError:
            pass
    return sorted(files)


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
    ) -> None:
        self._is_online_fn = is_online_fn
        self._aur_helper_fn = aur_helper_fn

    def build_tasks(self, context: ScanContext) -> list[SystemCheckTask]:
        tasks: list[SystemCheckTask] = []
        online = self._is_online_fn()

        if not online:
            tasks.append(
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
            tasks.append(
                SystemCheckTask(
                    check_id="sys.packages",
                    label="Packages",
                    runner=lambda: self._check_arch_packages(context),
                )
            )

            aur_helper = self._aur_helper_fn()
            if aur_helper is not None:
                tasks.append(
                    SystemCheckTask(
                        check_id="sys.aur",
                        label=f"AUR ({aur_helper})",
                        runner=lambda: self._check_aur_packages(context, aur_helper),
                    )
                )

            if shutil.which("flatpak") is not None:
                tasks.append(
                    SystemCheckTask(
                        check_id="sys.flatpak",
                        label="Flatpak packages",
                        runner=lambda: self._check_flatpak(context),
                    )
                )
                tasks.append(
                    SystemCheckTask(
                        check_id="sys.flatpak-unused",
                        label="Unused Flatpaks",
                        runner=lambda: self._check_flatpak_unused(context),
                    )
                )

            tasks.append(
                SystemCheckTask(
                    check_id="sys.firmware",
                    label="Firmware updates",
                    runner=lambda: self._check_firmware(context),
                )
            )

            omz_path = _resolve_oh_my_zsh_path(context)
            if omz_path is not None:
                tasks.append(
                    SystemCheckTask(
                        check_id="sys.shell-omz",
                        label="Oh-My-Zsh updates",
                        runner=lambda: self._check_oh_my_zsh(omz_path),
                    )
                )

        tasks.append(
            SystemCheckTask(
                check_id="sys.reboot",
                label="Reboot status",
                runner=lambda: self._check_reboot(context),
            )
        )
        tasks.append(
            SystemCheckTask(
                check_id="sys.disk",
                label="Disk space",
                runner=lambda: self._check_disk_space(context),
            )
        )

        if shutil.which("pacman") is not None:
            tasks.append(
                SystemCheckTask(
                    check_id="sys.orphans",
                    label="Orphan packages",
                    runner=lambda: self._check_orphans(context),
                )
            )

        if shutil.which("pacman") is not None or shutil.which("paccache") is not None:
            tasks.append(
                SystemCheckTask(
                    check_id="sys.cache",
                    label="Pacman cache",
                    runner=lambda: self._check_pacman_cache(context),
                )
            )

        if shutil.which("pacdiff") is not None or shutil.which("pacman") is not None:
            tasks.append(
                SystemCheckTask(
                    check_id="sys.pacnew",
                    label=".pacnew files",
                    runner=lambda: self._check_pacnew(context),
                )
            )

        if shutil.which("systemctl") is not None:
            tasks.append(
                SystemCheckTask(
                    check_id="sys.services",
                    label="Failed services",
                    runner=lambda: self._check_failed_services(context),
                )
            )

        if shutil.which("journalctl") is not None:
            tasks.append(
                SystemCheckTask(
                    check_id="sys.journal",
                    label="Journal disk usage",
                    runner=lambda: self._check_journal(context),
                )
            )

        return tasks

    def run(self, context: ScanContext) -> ScanReport:
        tasks = self.build_tasks(context)
        results = self._run_tasks(tasks, on_task_complete=None)
        return ScanReport(profile=context.profile, results=results)

    def run_with_progress(
        self,
        context: ScanContext,
        on_task_complete: Callable[[str], None] | None = None,
    ) -> ScanReport:
        tasks = self.build_tasks(context)
        results = self._run_tasks(tasks, on_task_complete=on_task_complete)
        return ScanReport(profile=context.profile, results=results)

    def _run_tasks(
        self,
        tasks: list[SystemCheckTask],
        on_task_complete: Callable[[str], None] | None,
    ) -> list[CheckResult]:
        if not tasks:
            return []

        ordered_results: dict[str, CheckResult | None] = {}
        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            futures: dict[Future[CheckResult | None], SystemCheckTask] = {
                pool.submit(task.runner): task for task in tasks
            }
            pending = set(futures.keys())
            while pending:
                done, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                for future in done:
                    task = futures[future]
                    ordered_results[task.check_id] = future.result()
                    if on_task_complete is not None:
                        on_task_complete(task.check_id)

        collected_results: list[CheckResult] = []
        for task in tasks:
            result = ordered_results.get(task.check_id)
            if result is not None:
                collected_results.append(result)
        return collected_results

    def _check_arch_packages(self, context: ScanContext) -> CheckResult:
        if shutil.which("checkupdates") is None:
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.PASS,
                message="checkupdates not installed",
                remediation=None,
            )

        result = _run_capture(["checkupdates"], timeout=60)
        if result.timed_out:
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.FAIL,
                message="package check timed out",
                remediation="refresh mirror list and retry",
            )
        if result.completed is None:
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN,
                message="could not run checkupdates",
                remediation="run checkupdates manually to inspect error",
            )
        completed = result.completed
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if completed.returncode == 2 or not lines:
            return _result_for_count("sys.packages", 0)

        if completed.returncode not in {0, 2}:
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.FAIL,
                message="package check failed",
                remediation="verify mirror availability and run pacman -Sy",
            )

        return _result_for_count("sys.packages", len(lines))

    def _check_flatpak(self, context: ScanContext) -> CheckResult:
        if shutil.which("flatpak") is None:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.PASS,
                message="flatpak not installed",
                remediation=None,
            )

        result = _run_capture(["flatpak", "remote-ls", "--updates"], timeout=60)
        if result.timed_out:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.FAIL,
                message="Flatpak check timed out",
                remediation="check network connectivity and retry",
            )
        if result.completed is None:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.WARN,
                message="could not run Flatpak check",
                remediation="run flatpak remote-ls --updates manually",
            )
        if result.completed.returncode != 0:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.FAIL,
                message=f"flatpak check failed (exit={result.completed.returncode})",
                remediation="check Flatpak remote configuration",
            )
        lines = [line for line in result.completed.stdout.splitlines() if line.strip()]
        return _result_for_count("sys.flatpak", len(lines))

    def _check_firmware(self, context: ScanContext) -> CheckResult:
        if shutil.which("fwupdmgr") is None:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.PASS,
                message="fwupd not installed",
                remediation=None,
            )

        refresh = _run_capture(["fwupdmgr", "refresh"], timeout=90)
        if refresh.timed_out:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.FAIL,
                message="fwupdmgr refresh timed out",
                remediation="check network connectivity and retry",
            )
        if refresh.completed is None:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.WARN,
                message="could not refresh firmware metadata",
                remediation="run fwupdmgr refresh manually",
            )

        updates_result = _run_capture(["fwupdmgr", "get-updates"], timeout=90)
        if updates_result.timed_out:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.FAIL,
                message="fwupdmgr get-updates timed out",
                remediation="check network connectivity and retry",
            )
        if updates_result.completed is None:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.WARN,
                message="could not run firmware update check",
                remediation="run fwupdmgr get-updates manually",
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
                remediation="run fwupdmgr get-updates manually and inspect output",
            )

        if update_count == 0:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.PASS,
                message="no firmware updates",
                remediation=None,
                details={"updates": 0},
            )

        return _result_for_count("sys.firmware", update_count)

    def _check_oh_my_zsh(self, omz_path: str) -> CheckResult:
        update_count = _detect_oh_my_zsh_updates(omz_path)
        if update_count > 0:
            return CheckResult(
                check_id="sys.shell-omz",
                severity=Severity.OUTD,
                message=f"{update_count} update{'s' if update_count != 1 else ''} available",
                remediation="run dotdoctor --sysup to apply updates",
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
                remediation="reboot system to load new kernel or packages",
                details={
                    "running_kernel": status.running_kernel,
                    "installed_kernels": status.installed_kernels,
                    "reboot_required": True,
                },
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
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.FAIL,
                message=f"{aur_helper} update check timed out",
                remediation="refresh mirror list and retry",
            )
        if result.completed is None:
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.WARN,
                message=f"could not run {aur_helper} -Qua",
                remediation=f"run {aur_helper} -Qua manually",
            )
        lines = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        flagged = [line for line in lines if _AUR_FLAGGED_RE.search(line)]
        regular = [line for line in lines if line not in flagged]

        if not lines:
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.PASS,
                message="up to date",
                remediation=None,
                details={"updates": 0, "flagged": 0},
            )
        if flagged:
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.OUTD,
                message=(
                    f"{len(lines)} AUR update{'s' if len(lines) != 1 else ''} available "
                    f"({len(flagged)} flagged out-of-date)"
                ),
                remediation="run dotdoctor --sysup to apply updates",
                details={"updates": len(regular), "flagged": len(flagged)},
            )
        return CheckResult(
            check_id="sys.aur",
            severity=Severity.OUTD,
            message=f"{len(regular)} AUR update{'s' if len(regular) != 1 else ''} available",
            remediation="run dotdoctor --sysup to apply updates",
            details={"updates": len(regular), "flagged": 0},
        )

    def _check_pacman_cache(
        self,
        context: ScanContext,
        cache_dir: Path = Path("/var/cache/pacman/pkg"),
    ) -> CheckResult:
        if not cache_dir.exists():
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.PASS,
                message="pacman cache clean",
                remediation=None,
            )

        total_bytes = 0
        try:
            with os.scandir(cache_dir) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        total_bytes += entry.stat().st_size
        except OSError:
            pass

        total_str = _format_bytes(total_bytes)
        candidates = 0
        saved_str = ""

        if shutil.which("paccache") is not None:
            res = _run_capture(["paccache", "-d"], timeout=20)
            if res.completed and res.completed.returncode == 0:
                match = re.search(
                    r"finished dry run:\s*(\d+)\s*candidates\s*\(disk space saved:\s*([^)]+)\)",
                    res.completed.stdout,
                )
                if match:
                    candidates = int(match.group(1))
                    saved_str = match.group(2).strip()

        if candidates > 0 and (total_bytes > 2 * 1024**3 or candidates >= 10):
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.WARN,
                message=f"{total_str} in pacman cache ({saved_str} reclaimable)",
                remediation="run sudo paccache -rk2",
                details={"total_bytes": total_bytes, "candidates": candidates, "saved": saved_str},
            )

        if total_bytes > 5 * 1024**3:
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.WARN,
                message=f"{total_str} in pacman cache",
                remediation="run sudo paccache -rk2",
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
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.PASS,
                message="pacman not installed",
                remediation=None,
            )

        result = _run_capture(["pacman", "-Qtdq"], timeout=15)
        if result.timed_out:
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="orphan check timed out",
                remediation="run pacman -Qtdq manually",
            )
        if result.completed is None or result.completed.returncode not in {0, 1}:
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="could not check orphan packages",
                remediation="run pacman -Qtdq manually",
            )

        orphans = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        if orphans:
            count = len(orphans)
            noun = "package" if count == 1 else "packages"
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message=f"{count} orphan {noun} found",
                remediation="run sudo pacman -Rns $(pacman -Qtdq)",
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
                remediation="run pacdiff -s to merge configuration files",
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
            return CheckResult(
                check_id="sys.services",
                severity=Severity.PASS,
                message="systemctl not installed",
                remediation=None,
            )

        failed_units: list[str] = []
        sys_res = _run_capture(
            ["systemctl", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if sys_res.completed and sys_res.completed.returncode == 0:
            for line in sys_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    failed_units.append(parts[0])

        user_res = _run_capture(
            ["systemctl", "--user", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if user_res.completed and user_res.completed.returncode == 0:
            for line in user_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    failed_units.append(f"{parts[0]} (user)")

        if failed_units:
            count = len(failed_units)
            noun = "unit" if count == 1 else "units"
            sample = ", ".join(failed_units[:2])
            first_unit = failed_units[0].split()[0]
            return CheckResult(
                check_id="sys.services",
                severity=Severity.FAIL,
                message=f"{count} failed {noun} ({sample})",
                remediation=f"run systemctl status {first_unit} to inspect",
                details={"failed_units": failed_units},
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
            return CheckResult(
                check_id="sys.flatpak-unused",
                severity=Severity.PASS,
                message="flatpak not installed",
                remediation=None,
            )

        res = _run_capture(
            ["flatpak", "uninstall", "--unused"],
            timeout=15,
            input_str="n\n",
        )
        if res.timed_out or res.completed is None:
            return CheckResult(
                check_id="sys.flatpak-unused",
                severity=Severity.PASS,
                message="could not check unused flatpaks",
                remediation=None,
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
                remediation="run flatpak uninstall --unused",
                details={"unused_count": count},
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
            return CheckResult(
                check_id="sys.journal",
                severity=Severity.PASS,
                message="journalctl not installed",
                remediation=None,
            )

        res = _run_capture(["journalctl", "--disk-usage"], timeout=10)
        if res.completed and res.completed.returncode == 0:
            match = re.search(
                r"take up\s+([\d.]+\s*[KMGT]?i?B?)\s+in",
                res.completed.stdout,
                re.IGNORECASE,
            )
            if match:
                size_str = match.group(1).strip()
                is_large = False
                if size_str.upper().endswith("G") or size_str.upper().endswith("GIB"):
                    num_part = re.sub(r"[^\d.]", "", size_str)
                    try:
                        if float(num_part) >= 4.0:
                            is_large = True
                    except ValueError:
                        pass

                return CheckResult(
                    check_id="sys.journal",
                    severity=Severity.WARN if is_large else Severity.PASS,
                    message=f"{size_str} in journal logs",
                    remediation="run sudo journalctl --vacuum-size=1G" if is_large else None,
                    details={"disk_usage": size_str},
                )

        return CheckResult(
            check_id="sys.journal",
            severity=Severity.PASS,
            message="journal size normal",
            remediation=None,
        )


def _result_for_count(check_id: str, updates: int) -> CheckResult:
    if updates > 0:
        return CheckResult(
            check_id=check_id,
            severity=Severity.OUTD,
            message=f"{updates} update{'s' if updates != 1 else ''} available",
            remediation="run dotdoctor --sysup to apply updates",
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


def _detect_oh_my_zsh_updates(omz_path: str) -> int:
    if shutil.which("git") is None:
        return 0

    git_dir = os.path.join(omz_path, ".git")
    if not os.path.isdir(git_dir):
        return 0

    _run_capture(["git", "-C", omz_path, "fetch", "--quiet", "origin"], timeout=30)
    count_result = _run_capture(
        ["git", "-C", omz_path, "rev-list", "--count", "HEAD..origin/master"],
        timeout=30,
    )
    if count_result.completed is None or count_result.completed.returncode != 0:
        return 0

    raw = count_result.completed.stdout.strip()
    if not raw.isdigit():
        return 0
    return int(raw)


class SystemUpgradeService:
    """Runs sequential interactive system update commands."""

    def __init__(
        self,
        is_online_fn: Callable[[], bool] = is_online,
        aur_helper_fn: Callable[[], str | None] = detect_aur_helper,
    ) -> None:
        self._is_online_fn = is_online_fn
        self._aur_helper_fn = aur_helper_fn

    def run(self, context: ScanContext, console: Console) -> int:
        if not self._is_online_fn():
            console.print(
                "[red]FAIL: No active internet connection detected. "
                "Aborting system upgrade.[/red]"
            )
            return 1

        disk_status = detect_disk_space_status()
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

        console.print("  [dim]Caching sudo credentials[/dim]")
        sudo_cache = subprocess.run(["sudo", "true"], check=False)
        if sudo_cache.returncode != 0:
            console.print("[red]Failed to cache sudo credentials. Aborting update phase.[/red]")
            return 3

        had_error = False
        done_count = 0
        fail_count = 0
        skip_count = 0
        console_width = getattr(console, "width", 80) or 80

        mirror_err, mirror_status = self._refresh_mirrors(console)
        had_error |= mirror_err
        if mirror_status == "done":
            done_count += 1
        elif mirror_status == "fail":
            fail_count += 1
        else:
            skip_count += 1

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
            aur_error, is_net_failure = self._run_step(update_cmd, console, update_title)
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
                retry_error, _ = self._run_step(
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
            elif aur_error:
                had_error = True
                fail_count += 1
            else:
                done_count += 1
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
            flatpak_error, _ = self._run_step(
                ["flatpak", "update", "-y"], console, "Flatpak update"
            )
            had_error |= flatpak_error
            if flatpak_error:
                fail_count += 1
            else:
                done_count += 1

            unused_error, _ = self._run_step(
                ["flatpak", "uninstall", "--unused", "-y"],
                console,
                "Flatpak cleanup (unused runtimes)",
            )
            had_error |= unused_error
            if unused_error:
                fail_count += 1
            else:
                done_count += 1
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
            cache_error, _ = self._run_step(
                ["sudo", "paccache", "-rk2"],
                console,
                "Pacman cache cleanup (keep 2 versions)",
            )
            had_error |= cache_error
            if cache_error:
                fail_count += 1
            else:
                done_count += 1

            uninstalled_error, _ = self._run_step(
                ["sudo", "paccache", "-ruk0"],
                console,
                "Pacman cache cleanup (uninstalled packages)",
            )
            had_error |= uninstalled_error
            if uninstalled_error:
                fail_count += 1
            else:
                done_count += 1

        omz_upgrade = context.home / ".oh-my-zsh" / "tools" / "upgrade.sh"
        if omz_upgrade.exists():
            omz_error, _ = self._run_step(
                ["sh", str(omz_upgrade)],
                console,
                "Oh-My-Zsh update",
            )
            had_error |= omz_error
            if omz_error:
                fail_count += 1
            else:
                done_count += 1
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
            fw_error, _ = self._run_step(["fwupdmgr", "update", "-y"], console, "Firmware update")
            had_error |= fw_error
            if fw_error:
                fail_count += 1
            else:
                done_count += 1
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Firmware update",
                detail="(not installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        pacnew_files = detect_pacnew_files()
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

        console.print()
        console.print(format_sysup_summary(done=done_count, failed=fail_count, skipped=skip_count))

        reboot_status = detect_reboot_status()
        if reboot_status.required:
            console.print(
                f"\n[bold yellow]System reboot recommended:[/bold yellow] "
                f"[yellow]{reboot_status.reason}[/yellow]"
            )
        return 2 if had_error else 0

    def _refresh_mirrors(self, console: Console) -> tuple[bool, str]:
        console_width = getattr(console, "width", 80) or 80
        if shutil.which("cachyos-rate-mirrors") is not None:
            had_error, _ = self._run_step(
                ["sudo", "cachyos-rate-mirrors"],
                console,
                "Mirror refresh",
            )
            return had_error, "fail" if had_error else "done"

        if shutil.which("reflector") is not None:
            had_error, _ = self._run_step(
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

    def _run_step(self, command: list[str], console: Console, title: str) -> tuple[bool, bool]:
        console_width = getattr(console, "width", 80) or 80
        is_interactive = (
            bool(getattr(console, "is_terminal", False))
            and not os.environ.get("NO_COLOR")
            and not os.environ.get("NO_ANIMATION")
            and not os.environ.get("DOTDOCTOR_NO_ANIMATION")
        )
        try:
            if is_interactive and hasattr(console, "status"):
                grid = Table.grid(expand=False)
                grid.add_column()
                grid.add_column(width=STATUS_WIDTH)
                grid.add_column()
                grid.add_column()
                grid.add_row(INDENT, Spinner("dots"), GAP, title)
                with Live(grid, console=console, transient=True, refresh_per_second=12.5):
                    completed = subprocess.run(
                        command,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
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
            return True, True
        except (OSError, subprocess.SubprocessError) as exc:
            for line_text in format_status_line(
                STATUS_FAIL, title, detail=f"(failed to start: {exc})", width=console_width
            ):
                console.print(line_text)
            return True, False

        stderr_output = (getattr(completed, "stderr", "") or "").strip()
        stdout_output = (getattr(completed, "stdout", "") or "").strip()
        combined_output = f"{stdout_output}\n{stderr_output}".strip()
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
            return True, is_net_failure

        for line_text in format_status_line(STATUS_DONE, title, width=console_width):
            console.print(line_text)
        return False, False


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
