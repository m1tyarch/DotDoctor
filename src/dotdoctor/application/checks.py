"""System audit and dry-run check services."""

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path

import dotdoctor.application.system_update as su
from dotdoctor.application.disk import _format_bytes, detect_disk_space_status
from dotdoctor.application.maintenance import PREFLIGHT_IDS, MaintenanceChecks
from dotdoctor.application.parsers import (
    _AUR_FLAGGED_RE,
    _parse_fwupdmgr_updates,
    parse_package_update_line,
)
from dotdoctor.application.reboot import detect_reboot_status
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure.audit_processes import AuditCancelled, AuditSession, check_cancelled
from dotdoctor.infrastructure.audit_processes import capture as capture_command
from dotdoctor.infrastructure.network_worker import HTTPS_TARGETS

logger = logging.getLogger(__name__)


def is_online(
    targets: tuple[str, ...] = HTTPS_TARGETS,
    timeout: float = 1.5,
) -> bool:
    """Check HTTPS reachability with a shared deadline, including DNS resolution."""
    if not targets or timeout <= 0:
        return False
    try:
        cap_fn = getattr(su, "capture_command", capture_command)
        completed = cap_fn(
            [
                sys.executable,
                "-m",
                "dotdoctor.infrastructure.network_worker",
                json.dumps(targets),
                str(timeout),
            ],
            timeout=timeout + 1.0,
        )
        return completed.returncode == 0 and json.loads(completed.stdout) is True
    except (OSError, ValueError, subprocess.SubprocessError):
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


def detect_aur_helper(which_fn: Callable[[str], str | None] | None = None) -> str | None:
    fn = which_fn or getattr(su, "shutil", shutil).which
    for helper in ("paru", "yay"):
        if fn(helper) is not None:
            return helper
    return None


def _run_capture(
    command: list[str],
    timeout: int,
    input_str: str | None = None,
) -> _ExecResult:
    custom_run_cap = getattr(su, "_run_capture", None)
    if custom_run_cap is not None and custom_run_cap is not _run_capture:
        res = custom_run_cap(command, timeout=timeout)
        if isinstance(res, _ExecResult):
            return res
        return _ExecResult(completed=res)

    cap_cmd = getattr(su, "capture_command", capture_command)
    try:
        return _ExecResult(
            completed=cap_cmd(command, timeout, input_str, {**os.environ, "LC_ALL": "C"}),
        )
    except subprocess.TimeoutExpired:
        return _ExecResult(completed=None, timed_out=True)
    except (OSError, subprocess.SubprocessError):
        return _ExecResult(completed=None, timed_out=False)


def detect_pacnew_files() -> list[str]:
    which_fn = getattr(su, "shutil", shutil).which
    pacdiff_bin = which_fn("pacdiff")
    if pacdiff_bin is not None:
        run_cap = getattr(su, "_run_capture", _run_capture)
        res = run_cap([pacdiff_bin, "-o"], timeout=15)
        if res.completed and res.completed.returncode == 0:
            return [line.strip() for line in res.completed.stdout.splitlines() if line.strip()]

    path_cls = getattr(su, "Path", Path)
    os_mod = getattr(su, "os", os)
    files: list[str] = []
    etc_dir = path_cls("/etc")
    if etc_dir.exists():

        def inaccessible(error: OSError) -> None:
            if not isinstance(error, PermissionError):
                raise error

        for directory, _, names in os_mod.walk(etc_dir, onerror=inaccessible):
            check_cancelled()
            files.extend(
                str(path_cls(directory) / name)
                for name in names
                if name.endswith((".pacnew", ".pacsave"))
            )
    return sorted(files)


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
    which_fn = getattr(su, "shutil", shutil).which
    if which_fn("git") is None:
        return None

    git_dir = os.path.join(omz_path, ".git")
    if not os.path.isdir(git_dir):
        return None

    run_cap = getattr(su, "_run_capture", _run_capture)
    fetched = run_cap(["git", "-C", omz_path, "fetch", "--quiet", "origin"], timeout=30)
    if fetched.completed is None or fetched.completed.returncode != 0:
        return None
    count_result = run_cap(
        ["git", "-C", omz_path, "rev-list", "--count", "HEAD..origin/master"],
        timeout=30,
    )
    if count_result.completed is None or count_result.completed.returncode != 0:
        return None

    raw = count_result.completed.stdout.strip()
    if not raw.isdigit():
        return None
    return int(raw)


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
        "sys.package-db",
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
        "sys.smart",
        "sys.mounts",
    }
)

ALL_CHECK_IDS: frozenset[str] = frozenset(UPDATE_CHECK_IDS | FIX_CHECK_IDS | {"sys.network"})


@dataclass(frozen=True)
class SystemCheckTask:
    check_id: str
    label: str
    runner: Callable[[], CheckResult | None]


class SystemDryRunService:
    """Prepares and runs read-only diagnostic checks without prompting."""

    def __init__(
        self,
        is_online_fn: Callable[[], bool] | None = None,
        aur_helper_fn: Callable[[], str | None] | None = None,
        config: DotDoctorConfig | None = None,
    ) -> None:
        self._is_online_fn = is_online_fn or is_online
        self._aur_helper_fn = aur_helper_fn or detect_aur_helper
        self.config = config or DotDoctorConfig()
        self.last_timings: dict[str, float] = {}

    def clear_cache(self) -> None:
        pass

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
            if task.check_id not in ALL_CHECK_IDS:
                raise ValueError(f"Unregistered check_id: {task.check_id}")
            if _is_included(task.check_id) and not _is_disabled(task.check_id):
                tasks.append(task)

        needs_network = any(_is_included(c) and not _is_disabled(c) for c in network_checks)

        # Thread-safe lazy network probe that does not block build_tasks()
        online_lock = threading.Lock()
        online_val: list[bool] = []
        online_event = threading.Event()
        probe_started = False

        def get_online() -> bool:
            nonlocal probe_started
            with online_lock:
                if online_val:
                    return online_val[0]
                if not probe_started:
                    probe_started = True

                    def _run_probe() -> None:
                        try:
                            online_fn = getattr(su, "is_online", self._is_online_fn)
                            res = (
                                self._is_online_fn()
                                if self._is_online_fn is not is_online
                                else online_fn()
                            )
                        except Exception:
                            res = False
                        with online_lock:
                            online_val.append(res)
                        online_event.set()

                    threading.Thread(target=_run_probe, daemon=True, name="dotdoctor-probe").start()
            online_event.wait()
            return online_val[0]

        self._current_get_online = get_online
        self._current_needs_network = needs_network

        if "sys.network" in (includes or set()) and not _is_disabled("sys.network"):

            def run_network_check() -> CheckResult | None:
                if not get_online():
                    return CheckResult(
                        check_id="sys.network",
                        severity=Severity.FAIL,
                        message="internet access unavailable (HTTPS checks failed)",
                        remediation="check connection, DNS and proxy settings, then retry",
                    )
                return None

            _add_task(
                SystemCheckTask(
                    check_id="sys.network",
                    label="Network connection",
                    runner=run_network_check,
                )
            )

        if needs_network:
            which_fn = getattr(su, "shutil", shutil).which

            if which_fn("pacman") or which_fn("checkupdates"):

                def run_packages() -> CheckResult | None:
                    if not get_online():
                        return None
                    return self._check_arch_packages(context)

                _add_task(
                    SystemCheckTask(
                        check_id="sys.packages",
                        label="Packages",
                        runner=run_packages,
                    )
                )

            aur_helper = self._aur_helper_fn()
            if aur_helper is not None:

                def run_aur() -> CheckResult | None:
                    if not get_online():
                        return None
                    return self._check_aur_packages(context, aur_helper)

                _add_task(
                    SystemCheckTask(
                        check_id="sys.aur",
                        label=f"AUR ({aur_helper})",
                        runner=run_aur,
                    )
                )

            if which_fn("flatpak") is not None:

                def run_flatpak() -> CheckResult | None:
                    if not get_online():
                        return None
                    return self._check_flatpak(context)

                _add_task(
                    SystemCheckTask(
                        check_id="sys.flatpak",
                        label="Flatpak packages",
                        runner=run_flatpak,
                    )
                )

            if which_fn("fwupdmgr") is not None:

                def run_firmware() -> CheckResult | None:
                    if not get_online():
                        return None
                    return self._check_firmware(context)

                _add_task(
                    SystemCheckTask(
                        check_id="sys.firmware",
                        label="Firmware updates",
                        runner=run_firmware,
                    )
                )

            omz_path = _resolve_oh_my_zsh_path(context)
            if omz_path is not None:

                def run_omz() -> CheckResult | None:
                    if not get_online():
                        return None
                    return self._check_oh_my_zsh(omz_path)

                _add_task(
                    SystemCheckTask(
                        check_id="sys.shell-omz",
                        label="Oh-My-Zsh updates",
                        runner=run_omz,
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

        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("pacman") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.orphans",
                    label="Orphan packages",
                    runner=lambda: self._check_orphans(context),
                )
            )

        if which_fn("pacman") is not None or which_fn("paccache") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.cache",
                    label="Pacman cache",
                    runner=lambda: self._check_pacman_cache(context),
                )
            )

        if which_fn("flatpak") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.flatpak-unused",
                    label="Unused Flatpaks",
                    runner=lambda: self._check_flatpak_unused(context),
                )
            )

        if which_fn("pacdiff") is not None or which_fn("pacman") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.pacnew",
                    label=".pacnew files",
                    runner=lambda: self._check_pacnew(context),
                )
            )

        if which_fn("systemctl") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.services",
                    label="Failed services",
                    runner=lambda: self._check_failed_services(context),
                )
            )

        if which_fn("journalctl") is not None:
            _add_task(
                SystemCheckTask(
                    check_id="sys.journal",
                    label="Journal disk usage",
                    runner=lambda: self._check_journal(context),
                )
            )

        maint_cls = getattr(su, "MaintenanceChecks", MaintenanceChecks)
        for cid, label, runner in maint_cls(self.config).registrations(context):
            if needs_network and cid in {"sys.news", "sys.security"}:
                base_runner = runner

                def make_net_maint(
                    check_id: str, fn: Callable[[], CheckResult]
                ) -> Callable[[], CheckResult]:
                    def net_maint_check() -> CheckResult:
                        if not get_online():
                            return CheckResult(
                                check_id=check_id,
                                severity=Severity.FAIL,
                                message="check blocked: internet access unavailable",
                                remediation="check connection, DNS and proxy settings, then retry",
                                details={"verified": False, "blocked_by": "sys.network"},
                            )
                        return fn()

                    return net_maint_check

                runner = make_net_maint(cid, base_runner)
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
            tasks,
            on_task_complete=on_task_complete,
            on_task_result=on_task_result,
            disabled_checks=disabled_checks,
            include_checks=include_checks,
        )
        return ScanReport(profile=context.profile, results=results)

    def _run_tasks(
        self,
        tasks: list[SystemCheckTask],
        on_task_complete: Callable[[str], None] | None,
        on_task_result: Callable[[str, CheckResult | None], None] | None = None,
        disabled_checks: set[str] | list[str] | None = None,
        include_checks: set[str] | list[str] | frozenset[str] | None = None,
    ) -> list[CheckResult]:
        self.last_timings = {}
        if not tasks:
            return []

        ordered_results: dict[str, CheckResult | None] = {}
        timings_lock = threading.Lock()
        session = AuditSession()
        pool = ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="dotdoctor-audit")

        def execute(task: SystemCheckTask) -> CheckResult | None:
            started = time.monotonic()
            with session.bind():
                try:
                    return task.runner()
                finally:
                    elapsed = time.monotonic() - started
                    with timings_lock:
                        self.last_timings[task.check_id] = elapsed

        interrupted = False
        try:
            futures: dict[Future[CheckResult | None], SystemCheckTask] = {
                pool.submit(execute, task): task for task in tasks
            }
            pending = set(futures.keys())
            try:
                wait_fn = getattr(su, "wait", wait)
                while pending:
                    done, pending = wait_fn(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                    for future in done:
                        task = futures[future]
                        try:
                            ordered_results[task.check_id] = future.result()
                        except Exception as exc:
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

        # Check if offline and sys.network should be injected into results
        get_online = getattr(self, "_current_get_online", None)
        needs_network = getattr(self, "_current_needs_network", False)
        if get_online is not None and needs_network and not get_online():
            disabled: set[str] = {*self.config.disabled_checks, *(disabled_checks or [])}
            env_disabled = os.environ.get("DOTDOCTOR_DISABLE_CHECKS", "")
            if env_disabled:
                disabled.update(item.strip() for item in env_disabled.split(",") if item.strip())
            is_net_disabled = "sys.network" in disabled or "sys:network" in disabled
            includes_set = set(include_checks) if include_checks is not None else None
            is_net_included = (
                includes_set is None
                or "sys.network" in includes_set
                or any(
                    c in includes_set
                    for c in {
                        "sys.packages",
                        "sys.aur",
                        "sys.flatpak",
                        "sys.firmware",
                        "sys.shell-omz",
                        "sys.news",
                        "sys.security",
                    }
                )
            )
            if not is_net_disabled and is_net_included and "sys.network" not in ordered_results:
                net_fail = CheckResult(
                    check_id="sys.network",
                    severity=Severity.FAIL,
                    message="internet access unavailable (HTTPS checks failed)",
                    remediation="check connection, DNS and proxy settings, then retry",
                )
                ordered_results["sys.network"] = net_fail
                if on_task_result is not None:
                    on_task_result("sys.network", net_fail)
                if on_task_complete is not None:
                    on_task_complete("sys.network")

        collected_results: list[CheckResult] = []
        if (
            "sys.network" in ordered_results
            and ordered_results["sys.network"] is not None
            and not any(t.check_id == "sys.network" for t in tasks)
        ):
            collected_results.append(ordered_results["sys.network"])

        for task in tasks:
            result = ordered_results.get(task.check_id)
            if result is not None:
                collected_results.append(result)
        return collected_results

    def _check_arch_packages(self, context: ScanContext) -> CheckResult:
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("checkupdates") is None:
            if which_fn("pacman") is None:
                return _unverified("sys.packages", "pacman not installed")
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN,
                message="checkupdates not installed",
                remediation="sudo pacman -S pacman-contrib",
            )

        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap(["checkupdates"], timeout=60)
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
            error_output = (
                getattr(completed, "stderr", "") or getattr(completed, "stdout", "") or ""
            ).strip()
            missing_fakeroot = "cannot find the fakeroot binary" in error_output.lower()
            is_locked = (
                "db.lck" in error_output.lower()
                or "unable to lock database" in error_output.lower()
            )
            if is_locked:
                msg = "pacman database is locked (/var/lib/pacman/db.lck)"
                remediation = "check running processes or remove /var/lib/pacman/db.lck"
            elif missing_fakeroot:
                msg = "checkupdates requires fakeroot; updates are not verified"
                remediation = "sudo pacman -Syu fakeroot"
            else:
                msg = f"checkupdates failed (exit={completed.returncode})"
                remediation = "checkupdates"

            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN if missing_fakeroot else Severity.FAIL,
                message=msg,
                remediation=remediation,
                details={
                    "verified": False,
                    "returncode": completed.returncode,
                    "items": error_output.splitlines() or ["command returned no error output"],
                },
            )

        if not lines:
            return _result_for_count("sys.packages", 0)

        pkg_entries: list[str] = []
        parse_line_fn = getattr(su, "parse_package_update_line", parse_package_update_line)
        for line in lines:
            parsed = parse_line_fn(line)
            if parsed:
                pkg_name, old_v, new_v = parsed
                pkg_entries.append(f"{pkg_name} {old_v} -> {new_v}")
            else:
                pkg_entries.append(line)

        count = len(lines)
        noun = "update" if count == 1 else "updates"

        return CheckResult(
            check_id="sys.packages",
            severity=Severity.OUTD,
            message=f"{count} {noun} available",
            remediation="dotdoctor --sysup",
            details={
                "updates": count,
                "packages": pkg_entries,
            },
        )

    def _check_flatpak(self, context: ScanContext) -> CheckResult:
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("flatpak") is None:
            return _unverified("sys.flatpak", "flatpak not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap(["flatpak", "remote-ls", "--updates"], timeout=60)
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
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("fwupdmgr") is None:
            return _unverified("sys.firmware", "fwupd not installed")

        # Read-only audit executes get-updates without mutating metadata refresh
        run_cap = getattr(su, "_run_capture", _run_capture)
        updates_result = run_cap(["fwupdmgr", "get-updates"], timeout=90)
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

        parse_fwupd_fn = getattr(su, "_parse_fwupdmgr_updates", _parse_fwupdmgr_updates)
        update_count = parse_fwupd_fn(completed.stdout)
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
        if os.geteuid() == 0:
            return CheckResult(
                check_id="sys.shell-omz",
                severity=Severity.SKIP,
                message="skipped when running as root",
                remediation=None,
                details={"updates": 0},
            )
        detect_omz_fn = getattr(su, "_detect_oh_my_zsh_updates", _detect_oh_my_zsh_updates)
        update_count = detect_omz_fn(omz_path)
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
        extra_pkgs = getattr(self.config.maintenance, "extra_reboot_packages", [])
        detect_reboot_fn = getattr(su, "detect_reboot_status", detect_reboot_status)
        try:
            status = (
                detect_reboot_fn(extra_critical_packages=extra_pkgs)
                if extra_pkgs
                else detect_reboot_fn()
            )
        except TypeError:
            status = detect_reboot_fn()
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
                    "packages": status.packages,
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
                "packages": [],
            },
        )

    def _check_disk_space(self, context: ScanContext) -> CheckResult:
        detect_disk_fn = getattr(su, "detect_disk_space_status", detect_disk_space_status)
        status = detect_disk_fn()
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
        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap([aur_helper, "-Qua"], timeout=60)
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
                details={"updates": 0, "flagged": 0, "packages": []},
            )

        aur_entries: list[str] = []
        parse_line_fn = getattr(su, "parse_package_update_line", parse_package_update_line)
        for line in lines:
            parts = line.split()
            pkg_name = parts[0]
            if pkg_name.startswith("aur/"):
                pkg_name = pkg_name[4:]
            parsed = parse_line_fn(line)
            if parsed:
                _, old_v, new_v = parsed
                aur_entries.append(f"{pkg_name} {old_v} -> {new_v}")
            else:
                aur_entries.append(line)

        count = len(lines)
        noun = "update" if count == 1 else "updates"
        if flagged:
            msg = f"{count} AUR {noun} available ({len(flagged)} flagged out-of-date)"
        else:
            msg = f"{len(regular)} AUR {noun} available"

        return CheckResult(
            check_id="sys.aur",
            severity=Severity.OUTD,
            message=msg,
            remediation="dotdoctor --sysup",
            details={
                "updates": len(regular),
                "flagged": len(flagged),
                "packages": aur_entries,
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

        format_bytes_fn = getattr(su, "_format_bytes", _format_bytes)
        total_str = format_bytes_fn(total_bytes)
        candidates = 0
        saved_str = ""

        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("paccache") is not None:
            run_cap = getattr(su, "_run_capture", _run_capture)
            res = run_cap(["paccache", "-d"], timeout=20)
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
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("pacman") is None:
            return _unverified("sys.orphans", "pacman not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap(["pacman", "-Qtdq"], timeout=15)
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
        detect_pacnew_fn = getattr(su, "detect_pacnew_files", detect_pacnew_files)
        files = detect_pacnew_fn()
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
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("systemctl") is None:
            return _unverified("sys.services", "systemctl not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        failed_units: list[str] = []
        unavailable: list[str] = []
        sys_res = run_cap(
            ["systemctl", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if sys_res.completed and sys_res.completed.returncode == 0:
            for line in sys_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    unit = parts[1] if parts[0] in {"●", "*", "x"} and len(parts) > 1 else parts[0]
                    failed_units.append(unit)
        else:
            unavailable.append("system")

        user_res = run_cap(
            ["systemctl", "--user", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if user_res.completed and user_res.completed.returncode == 0:
            for line in user_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    unit = parts[1] if parts[0] in {"●", "*", "x"} and len(parts) > 1 else parts[0]
                    failed_units.append(f"{unit} (user)")
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
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("flatpak") is None:
            return _unverified("sys.flatpak-unused", "flatpak not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        res = run_cap(
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
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("journalctl") is None:
            return _unverified("sys.journal", "journalctl not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        res = run_cap(["journalctl", "--disk-usage"], timeout=10)
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
                size_bytes_int = round(size_bytes)
                format_bytes_fn = getattr(su, "_format_bytes", _format_bytes)
                formatted_size = format_bytes_fn(size_bytes_int)
                is_large = size_bytes >= 4 * 1024**3

                return CheckResult(
                    check_id="sys.journal",
                    severity=Severity.WARN if is_large else Severity.PASS,
                    message=f"{formatted_size} in journal logs",
                    remediation="sudo journalctl --vacuum-size=1G" if is_large else None,
                    details={
                        "disk_usage": formatted_size,
                        "disk_usage_bytes": size_bytes_int,
                    },
                )

        return _unverified(
            "sys.journal", "journal size could not be verified", "journalctl --disk-usage"
        )


__all__ = [
    "ALL_CHECK_IDS",
    "FIX_CHECK_IDS",
    "HTTPS_TARGETS",
    "UPDATE_CHECK_IDS",
    "SystemCheckTask",
    "SystemDryRunService",
    "_ExecResult",
    "_detect_oh_my_zsh_updates",
    "_resolve_oh_my_zsh_path",
    "_result_for_count",
    "_run_capture",
    "_unverified",
    "detect_aur_helper",
    "detect_pacnew_files",
    "is_online",
]
