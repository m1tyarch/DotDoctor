"""System audit task planning and parallel execution orchestrator."""

from __future__ import annotations

import os
import shutil
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass

import dotdoctor.application.system_update as su
from dotdoctor.application.check_common import (
    ALL_CHECK_IDS,
    CATEGORY_ALIASES,
    CHECK_CATEGORIES,
    FIX_CHECK_IDS,
    UPDATE_CHECK_IDS,
    _detect_oh_my_zsh_updates,
    _ExecResult,
    _resolve_oh_my_zsh_path,
    _result_for_count,
    _run_capture,
    _unverified,
    detect_aur_helper,
    detect_pacnew_files,
    is_online,
    resolve_category_checks,
)
from dotdoctor.application.check_mixins import (
    HygieneChecksMixin,
    RuntimeChecksMixin,
    UpdatesChecksMixin,
)
from dotdoctor.application.maintenance import MaintenanceChecks
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure.audit_processes import AuditCancelled, AuditSession
from dotdoctor.infrastructure.network_worker import HTTPS_TARGETS


@dataclass(frozen=True)
class SystemCheckTask:
    check_id: str
    label: str
    runner: Callable[[], CheckResult | None]


class SystemDryRunService(UpdatesChecksMixin, HygieneChecksMixin, RuntimeChecksMixin):
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


__all__ = [
    "ALL_CHECK_IDS",
    "CATEGORY_ALIASES",
    "CHECK_CATEGORIES",
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
    "resolve_category_checks",
]
