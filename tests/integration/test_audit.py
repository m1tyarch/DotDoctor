"""Audit regressions; real processes are harmless Python helpers, never system tools."""

import io
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

from dotdoctor.application import maintenance as m
from dotdoctor.application import system_update as s
from dotdoctor.cli.app import _run_tasks_with_progress, app
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity
from dotdoctor.infrastructure import audit_processes as processes
from dotdoctor.infrastructure import maintenance as readers


@pytest.fixture
def context(tmp_path):
    return ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")


def completed(stdout="", returncode=0, stderr=""):
    return s._ExecResult(SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode))


@pytest.mark.parametrize(
    "installed_kernel,expected", [("test-running", Severity.PASS), ("test-new", Severity.WARN)]
)
def test_kernel_journal_removed_but_reboot_detection_needs_no_sudo(
    monkeypatch, context, tmp_path, installed_kernel, expected
):
    modules = tmp_path / "modules"
    (modules / installed_kernel).mkdir(parents=True)
    detect = s.detect_reboot_status
    monkeypatch.setattr(
        s,
        "detect_reboot_status",
        lambda: detect(modules, running_kernel="test-running", marker_paths=()),
    )
    monkeypatch.setattr(
        s.shutil, "which", lambda name: "/bin/journalctl" if name == "journalctl" else None
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Kernel checks must not invoke a command or sudo")

    monkeypatch.setattr(s, "_run_capture", forbidden)
    monkeypatch.setattr(m, "capture", forbidden)
    report = s.SystemDryRunService(is_online_fn=lambda: False).run(
        context, include_checks={"sys.kernel-errors", "sys.reboot"}
    )
    assert [result.check_id for result in report.results] == ["sys.reboot"]
    assert report.results[0].severity == expected


@pytest.mark.parametrize(
    "checker,cid",
    [
        ("_check_aur_packages", "sys.aur"),
        ("_check_failed_services", "sys.services"),
        ("_check_flatpak_unused", "sys.flatpak-unused"),
        ("_check_journal", "sys.journal"),
    ],
)
@pytest.mark.parametrize(
    "result",
    [completed(returncode=1, stderr="unavailable"), s._ExecResult(None), s._ExecResult(None, True)],
)
def test_failed_command_never_becomes_pass(monkeypatch, context, checker, cid, result):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(s, "_run_capture", lambda *args, **kwargs: result)
    finding = getattr(s.SystemDryRunService(), checker)(context)
    assert finding.check_id == cid
    assert finding.severity in {Severity.WARN, Severity.FAIL}


@pytest.mark.parametrize("unavailable", ["system", "user", "both"])
def test_service_manager_partial_access_is_not_clean(monkeypatch, context, unavailable):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")

    def capture(cmd, **kwargs):
        scope = "user" if "--user" in cmd else "system"
        return completed(returncode=int(unavailable in {scope, "both"}))

    monkeypatch.setattr(s, "_run_capture", capture)
    result = s.SystemDryRunService()._check_failed_services(context)
    assert result.severity == Severity.WARN
    assert result.details["verified"] is False


def test_known_service_failure_survives_partial_access(monkeypatch, context):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        s,
        "_run_capture",
        lambda cmd, **kwargs: (
            completed(returncode=1)
            if "--user" in cmd
            else completed("broken.service loaded failed failed Job\n")
        ),
    )
    result = s.SystemDryRunService()._check_failed_services(context)
    assert result.severity == Severity.FAIL
    assert result.details["failed_units"] == ["broken.service"]
    assert result.details["unavailable_scopes"] == ["user"]


@pytest.mark.parametrize("size", ["6.2G", "6.2GiB", "6.2GB", "1T"])
def test_large_journal_units_are_recognized(monkeypatch, context, size):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        s,
        "_run_capture",
        lambda *args, **kwargs: completed(
            f"Archived and active journals take up {size} in the file system."
        ),
    )
    assert s.SystemDryRunService()._check_journal(context).severity == Severity.WARN


def test_unrecognized_journal_output_is_not_clean(monkeypatch, context):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(s, "_run_capture", lambda *args, **kwargs: completed("unexpected output"))
    assert s.SystemDryRunService()._check_journal(context).details["verified"] is False


@pytest.mark.parametrize("failure", ["fetch", "count", "format"])
def test_omz_failure_does_not_look_up_to_date(monkeypatch, tmp_path, failure):
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")

    def capture(cmd, **kwargs):
        if "fetch" in cmd:
            return completed(returncode=int(failure == "fetch"))
        return completed("bad" if failure == "format" else "0", int(failure == "count"))

    monkeypatch.setattr(s, "_run_capture", capture)
    assert s.SystemDryRunService()._check_oh_my_zsh(str(tmp_path)).severity == Severity.WARN


@pytest.mark.parametrize(
    "checker",
    [
        "_check_arch_packages",
        "_check_flatpak",
        "_check_firmware",
        "_check_orphans",
        "_check_failed_services",
        "_check_journal",
        "_check_flatpak_unused",
    ],
)
def test_missing_checker_is_not_a_health_pass(monkeypatch, context, checker):
    monkeypatch.setattr(s.shutil, "which", lambda name: None)
    assert getattr(s.SystemDryRunService(), checker)(context).details["verified"] is False


@pytest.mark.parametrize("is_terminal", [False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_ui_executes_the_exact_prepared_plan(monkeypatch, context, is_terminal, empty):
    service = s.SystemDryRunService()
    calls = []
    task = s.SystemCheckTask(
        "test",
        "Test",
        lambda: (
            calls.append("executed")
            or CheckResult(check_id="test", severity=Severity.PASS, message="ok")
        ),
    )
    tasks = [] if empty else [task]

    def forbidden(*args, **kwargs):
        raise AssertionError("Prepared tasks must not be rebuilt")

    monkeypatch.setattr(service, "build_tasks", forbidden)
    console = Console(file=io.StringIO(), force_terminal=is_terminal)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("NO_ANIMATION", raising=False)
    monkeypatch.delenv("DOTDOCTOR_NO_ANIMATION", raising=False)
    report = _run_tasks_with_progress(service, context, tasks, [], None, console)
    assert calls == ([] if empty else ["executed"])
    assert len(report.results) == len(tasks)


@pytest.mark.parametrize("args", [[], ["--fix"], ["--sysup"]])
def test_cli_builds_one_plan_per_initial_scan(monkeypatch, args):
    calls = []
    monkeypatch.setattr(
        s.SystemDryRunService, "build_tasks", lambda *a, **kw: calls.append("built") or []
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0
    assert calls == ["built"]


def test_internal_type_error_does_not_retry_the_audit(monkeypatch, context):
    calls = []

    def fail(*args, **kwargs):
        calls.append(True)
        raise TypeError("reader bug")

    service = s.SystemDryRunService()
    monkeypatch.setattr(service, "run_with_progress", fail)
    with pytest.raises(TypeError, match="reader bug"):
        service.run(context)
    assert calls == [True]


def test_successful_capture_preserves_input_output_and_status():
    session = processes.AuditSession()
    with session.bind():
        result = processes.capture(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.stdin.read()); print('err', file=sys.stderr)",
            ],
            2,
            "answer",
        )
    assert result.returncode == 0
    assert result.stdout == "answer\n"
    assert result.stderr == "err\n"


def test_capture_timeout_terminates_the_process_group(tmp_path):
    pid_file = tmp_path / "pid"
    code = "import os,time,pathlib; pathlib.Path({!r}).write_text(str(os.getpid())); time.sleep(60)"
    session = processes.AuditSession()
    with session.bind(), pytest.raises(subprocess.TimeoutExpired):
        processes.capture([sys.executable, "-c", code.format(str(pid_file))], 0.3)
    assert not Path(f"/proc/{pid_file.read_text()}").exists()


def wait_for(path, timeout=3):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError("Helper failed to start")
        time.sleep(0.01)


def running(pid):
    try:
        # An orphan zombie has exited; it cannot keep executing or hold descriptors.
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.parametrize("ignore_parent", [False, True])
def test_interrupt_stops_readers_and_term_resistant_descendants(
    monkeypatch, context, tmp_path, ignore_parent
):
    pid_file = tmp_path / "pids"
    child_ready = tmp_path / "child-ready"
    child = (
        "import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(child_ready)!r}).touch(); time.sleep(60)"
    )
    code = (
        "import os,subprocess,sys,time,pathlib,signal; "
        f"signal.signal(signal.SIGTERM, signal.{'SIG_IGN' if ignore_parent else 'SIG_DFL'}); "
        f"p=subprocess.Popen([sys.executable, '-c', {child!r}])\n"
        f"while not pathlib.Path({str(child_ready)!r}).exists(): time.sleep(0.01)\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())+' '+str(p.pid))\n"
        "time.sleep(60)"
    )
    task = s.SystemCheckTask(
        "slow", "Slow reader", lambda: readers.capture([sys.executable, "-c", code], 60)
    )

    def interrupt(*args, **kwargs):
        wait_for(pid_file)
        raise KeyboardInterrupt()

    monkeypatch.setattr(s, "wait", interrupt)
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        s.SystemDryRunService().run_with_progress(context, tasks=[task])
    pids = [int(pid) for pid in pid_file.read_text().split()]
    deadline = time.monotonic() + 2
    while any(running(pid) for pid in pids) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert all(not running(pid) for pid in pids)
    assert time.monotonic() - started < 3
    assert processes.current_session() is None


def test_cancelled_session_cannot_start_more_commands(tmp_path):
    session = processes.AuditSession()
    session.cancel()
    marker = tmp_path / "must-not-exist"
    with pytest.raises(processes.AuditCancelled):
        session.capture([sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"], 2)
    assert not marker.exists()


def test_http_reader_is_isolated_during_audit(monkeypatch):
    calls = []

    def capture(cmd, timeout):
        calls.append(cmd)
        return SimpleNamespace(
            returncode=0, stdout='[{"title":"Notice","url":"https://archlinux.org/news/notice/"}]'
        )

    monkeypatch.setattr(readers, "capture", capture)
    with processes.AuditSession().bind():
        assert readers.fetch_news()[0]["title"] == "Notice"
    assert calls == [[sys.executable, "-m", "dotdoctor.infrastructure.news_worker"]]


def test_real_sigint_exits_130_and_reaps_audit_reader(tmp_path):
    pid_file = tmp_path / "reader.pid"
    reader_code = (
        f"import os,pathlib,time; pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
        "time.sleep(60)"
    )
    code = (
        "from dotdoctor.application.system_update import SystemDryRunService,SystemCheckTask; "
        "from dotdoctor.infrastructure.maintenance import capture; "
        "from dotdoctor.main import run; import sys; "
        "SystemDryRunService.build_tasks=lambda *a,**kw: "
        "[SystemCheckTask('slow','Slow reader',"
        f"lambda: capture([sys.executable,'-c',{reader_code!r}],60))]; "
        "run()"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "NO_ANIMATION": "1"},
    )
    try:
        wait_for(pid_file)
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=3)
        assert process.returncode == 130
        assert "Traceback" not in stderr
        assert "DotDoctor" in stdout
        assert not running(int(pid_file.read_text()))
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
        if pid_file.exists() and running(int(pid_file.read_text())):
            os.killpg(int(pid_file.read_text()), signal.SIGKILL)


def test_failed_firmware_refresh_does_not_use_stale_metadata(monkeypatch, context):
    commands = []
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")

    def capture(cmd, **kwargs):
        commands.append(cmd)
        return completed(returncode=1)

    monkeypatch.setattr(s, "_run_capture", capture)
    result = s.SystemDryRunService()._check_firmware(context)
    assert result.severity == Severity.WARN
    assert commands == [["fwupdmgr", "refresh"]]


@pytest.mark.parametrize(
    "result", [completed("unexpected output"), completed(returncode=1), s._ExecResult(None, True)]
)
def test_unknown_cache_cleanup_candidates_are_not_clean(monkeypatch, context, tmp_path, result):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(s, "_run_capture", lambda *args, **kwargs: result)
    finding = s.SystemDryRunService()._check_pacman_cache(context, tmp_path)
    assert finding.severity == Severity.WARN
    assert finding.details["verified"] is False


@pytest.mark.parametrize(
    "result,expected",
    [
        (completed(returncode=1), Severity.PASS),
        (completed(returncode=1, stderr="could not open database"), Severity.WARN),
    ],
)
def test_orphan_empty_selection_differs_from_query_error(monkeypatch, context, result, expected):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(s, "_run_capture", lambda *args, **kwargs: result)
    assert s.SystemDryRunService()._check_orphans(context).severity == expected


def test_disabled_network_checks_do_not_probe_internet(monkeypatch, context):
    ids = [
        "sys.packages",
        "sys.aur",
        "sys.flatpak",
        "sys.firmware",
        "sys.shell-omz",
        "sys.news",
        "sys.security",
    ]
    from dotdoctor.domain.config import DotDoctorConfig

    def forbidden():
        raise AssertionError("Disabled network checks must not trigger a probe")

    service = s.SystemDryRunService(
        config=DotDoctorConfig(disabled_checks=ids),
        is_online_fn=forbidden,
        aur_helper_fn=lambda: None,
    )
    tasks = service.build_tasks(context)
    assert not {task.check_id for task in tasks}.intersection(ids)


@pytest.mark.parametrize(
    "checker,output",
    [
        ("_check_firmware", "unexpected firmware output"),
        ("_check_flatpak_unused", "unexpected runtime output"),
    ],
)
def test_unrecognized_success_output_does_not_pass(monkeypatch, context, checker, output):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(s, "_run_capture", lambda *args, **kwargs: completed(output))
    result = getattr(s.SystemDryRunService(), checker)(context)
    assert result.severity == Severity.WARN
    assert result.details["verified"] is False


def test_upgrade_readers_use_the_existing_unscoped_execution(monkeypatch):
    options = []
    monkeypatch.setattr(
        processes.subprocess,
        "run",
        lambda command, **kwargs: options.append(kwargs) or SimpleNamespace(returncode=0),
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("No audit process may be launched outside its session")

    monkeypatch.setattr(processes.subprocess, "Popen", forbidden)
    processes.capture(["mock-reader"], 2)
    assert len(options) == 1
    assert "start_new_session" not in options[0]


def test_unverified_update_scan_does_not_claim_everything_is_current(monkeypatch):
    task = s.SystemCheckTask(
        "sys.aur",
        "AUR",
        lambda: CheckResult(
            check_id="sys.aur",
            severity=Severity.WARN,
            message="AUR unavailable",
            details={"verified": False},
        ),
    )
    monkeypatch.setattr(s.SystemDryRunService, "build_tasks", lambda *a, **kw: [task])
    result = CliRunner().invoke(app, ["--sysup"])
    assert result.exit_code == 0
    assert "AUR unavailable" in result.stdout
    assert "up to date" not in result.stdout
    assert "No updates reported; review" in result.stdout


def test_inaccessible_boot_space_does_not_borrow_root_capacity(monkeypatch, tmp_path):
    (tmp_path / "boot").mkdir()

    def usage(path):
        if path == tmp_path:
            return SimpleNamespace(free=100 * 1024**3)
        raise PermissionError("boot unavailable")

    monkeypatch.setattr(s.shutil, "disk_usage", usage)
    with pytest.raises(OSError, match="could not be verified"):
        s.detect_disk_space_status(root_path=tmp_path, boot_path=tmp_path / "boot")


def test_inaccessible_configuration_tree_is_not_clean(monkeypatch, context):
    monkeypatch.setattr(s.shutil, "which", lambda name: None)

    def walk(path, onerror):
        onerror(PermissionError("configuration directory unavailable"))

    monkeypatch.setattr(s.os, "walk", walk)
    service = s.SystemDryRunService()
    task = s.SystemCheckTask("sys.pacnew", "Config", lambda: service._check_pacnew(context))
    report = service.run_with_progress(context, tasks=[task])
    assert report.results[0].severity == Severity.WARN
    assert report.results[0].details["verified"] is False


def test_unknown_disk_capacity_blocks_upgrade_before_any_commands(monkeypatch, context):
    def unavailable():
        raise OSError("boot capacity unavailable")

    monkeypatch.setattr(s, "detect_disk_space_status", unavailable)

    def forbidden(*args, **kwargs):
        raise AssertionError("An unverified disk must block the transaction")

    monkeypatch.setattr(s.subprocess, "run", forbidden)
    assert (
        s.SystemUpgradeService(is_online_fn=lambda: True).run(context, Console(file=io.StringIO()))
        == 2
    )


@pytest.mark.parametrize("helper", ["yay", "paru"])
@pytest.mark.parametrize("stdout,stderr", [("", ""), (" \n", "\t\n")])
def test_aur_exit_one_with_empty_output_means_no_updates(
    monkeypatch, context, helper, stdout, stderr
):
    monkeypatch.setattr(s, "_run_capture", lambda *args, **kwargs: completed(stdout, 1, stderr))
    result = s.SystemDryRunService()._check_aur_packages(context, helper)
    assert result.severity == Severity.PASS
    assert result.details["updates"] == 0
    assert result.details["packages"] == []


@pytest.mark.parametrize(
    "returncode,stdout,stderr",
    [
        (1, "", "AUR RPC request failed"),
        (1, "database unavailable", ""),
        (1, "aur/package 1 -> 2", "AUR request incomplete"),
        (2, "", ""),
        (-15, "", ""),
    ],
)
def test_aur_nonempty_errors_and_other_exit_codes_remain_unverified(
    monkeypatch, context, returncode, stdout, stderr
):
    monkeypatch.setattr(
        s, "_run_capture", lambda *args, **kwargs: completed(stdout, returncode, stderr)
    )
    result = s.SystemDryRunService()._check_aur_packages(context)
    assert result.severity == Severity.WARN
    assert result.details["verified"] is False


@pytest.mark.parametrize("refresh_stream", ["stdout", "stderr"])
@pytest.mark.parametrize(
    "updates,expected",
    [
        (completed(returncode=2), Severity.PASS),
        (completed("1.2.3 -> 1.2.4\n"), Severity.OUTD),
        (completed(returncode=1, stderr="could not contact daemon"), Severity.WARN),
    ],
)
def test_fresh_firmware_metadata_still_queries_updates(
    monkeypatch, context, refresh_stream, updates, expected
):
    commands = []
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    fresh = {refresh_stream: "Metadata is up to date; use --force to refresh again"}

    def capture(cmd, **kwargs):
        commands.append(cmd)
        return completed(returncode=2, **fresh) if cmd[1] == "refresh" else updates

    monkeypatch.setattr(s, "_run_capture", capture)
    result = s.SystemDryRunService()._check_firmware(context)
    assert result.severity == expected
    assert commands == [["fwupdmgr", "refresh"], ["fwupdmgr", "get-updates"]]
    assert all("--force" not in cmd for cmd in commands)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize(
    "message",
    [
        "==> no candidate packages found for pruning\n",
        "no candidate packages found for pruning\n",
    ],
)
def test_paccache_no_candidates_is_a_clean_result(monkeypatch, context, tmp_path, stream, message):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(s, "_run_capture", lambda *args, **kwargs: completed(**{stream: message}))
    result = s.SystemDryRunService()._check_pacman_cache(context, tmp_path)
    assert result.severity == Severity.PASS
    assert result.details["candidates"] == 0


def test_no_candidates_message_cannot_mask_failed_paccache(monkeypatch, context, tmp_path):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        s,
        "_run_capture",
        lambda *args, **kwargs: completed(
            "==> no candidate packages found for pruning\n", 1, "cache inaccessible"
        ),
    )
    result = s.SystemDryRunService()._check_pacman_cache(context, tmp_path)
    assert result.severity == Severity.WARN
    assert result.details["verified"] is False


def test_normal_empty_results_pass_together_in_parallel_audit(monkeypatch, context, tmp_path):
    available = {"pacman", "yay", "paccache", "fwupdmgr"}
    monkeypatch.setattr(
        s.shutil, "which", lambda name: f"/bin/{name}" if name in available else None
    )

    def capture(cmd, **kwargs):
        if cmd == ["yay", "-Qua"]:
            return completed(returncode=1)
        if cmd == ["fwupdmgr", "refresh"]:
            return completed(
                returncode=2, stderr="Metadata is up to date; use --force to refresh again"
            )
        if cmd == ["fwupdmgr", "get-updates"]:
            return completed(returncode=2)
        if cmd == ["paccache", "-d"]:
            return completed("==> no candidate packages found for pruning\n")
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(s, "_run_capture", capture)
    service = s.SystemDryRunService(is_online_fn=lambda: True, aur_helper_fn=lambda: "yay")
    cache_check = service._check_pacman_cache
    monkeypatch.setattr(service, "_check_pacman_cache", lambda ctx: cache_check(ctx, tmp_path))
    ids = frozenset({"sys.aur", "sys.firmware", "sys.cache"})
    report = service.run(context, include_checks=ids)
    assert {result.check_id for result in report.results} == ids
    assert all(result.severity == Severity.PASS for result in report.results)
