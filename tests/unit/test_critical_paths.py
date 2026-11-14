"""High-value unit and edge-case tests for critical system diagnostic paths."""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from dotdoctor.application.auto_fix import (
    InteractiveAutoFixer,
    OrphanRemovalPlan,
    RemovalPackage,
)
from dotdoctor.application.maintenance import MaintenanceChecks
from dotdoctor.application.system_update import (
    DiskSpaceStatus,
    SystemDryRunService,
    SystemUpgradeService,
)
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity
from dotdoctor.infrastructure.audit_processes import AuditCancelled, AuditSession


@pytest.fixture
def test_context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        profile="system",
        cwd=tmp_path,
        home=tmp_path / "home",
        path_value=os.environ.get("PATH", ""),
        shell="/bin/bash",
    )


def test_package_database_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test 1a: package_database reports PASS when pacman -Dk succeeds."""
    monkeypatch.setattr(
        "dotdoctor.application.maintenance.capture",
        lambda cmd, timeout: subprocess.CompletedProcess(cmd, 0, "database consistent\n", ""),
    )
    checks = MaintenanceChecks(DotDoctorConfig())
    result = checks.package_database()
    assert result.check_id == "sys.package-db"
    assert result.severity == Severity.PASS
    assert "consistent" in result.message


def test_package_database_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test 1b: package_database reports FAIL and blocks upgrade when pacman -Dk fails."""
    monkeypatch.setattr(
        "dotdoctor.application.maintenance.capture",
        lambda cmd, timeout: subprocess.CompletedProcess(
            cmd, 1, "", "error: missing dependency 'libfoo' for 'bar'\n"
        ),
    )
    checks = MaintenanceChecks(DotDoctorConfig())
    result = checks.package_database()
    assert result.check_id == "sys.package-db"
    assert result.severity == Severity.FAIL
    assert result.details.get("blocks_upgrade") is True
    assert "inconsistent" in result.message
    assert any("libfoo" in item for item in result.details.get("items", []))


def test_sysup_aborts_on_snapshot_failure(test_context: ScanContext) -> None:
    """Test 2: System update workflow aborts immediately if snapshot creation fails."""
    console = Console(record=True)
    workflow = SystemUpgradeService(
        is_online_fn=lambda: True,
        snapshot_tool_fn=lambda: "snapper",
        config=DotDoctorConfig(),
    )

    with patch("os.geteuid", return_value=0):
        with patch("dotdoctor.application.system_update.detect_disk_space_status") as mock_disk:
            mock_disk.return_value = DiskSpaceStatus(
                root_free_bytes=10000000000,
                boot_free_bytes=1000000000,
                severity=Severity.PASS,
                message="enough space",
                remediation=None,
            )

            workflow._run_step = MagicMock(return_value=(True, "fail", False))
            workflow._refresh_mirrors = MagicMock()

            code = workflow.run(test_context, console)
            assert code == 2
            workflow._refresh_mirrors.assert_not_called()
            output = console.export_text()
            assert "Update aborted: pre-update snapshot failed" in output


def test_pacman_db_lock_detection(
    test_context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 3: checkupdates failure due to db.lck provides specific lock diagnostic."""
    service = SystemDryRunService(DotDoctorConfig())

    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/checkupdates")
    error_output = (
        "error: failed to init transaction (unable to lock database)\n"
        "error: could not lock database: File exists\n"
        "  if you're sure a package manager is not already\n"
        "  running, you can remove /var/lib/pacman/db.lck\n"
    )

    fake_completed = subprocess.CompletedProcess(
        ["checkupdates"],
        returncode=1,
        stdout="",
        stderr=error_output,
    )
    fake_run_capture = MagicMock(completed=fake_completed, timed_out=False)
    monkeypatch.setattr(
        "dotdoctor.application.system_update._run_capture", lambda *a, **kw: fake_run_capture
    )

    result = service._check_arch_packages(test_context)
    assert result.check_id == "sys.packages"
    assert result.severity == Severity.FAIL
    assert "database is locked" in result.message
    assert result.remediation is not None and "db.lck" in result.remediation


def test_sysup_partial_failure_exit_code(test_context: ScanContext) -> None:
    """Test 4: System update workflow returns error exit code 2 when any step fails."""
    console = Console(record=True)
    workflow = SystemUpgradeService(
        is_online_fn=lambda: True,
        snapshot_tool_fn=lambda: None,
        config=DotDoctorConfig(),
    )

    workflow._refresh_mirrors = MagicMock(return_value=(False, "done"))
    workflow._prepare_keyring = MagicMock(return_value=True)

    def mock_run_step(cmd, c, label):
        if "flatpak" in cmd:
            return True, "fail", False  # flatpak fails
        return False, "done", True

    workflow._run_step = mock_run_step

    with patch("os.geteuid", return_value=0):
        with patch("dotdoctor.application.system_update.detect_disk_space_status") as mock_disk:
            mock_disk.return_value = DiskSpaceStatus(
                root_free_bytes=10000000000,
                boot_free_bytes=1000000000,
                severity=Severity.PASS,
                message="enough space",
                remediation=None,
            )

            valid_managers = {"pacman", "flatpak"}
            with patch(
                "shutil.which",
                lambda name: "/usr/bin/" + name if name in valid_managers else None,
            ):
                with patch(
                    "dotdoctor.application.system_update.detect_pacnew_files", return_value=[]
                ):
                    with patch(
                        "dotdoctor.application.system_update.MaintenanceChecks.run",
                        return_value=[],
                    ):
                        code = workflow.run(test_context, console)

    assert code == 2


def test_audit_session_cancellation_terminates_process() -> None:
    """Test 5: AuditSession cancel() immediately interrupts running process group."""
    session = AuditSession()
    caught_cancelled = threading.Event()

    def run_worker():
        with session.bind():
            try:
                session.capture([sys.executable, "-c", "import time; time.sleep(10)"], timeout=5)
            except AuditCancelled:
                caught_cancelled.set()

    t = threading.Thread(target=run_worker)
    t.start()

    time.sleep(0.2)  # Allow process to start
    session.cancel()
    t.join(timeout=2.0)

    assert not t.is_alive(), "Worker thread did not terminate"
    assert caught_cancelled.is_set(), "AuditCancelled was not raised"


def test_auto_fix_handles_eof_on_prompt(
    test_context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 6: InteractiveAutoFixer does not crash on EOF (Ctrl+D) during orphan confirmation."""
    service = InteractiveAutoFixer(DotDoctorConfig())
    console = Console(record=True)
    service._console = console

    mock_plan = OrphanRemovalPlan(
        targets=("orphan-pkg",),
        packages=(RemovalPackage(name="orphan-pkg", version="1.0.0", size=1024),),
    )
    monkeypatch.setattr(service, "_read_orphan_plan", lambda: mock_plan)

    def mock_confirm(*args, **kwargs):
        raise EOFError("Unexpected EOF on stdin")

    monkeypatch.setattr("typer.confirm", mock_confirm)

    check_res = CheckResult(
        check_id="sys.orphans",
        severity=Severity.WARN,
        message="1 orphan package found",
    )
    outcome = service._fix_sys_orphans(test_context, check_res)
    assert outcome.changed is False
    assert "Removal declined" in outcome.note


def test_failed_services_strips_systemd_bullets(
    test_context: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 7: _check_failed_services parses unit names even with bullet prefix and non-ASCII."""
    service = SystemDryRunService(DotDoctorConfig())

    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/systemctl")

    sys_stdout = "● broken-system.service loaded failed failed Описание сервиса\n"
    user_stdout = "● broken-user.service loaded failed failed User Service\n"

    def mock_run_capture(cmd, timeout=10):
        if "--user" in cmd:
            return MagicMock(completed=subprocess.CompletedProcess(cmd, 0, user_stdout, ""))
        return MagicMock(completed=subprocess.CompletedProcess(cmd, 0, sys_stdout, ""))

    monkeypatch.setattr("dotdoctor.application.system_update._run_capture", mock_run_capture)

    result = service._check_failed_services(test_context)
    assert result.check_id == "sys.services"
    assert result.severity == Severity.FAIL
    assert "broken-system.service" in result.details.get("failed_units", [])
    assert "broken-user.service (user)" in result.details.get("failed_units", [])
    assert "broken-system.service" in result.remediation


def test_news_worker_handles_failure() -> None:
    """Test 8: news_worker.py produces empty JSON [] and exits non-zero on network exception."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    src_dir = repo_root / "src"

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{src_dir}{os.pathsep}{env.get('PYTHONPATH', '')}"

    py_cmd = (
        "import runpy; from dotdoctor.infrastructure import maintenance; "
        "maintenance.NEWS_URL = 'http://127.0.0.1:9999/invalid'; "
        "runpy.run_module('dotdoctor.infrastructure.news_worker', run_name='__main__')"
    )
    result = subprocess.run(
        [sys.executable, "-c", py_cmd],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert "[]" in result.stdout
    assert result.returncode == 1
