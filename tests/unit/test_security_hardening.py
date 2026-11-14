import os
import subprocess
import sys
from pathlib import Path

import pytest
from rich.console import Console

from dotdoctor.application.system_update import SystemDryRunService, SystemUpgradeService
from dotdoctor.cli.app import _export_json_report
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure.maintenance import MaintenanceState


def test_json_output_symlink_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("critical data", encoding="utf-8")
    symlink_file = tmp_path / "link.json"
    symlink_file.symlink_to(target)

    report = ScanReport(
        profile="system",
        results=[CheckResult(check_id="sys.test", severity=Severity.PASS, message="ok")],
    )
    fake_console = Console(record=True, width=200)

    _export_json_report(report, symlink_file, fake_console)

    output = fake_console.export_text()
    assert "Refusing to write to symlink" in output
    assert target.read_text(encoding="utf-8") == "critical data"


def test_omz_check_skipped_when_root(monkeypatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    service = SystemDryRunService()
    result = service._check_oh_my_zsh("/tmp/fake-omz")
    assert result.severity == Severity.SKIP
    assert "skipped when running as root" in result.message


def test_omz_upgrade_skipped_when_root(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    fake_home = tmp_path / "home"
    omz_tool = fake_home / ".oh-my-zsh" / "tools" / "upgrade.sh"
    omz_tool.parent.mkdir(parents=True)
    omz_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    context = ScanContext(
        profile="system",
        cwd=tmp_path,
        home=fake_home,
        path_value="",
        shell="/bin/bash",
    )

    fake_console = Console(record=True, width=120)
    service = SystemUpgradeService()

    executed_steps = []

    def fake_step(command, console, title):
        executed_steps.append(command)
        return False, False, False

    monkeypatch.setattr(service, "_run_step", fake_step)
    monkeypatch.setattr(service, "_refresh_mirrors", lambda *a: (False, "skip"))
    monkeypatch.setattr(service, "_maintenance_preflight", lambda *a: True)
    monkeypatch.setattr("dotdoctor.application.system_update.MaintenanceChecks.run", lambda *a: [])
    monkeypatch.setattr("dotdoctor.application.system_update.detect_snapshot_tool", lambda: None)

    service.run(context, fake_console)

    # Must NOT have run the upgrade script as root
    assert not any("upgrade.sh" in str(cmd) for cmd in executed_steps)
    output = fake_console.export_text()
    assert "cannot run shell script as root" in output


def test_streaming_step_timeout_enforced() -> None:
    service = SystemUpgradeService()
    console = Console(record=True)
    hanging_cmd = [sys.executable, "-c", "import time; time.sleep(10)"]

    with pytest.raises(subprocess.TimeoutExpired):
        service._run_streaming_step(
            hanging_cmd, console, "Hanging step", console_width=80, timeout=0.1
        )


def test_maintenance_state_fix_ownership(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    chowned = []

    def fake_chown(path, uid, gid):
        chowned.append((str(path), uid, gid))

    monkeypatch.setattr(os, "chown", fake_chown)

    state_file = tmp_path / "dotdoctor" / "maintenance.json"
    state = MaintenanceState(state_file)
    state.acknowledge_news(["https://archlinux.org/news/1/"])

    assert state_file.exists()
    assert any(item[0] == str(state_file) and item[1:] == (1000, 1000) for item in chowned)


def test_system_update_unescaped_error_output_does_not_crash(monkeypatch) -> None:
    service = SystemUpgradeService()
    fake_console = Console(record=True, width=80)

    # Command output contains broken rich tags like [/dim] and unknown tags
    evil_cmd = [
        sys.executable,
        "-c",
        'import sys; sys.stderr.write("[/dim][bold]broken markup [ERROR]\\n"); sys.exit(1)',
    ]

    had_error, is_net_fail, had_updates = service._run_step(evil_cmd, fake_console, "Evil step")
    assert had_error is True
    output = fake_console.export_text()
    assert "broken markup [ERROR]" in output
