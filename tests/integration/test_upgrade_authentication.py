"""Authentication order is tested with mocked commands, never real sudo."""

import io
import subprocess
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

from dotdoctor.application import maintenance as maintenance
from dotdoctor.application import system_update as updates
from dotdoctor.cli.app import app
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


@pytest.fixture
def environment(monkeypatch, tmp_path):
    state = SimpleNamespace(events=[], authenticated=False, preflights=0)
    output = io.StringIO()
    console = Console(file=output, color_system=None)
    context = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")

    def authenticate(command, **kwargs):
        assert command == ["sudo", "-v"], "No mutation may precede authentication"
        assert kwargs == {"check": False, "timeout": 120}
        state.events.append("sudo")
        state.authenticated = True
        return SimpleNamespace(returncode=0)

    def online():
        assert state.authenticated
        state.events.append("network")
        return True

    def disk():
        assert state.authenticated
        state.events.append("disk")
        return updates.DiskSpaceStatus(100 * 1024**3, 1024**3, Severity.PASS, "healthy", None)

    def checks(self, context, ids):
        assert state.authenticated
        if ids == maintenance.PREFLIGHT_IDS:
            state.preflights += 1
            state.events.append("preflight")
        else:
            assert ids == maintenance.POSTFLIGHT_IDS
            state.events.append("postflight")
        return []

    def snapshot_tool():
        assert state.events[-1] == "preflight"
        state.events.append("snapshot")
        return None

    service = updates.SystemUpgradeService(
        is_online_fn=online, aur_helper_fn=lambda: None, snapshot_tool_fn=snapshot_tool
    )

    def step(command, console, title):
        assert state.events[:4] == ["sudo", "network", "disk", "preflight"] or state.events[:5] == [
            "confirm",
            "sudo",
            "network",
            "disk",
            "preflight",
        ]
        assert state.preflights == 1
        state.events.append("transaction")
        return False, False, True

    monkeypatch.setattr(updates.subprocess, "run", authenticate)
    monkeypatch.setattr(updates, "detect_disk_space_status", disk)
    monkeypatch.setattr(updates, "detect_pacnew_files", lambda: [])
    monkeypatch.setattr(
        updates, "detect_reboot_status", lambda: updates.RebootStatus(False, None, "test", ["test"])
    )
    monkeypatch.setattr(
        updates.shutil, "which", lambda name: "/bin/pacman" if name == "pacman" else None
    )
    monkeypatch.setattr(maintenance.MaintenanceChecks, "run", checks)
    monkeypatch.setattr(service, "_run_step", step)
    return SimpleNamespace(
        state=state, service=service, context=context, console=console, output=output
    )


def test_sudo_precedes_every_guard_and_guards_precede_mutations(environment):
    env = environment
    assert env.service.run(env.context, env.console) == 0
    assert env.state.events == [
        "sudo",
        "network",
        "disk",
        "preflight",
        "snapshot",
        "transaction",
        "postflight",
    ]
    assert env.state.preflights == 1


def test_accepting_update_goes_directly_to_sudo(monkeypatch, environment):
    env = environment

    def confirm(*args, **kwargs):
        env.state.events.append("confirm")
        return True

    monkeypatch.setattr("dotdoctor.cli.app._safe_confirm", confirm)
    monkeypatch.setattr("dotdoctor.cli.app.load_config", lambda *a: DotDoctorConfig())
    monkeypatch.setattr("dotdoctor.cli.app.SystemUpgradeService", lambda **kw: env.service)
    monkeypatch.setattr(updates.SystemDryRunService, "build_tasks", lambda *a, **kw: [])
    monkeypatch.setattr(
        updates.SystemDryRunService,
        "run_with_progress",
        lambda *a, **kw: ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages", severity=Severity.OUTD, message="1 update available"
                )
            ],
        ),
    )
    monkeypatch.setattr(
        updates.SystemDryRunService,
        "run",
        lambda *a, **kw: ScanReport(profile="system", results=[]),
    )
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0, result.output
    assert env.state.events[:5] == ["confirm", "sudo", "network", "disk", "preflight"]


def test_preflight_progress_never_overwrites_sudo_or_news_prompts(monkeypatch, environment):
    env = environment
    env.state.active = False
    frames = []
    for flag in ("NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR"):
        monkeypatch.delenv(flag, raising=False)
    monkeypatch.setenv("TERM", "xterm")
    console = Console(file=env.output, force_terminal=True)

    class Live:
        def __init__(self, grid, **kwargs):
            assert kwargs["transient"] is True
            assert kwargs["refresh_per_second"] == 10
            assert grid.columns[1].width == 4
            spinner = grid.columns[1]._cells[0]
            frames.extend(spinner.render(now).plain for now in (0.0, 0.09, 0.18, 0.27))

        def __enter__(self):
            assert env.state.authenticated and not env.state.active
            env.state.active = True

        def __exit__(self, *args):
            env.state.active = False

    authenticate = updates.subprocess.run

    def run(command, **kwargs):
        assert not env.state.active
        return authenticate(command, **kwargs)

    original_checks = maintenance.MaintenanceChecks.run

    def checks(self, context, ids):
        assert env.state.active
        original_checks(self, context, ids)
        return [
            CheckResult(
                check_id="sys.news",
                severity=Severity.WARN,
                message="1 unread Arch upgrade notice",
                details={
                    "notices": [{"title": "Change", "url": "https://archlinux.org/news/change/"}]
                },
            )
        ]

    def decline(*args, **kwargs):
        assert not env.state.active
        env.state.events.append("news")
        return False

    monkeypatch.setattr(updates, "Live", Live)
    monkeypatch.setattr(updates.subprocess, "run", run)
    monkeypatch.setattr(maintenance.MaintenanceChecks, "run", checks)
    monkeypatch.setattr(updates.typer, "confirm", decline)
    assert env.service.run(env.context, console) == 2
    assert env.state.events == ["sudo", "network", "disk", "preflight", "news"]
    assert not env.state.active
    assert len(set(frames)) >= 3


@pytest.mark.parametrize("failure", ["denied", "timeout", "unavailable", "interrupted"])
def test_authentication_failure_never_runs_checks_or_transactions(
    monkeypatch, environment, failure
):
    env = environment

    def authenticate(command, **kwargs):
        assert command == ["sudo", "-v"]
        env.state.events.append("sudo")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 120)
        if failure == "unavailable":
            raise FileNotFoundError("sudo unavailable")
        if failure == "interrupted":
            raise KeyboardInterrupt
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(updates.subprocess, "run", authenticate)
    if failure == "interrupted":
        with pytest.raises(KeyboardInterrupt):
            env.service.run(env.context, env.console)
    else:
        assert env.service.run(env.context, env.console) == 3
    assert env.state.events == ["sudo"]
    assert env.state.preflights == 0
