"""Maintenance waits use mocked commands; TRIM, scrubs and backups never run."""

import io
import subprocess
from types import SimpleNamespace

import pytest
from rich.console import Console

from dotdoctor.application import auto_fix as fixes
from dotdoctor.domain.config import BackupConfig, DotDoctorConfig, MaintenanceConfig, TimerConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


@pytest.fixture
def environment(monkeypatch, tmp_path):
    monkeypatch.setenv("TERM", "xterm-256color")
    for name in ("NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)
    output = io.StringIO()
    fixer = fixes.InteractiveAutoFixer(Console(file=output, force_terminal=True, color_system=None))
    context = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    result = CheckResult(
        check_id="sys.trim",
        severity=Severity.WARN,
        message="TRIM overdue",
        details={"actionable": True},
    )
    state = SimpleNamespace(active=False, grids=[], calls=[], verified=False)

    class Live:
        def __init__(self, grid, **kwargs):
            assert kwargs["transient"] is True
            assert not kwargs.get("screen", False)
            assert kwargs["refresh_per_second"] == 10
            assert grid.columns[1].width == 4
            state.grids.append(grid)

        def __enter__(self):
            assert not state.active
            state.active = True
            return self

        def __exit__(self, *args):
            state.active = False

    def forbidden(*args, **kwargs):
        raise AssertionError("Every subprocess must be mocked")

    def verify(result, context):
        state.verified = True
        return CheckResult(check_id=result.check_id, severity=Severity.PASS, message="verified")

    monkeypatch.setattr(fixes, "Live", Live)
    monkeypatch.setattr(fixes.subprocess, "run", forbidden)
    monkeypatch.setattr(fixes.typer, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(fixer, "_verify", verify)
    return SimpleNamespace(fixer=fixer, context=context, result=result, state=state, output=output)


def apply(env):
    return env.fixer.apply(ScanReport(profile="system", results=[env.result]), env.context)


@pytest.mark.parametrize("cached", [True, False])
def test_trim_animates_silent_wait_and_verification_without_hiding_auth(
    monkeypatch, environment, cached
):
    env = environment
    frames = []

    def run(command, **kwargs):
        env.state.calls.append(command)
        if command in (["sudo", "-n", "-v"], ["sudo", "-v"]):
            assert not env.state.active
            if command == ["sudo", "-v"]:
                assert kwargs == {"check": False, "timeout": 120}
            return SimpleNamespace(returncode=0 if cached or command == ["sudo", "-v"] else 1)
        assert env.state.active
        assert kwargs == {
            "check": False,
            "stdin": subprocess.DEVNULL,
            "capture_output": True,
            "text": True,
        }
        if command[-1] == "fstrim.service":
            spinner = env.state.grids[-1].columns[1]._cells[0]
            # Rich refreshes this same spinner while the subprocess emits no output.
            frames.extend(spinner.render(now).plain for now in (0.0, 0.09, 0.18, 0.27))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def verify(result, context):
        assert env.state.active
        env.state.verified = True
        return CheckResult(
            check_id=result.check_id, severity=Severity.PASS, message="TRIM succeeded"
        )

    monkeypatch.setattr(fixes.subprocess, "run", run)
    monkeypatch.setattr(env.fixer, "_verify", verify)
    report = apply(env)
    assert report.results[0].severity == Severity.PASS
    assert env.state.verified and not env.state.active
    assert len(set(frames)) >= 3
    assert env.state.calls == [
        ["sudo", "-n", "-v"],
        *([] if cached else [["sudo", "-v"]]),
        ["sudo", "-n", "systemctl", "--no-ask-password", "enable", "--now", "fstrim.timer"],
        ["sudo", "-n", "systemctl", "--no-ask-password", "start", "fstrim.service"],
    ]
    assert [grid.columns[3]._cells[0].plain for grid in env.state.grids] == [
        "Enabling weekly TRIM",
        "Waiting for TRIM service to finish",
        "Checking sys.trim after maintenance",
    ]


@pytest.mark.parametrize("failure", ["cached-timeout", "prompt-timeout", "prompt-failed"])
def test_authentication_failure_never_starts_maintenance_or_spinner(
    monkeypatch, environment, failure
):
    env = environment

    def run(command, **kwargs):
        env.state.calls.append(command)
        assert not env.state.active
        if failure == "cached-timeout" or (
            failure == "prompt-timeout" and command == ["sudo", "-v"]
        ):
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(fixes.subprocess, "run", run)
    report = apply(env)
    assert report.results[0].severity == Severity.WARN
    assert env.state.grids == []
    assert not env.state.verified
    assert all(command in (["sudo", "-n", "-v"], ["sudo", "-v"]) for command in env.state.calls)
    assert "maintenance not started" in " ".join(env.output.getvalue().split())


@pytest.mark.parametrize("failed_unit", ["fstrim.timer", "fstrim.service"])
def test_failed_trim_step_closes_spinner_and_reveals_error(monkeypatch, environment, failed_unit):
    env = environment

    def run(command, **kwargs):
        env.state.calls.append(command)
        return SimpleNamespace(
            returncode=int(command[-1] == failed_unit),
            stdout="",
            stderr="Job failed: device unavailable",
        )

    monkeypatch.setattr(fixes.subprocess, "run", run)
    report = apply(env)
    assert report.results[0].severity == Severity.WARN
    assert not env.state.active and not env.state.verified
    assert env.state.calls[-1][-1] == failed_unit
    assert "Job failed: device unavailable" in env.output.getvalue()


@pytest.mark.parametrize(
    "setting", ["pipe", "dumb", "NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR"]
)
def test_static_maintenance_waits_have_visible_stage_messages(monkeypatch, environment, setting):
    env = environment
    if setting == "pipe":
        env.fixer._console = Console(file=env.output, force_terminal=False)
    elif setting == "dumb":
        monkeypatch.setenv("TERM", "dumb")
    else:
        monkeypatch.setenv(setting, "1")
    monkeypatch.setattr(
        fixes.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0)
    )
    report = apply(env)
    assert report.results[0].severity == Severity.PASS
    assert env.state.grids == []
    output = env.output.getvalue()
    assert "        Enabling weekly TRIM" in output
    assert "        Waiting for TRIM service to finish" in output
    assert "        Checking sys.trim after maintenance" in output
    assert "\x1b[" not in output


def test_user_timer_needs_no_sudo_and_cannot_prompt_inside_spinner(monkeypatch, environment):
    env = environment
    env.fixer.config = DotDoctorConfig(
        maintenance=MaintenanceConfig(timers=[TimerConfig(unit="backup.timer", scope="user")])
    )
    env.result = CheckResult(
        check_id="sys.timers",
        severity=Severity.WARN,
        message="timer inactive",
        details={"timers": [{"unit": "backup.timer", "scope": "user"}]},
    )

    def run(command, **kwargs):
        env.state.calls.append(command)
        assert env.state.active
        assert kwargs["stdin"] == subprocess.DEVNULL
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(fixes.subprocess, "run", run)
    assert apply(env).results[0].severity == Severity.PASS
    assert env.state.calls == [
        ["systemctl", "--no-ask-password", "--user", "enable", "--now", "backup.timer"]
    ]


@pytest.mark.parametrize("check_id", ["sys.btrfs", "sys.backup"])
def test_other_long_maintenance_commands_get_named_progress(monkeypatch, environment, check_id):
    env = environment
    env.fixer.config = DotDoctorConfig(
        maintenance=MaintenanceConfig(
            backup=BackupConfig(service="backup.service", status_command=["backup-status"])
        )
    )
    result = CheckResult(
        check_id=check_id,
        severity=Severity.WARN,
        message="maintenance overdue",
        details={"scrub_targets": ["/mnt/data"]},
    )

    def run(command, **kwargs):
        if command != ["sudo", "-n", "-v"]:
            assert env.state.active
            assert command[:2] == ["sudo", "-n"]
            assert kwargs["stdin"] == subprocess.DEVNULL
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(fixes.subprocess, "run", run)
    assert env.fixer._fix_maintenance(env.context, result).changed
    label = env.state.grids[0].columns[3]._cells[0].plain
    assert label == (
        "Scrubbing Btrfs filesystem /mnt/data"
        if check_id == "sys.btrfs"
        else "Starting backup service backup.service"
    )


def test_interrupted_trim_wait_restores_display_without_claiming_success(monkeypatch, environment):
    env = environment

    def run(command, **kwargs):
        if command[-1] == "fstrim.service":
            assert env.state.active
            raise KeyboardInterrupt
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(fixes.subprocess, "run", run)
    with pytest.raises(KeyboardInterrupt):
        apply(env)
    assert not env.state.active and not env.state.verified
    assert "DONE" not in env.output.getvalue()
