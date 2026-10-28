"""Removal plans and confirmations run only against mocked pacman readers."""

import io
import subprocess
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from rich.console import Console

from dotdoctor.application import auto_fix as fixes
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


@pytest.fixture
def environment(monkeypatch, tmp_path):
    output = io.StringIO()
    fixer = fixes.InteractiveAutoFixer(Console(file=output, width=100, color_system=None))
    ctx = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    result = CheckResult(
        check_id="sys.orphans",
        severity=Severity.WARN,
        message="orphans",
        details={"orphans": ["old"]},
    )
    state = SimpleNamespace(commands=[], queries=0, previews=0, confirmed=False, verified=False)
    monkeypatch.setattr(fixes.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(fixer, "_maintenance_progress", lambda *a: nullcontext())

    def verify(*args):
        state.verified = True
        return CheckResult(check_id="sys.orphans", severity=Severity.PASS, message="no orphans")

    monkeypatch.setattr(fixer, "_verify", verify)

    def run(command, **kwargs):
        state.commands.append(command)
        if command == ["pacman", "-Qtdq"]:
            state.queries += 1
            return SimpleNamespace(returncode=0, stdout="orphan\n", stderr="")
        if command[:2] == ["pacman", "-Rs"]:
            state.previews += 1
            assert "--print-format" in command
            assert "--" in command
            assert kwargs["stdin"] == subprocess.DEVNULL
            assert kwargs["env"]["LC_ALL"] == "C"
            return SimpleNamespace(
                returncode=0,
                stdout="orphan\t1.0-1\t1048576\ndependency\t2.0-1\t2097152\n",
                stderr="",
            )
        assert state.confirmed
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(fixes.subprocess, "run", run)

    def confirm(prompt, default=True):
        preview = output.getvalue()
        assert "orphan 1.0-1" in preview
        assert "dependency 2.0-1 (dependency)" in preview
        assert "~3.0 MiB to free" in preview
        assert prompt == "Remove these 2 packages now?"
        assert all(command[0] == "pacman" for command in state.commands)
        state.confirmed = True
        return True

    monkeypatch.setattr(fixes.typer, "confirm", confirm)
    return SimpleNamespace(
        fixer=fixer, context=ctx, result=result, state=state, output=output, run=run
    )


def apply(env):
    return env.fixer.apply(ScanReport(profile="system", results=[env.result]), env.context)


def test_full_plan_is_shown_before_confirmation_and_exact_set_is_removed(environment):
    env = environment
    assert apply(env).results[0].severity == Severity.PASS
    assert env.state.verified and env.state.confirmed
    assert env.state.queries == env.state.previews == 2
    assert env.state.commands[-1] == [
        "sudo",
        "-n",
        "pacman",
        "-Rn",
        "--noconfirm",
        "--",
        "dependency",
        "orphan",
    ]
    assert "old" not in env.state.commands[-1]


def test_pacman_print_mode_rejects_nosave_but_real_removal_keeps_it(monkeypatch, environment):
    env = environment

    def run(command, **kwargs):
        if command[0] == "pacman" and "--print-format" in command:
            flags = set()
            for arg in command[1 : command.index("--")]:
                if arg.startswith("-") and not arg.startswith("--"):
                    flags.update(arg[1:])
            if "n" in flags or "--nosave" in command:
                return SimpleNamespace(
                    returncode=1,
                    stdout="",
                    stderr=(
                        "error: invalid option: '--nosave' and '--print' may not be used together"
                    ),
                )
        return env.run(command, **kwargs)

    monkeypatch.setattr(fixes.subprocess, "run", run)
    assert apply(env).results[0].severity == Severity.PASS
    assert env.state.verified
    assert "-Rn" in env.state.commands[-1]
    assert "invalid option" not in env.output.getvalue()


def test_declining_plan_does_not_authenticate_or_remove(monkeypatch, environment):
    env = environment
    monkeypatch.setattr(fixes.typer, "confirm", lambda *a, **kw: False)
    assert apply(env).results[0].severity == Severity.WARN
    assert not env.state.verified
    assert len(env.state.commands) == 2
    assert "Removal declined" in env.output.getvalue()


@pytest.mark.parametrize("change", ["version", "size", "extra", "orphan", "unreadable"])
def test_plan_changes_after_authentication_stop_removal(monkeypatch, environment, change):
    env = environment

    def run(command, **kwargs):
        result = env.run(command, **kwargs)
        if command[0] == "pacman" and env.state.queries == 2:
            if change == "orphan" and command == ["pacman", "-Qtdq"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if command[:2] == ["pacman", "-Rs"]:
                result.stdout = {
                    "version": result.stdout.replace("1.0-1", "1.0-2"),
                    "size": result.stdout.replace("1048576", "1048577"),
                    "extra": result.stdout + "extra\t1.0\t1024\n",
                    "unreadable": "unexpected output",
                }.get(change, result.stdout)
        return result

    monkeypatch.setattr(fixes.subprocess, "run", run)
    assert apply(env).results[0].severity == Severity.WARN
    assert not env.state.verified
    assert all("-Rn" not in command for command in env.state.commands)


@pytest.mark.parametrize(
    "preview",
    [
        "",
        "unexpected",
        "orphan\t1.0\t-1\n",
        "orphan\t1.0\tunknown\n",
        "orphan\t1\t0\norphan\t1\t0\n",
        "other\t1\t0\n",
    ],
)
def test_invalid_preview_never_asks_to_remove(monkeypatch, environment, preview):
    env = environment

    def run(command, **kwargs):
        result = env.run(command, **kwargs)
        if command[:2] == ["pacman", "-Rs"]:
            result.stdout = preview
        return result

    monkeypatch.setattr(fixes.subprocess, "run", run)
    assert apply(env).results[0].severity == Severity.WARN
    assert not env.state.confirmed and not env.state.verified
    assert all(command[0] == "pacman" for command in env.state.commands)


@pytest.mark.parametrize("failure", ["query", "preview", "timeout"])
def test_reader_failure_never_removes_packages(monkeypatch, environment, failure):
    env = environment

    def run(command, **kwargs):
        result = env.run(command, **kwargs)
        if (failure == "query" and command == ["pacman", "-Qtdq"]) or (
            failure in {"preview", "timeout"} and command[:2] == ["pacman", "-Rs"]
        ):
            if failure == "timeout":
                raise subprocess.TimeoutExpired(command, 15)
            return SimpleNamespace(returncode=1, stdout="", stderr="database unavailable")
        return result

    monkeypatch.setattr(fixes.subprocess, "run", run)
    assert apply(env).results[0].severity == Severity.WARN
    assert not env.state.confirmed and not env.state.verified
    assert all(command[0] == "pacman" for command in env.state.commands)
