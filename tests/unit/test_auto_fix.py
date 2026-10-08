import io
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner

from dotdoctor.application.auto_fix import FixOutcome, InteractiveAutoFixer
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        profile="system",
        cwd=tmp_path,
        home=tmp_path,
        path_value="/usr/bin",
        shell="/bin/bash",
    )


def test_fix_sys_orphans_removes_packages(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.orphans",
        severity=Severity.WARN,
        message="2 orphan packages found",
        details={"orphans": ["libfoo", "libbar"]},
    )
    outcome = fixer._fix_sys_orphans(context, result)

    assert outcome.changed is True
    assert "Removed 2 orphan packages" in outcome.note
    assert commands == [["sudo", "pacman", "-Rns", "--noconfirm", "libfoo", "libbar"]]


def test_fix_sys_orphans_queries_when_details_empty(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        if cmd == ["pacman", "-Qtdq"]:
            return SimpleNamespace(returncode=0, stdout="orphan1\norphan2\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.orphans",
        severity=Severity.WARN,
        message="orphan packages found",
        details={},
    )
    outcome = fixer._fix_sys_orphans(context, result)

    assert outcome.changed is True
    assert "Removed 2 orphan packages" in outcome.note
    assert ["sudo", "pacman", "-Rns", "--noconfirm", "orphan1", "orphan2"] in commands


def test_fix_sys_cache_runs_paccache(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.cache",
        severity=Severity.WARN,
        message="5.0 GiB in pacman cache",
    )
    outcome = fixer._fix_sys_cache(context, result)

    assert outcome.changed is True
    assert outcome.note == "Cleaned pacman package cache."
    assert commands == [["sudo", "paccache", "-rk2"], ["sudo", "paccache", "-ruk0"]]


def test_fix_sys_flatpak_unused(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.flatpak-unused",
        severity=Severity.WARN,
        message="3 unused runtimes",
    )
    outcome = fixer._fix_sys_flatpak_unused(context, result)

    assert outcome.changed is True
    assert outcome.note == "Removed unused Flatpak runtimes."
    assert commands == [["flatpak", "uninstall", "--unused", "-y"]]


def test_fix_sys_pacnew(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.pacnew",
        severity=Severity.WARN,
        message="1 .pacnew file found",
    )
    outcome = fixer._fix_sys_pacnew(context, result)

    assert outcome.changed is True
    assert outcome.note == "Reviewed .pacnew files with pacdiff."
    assert commands == [["sudo", "pacdiff"]]


def test_fix_sys_journal(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.journal",
        severity=Severity.WARN,
        message="4.5 GiB in journal logs",
    )
    outcome = fixer._fix_sys_journal(context, result)

    assert outcome.changed is True
    assert outcome.note == "Vacuumed systemd journal logs to 1G."
    assert commands == [["sudo", "journalctl", "--vacuum-size=1G"]]


@pytest.mark.parametrize("request_code", [0, 1])
def test_fix_sys_reboot(monkeypatch, tmp_path: Path, request_code: int) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append((cmd, kwargs))
        return SimpleNamespace(returncode=0 if cmd == ["sudo", "-v"] else request_code)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.reboot",
        severity=Severity.WARN,
        message="reboot required",
    )
    outcome = fixer._fix_sys_reboot(context, result)

    assert outcome.changed is (request_code == 0)
    assert outcome.note == (
        "Reboot request accepted." if request_code == 0 else "Reboot command failed (exit=1)."
    )
    assert commands == [
        (["sudo", "-v"], {"check": False, "timeout": 120}),
        (
            ["sudo", "-n", "systemctl", "--no-ask-password", "reboot"],
            {"check": False, "timeout": 15},
        ),
    ]


def test_reboot_fallback_is_bounded_and_noninteractive(monkeypatch, tmp_path):
    commands = []

    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)
    monkeypatch.setattr("dotdoctor.application.auto_fix.shutil.which", lambda name: None)
    result = CheckResult(check_id="sys.reboot", severity=Severity.WARN, message="reboot required")
    outcome = InteractiveAutoFixer(Console(file=io.StringIO()))._fix_sys_reboot(
        _context(tmp_path), result
    )
    assert outcome.changed is True
    assert commands[-1] == (["sudo", "-n", "reboot"], {"check": False, "timeout": 15})


def test_reboot_confirmation_defaults_to_no_with_real_prompt(monkeypatch, tmp_path):
    app = typer.Typer()
    fixer = InteractiveAutoFixer(Console())

    def forbidden(*args):
        raise AssertionError("Pressing Enter must not authenticate or request a reboot")

    monkeypatch.setattr(fixer, "_fix_sys_reboot", forbidden)
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="sys.reboot", severity=Severity.WARN, message="reboot required")
        ],
    )

    @app.command()
    def run():
        fixer.apply(report, _context(tmp_path))

    result = CliRunner().invoke(app, [], input="\n")

    assert result.exit_code == 0
    assert "[y/N]" in result.output
    assert "Skipped by user" in result.output


@pytest.mark.parametrize("phase", ["authentication", "request"])
def test_reboot_timeouts_do_not_retry_or_claim_success(monkeypatch, tmp_path, phase):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if phase == "authentication" or command[:2] != ["sudo", "-v"]:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)
    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    result = CheckResult(check_id="sys.reboot", severity=Severity.WARN, message="reboot required")
    outcome = InteractiveAutoFixer(Console(file=io.StringIO()))._fix_sys_reboot(
        _context(tmp_path), result
    )
    assert outcome.changed is False
    assert "timed out" in outcome.note
    if phase == "authentication":
        assert commands == [["sudo", "-v"]]
        assert "no reboot requested" in outcome.note
    else:
        assert len(commands) == 2
        assert "state is unknown" in outcome.note
        assert "systemctl list-jobs" in outcome.note


def test_denied_reboot_authentication_never_sends_request(monkeypatch, tmp_path):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)
    result = CheckResult(check_id="sys.reboot", severity=Severity.WARN, message="reboot required")
    outcome = InteractiveAutoFixer(Console(file=io.StringIO()))._fix_sys_reboot(
        _context(tmp_path), result
    )
    assert commands == [["sudo", "-v"]]
    assert outcome.changed is False
    assert "no reboot requested" in outcome.note


@pytest.mark.parametrize("accepted", [True, False])
def test_reboot_is_last_has_no_spinner_and_is_not_verified_before_boot(
    monkeypatch, tmp_path, accepted
):
    output = io.StringIO()
    console = Console(file=output, force_terminal=True)
    fixer = InteractiveAutoFixer(console)
    actions = []
    prompts = []
    spinner_active = [False]

    @contextmanager
    def status(*args, **kwargs):
        spinner_active[0] = True
        try:
            yield
        finally:
            spinner_active[0] = False

    def confirm(prompt, default):
        prompts.append((prompt, default))
        return True

    def clean(context, result):
        actions.append("cache")
        return FixOutcome(True, "Cache cleaned.")

    def reboot(context, result):
        assert spinner_active[0] is False
        actions.append("reboot")
        return FixOutcome(
            accepted, "Reboot request accepted." if accepted else "Reboot request timed out."
        )

    def verify(result, context):
        assert result.check_id == "sys.cache", "Reboot completion needs a new boot"
        return CheckResult(check_id="sys.cache", severity=Severity.PASS, message="cache clean")

    monkeypatch.setattr(console, "status", status)
    monkeypatch.setattr("dotdoctor.application.auto_fix.typer.confirm", confirm)
    monkeypatch.setattr(fixer, "_fix_sys_cache", clean)
    monkeypatch.setattr(fixer, "_fix_sys_reboot", reboot)
    monkeypatch.setattr(fixer, "_verify", verify)
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="sys.reboot", severity=Severity.WARN, message="reboot required"),
            CheckResult(check_id="sys.cache", severity=Severity.WARN, message="cache too large"),
        ],
    )

    updated = fixer.apply(report, _context(tmp_path))

    assert actions == ["cache", "reboot"]
    assert [result.check_id for result in updated.results] == ["sys.reboot", "sys.cache"]
    assert prompts[-1][1] is False
    assert updated.get_result("sys.cache").severity == Severity.PASS
    reboot_result = updated.get_result("sys.reboot")
    assert reboot_result.severity == Severity.WARN
    assert reboot_result.details.get("reboot_requested", False) is accepted
    if accepted:
        assert reboot_result.details["verified"] is False
        assert "next boot" in reboot_result.message
    else:
        assert "timed out" in output.getvalue()
        assert "No changes applied" not in output.getvalue()


def test_fix_sys_services(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.services",
        severity=Severity.FAIL,
        message="1 failed unit",
    )
    outcome = fixer._fix_sys_services(context, result)

    assert outcome.changed is False
    assert "resolve the cause" in outcome.note
    assert commands == []


def test_fix_sys_disk(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())

    commands = []

    def fake_run(cmd, *args, **kwargs):
        commands.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.subprocess.run", fake_run)

    result = CheckResult(
        check_id="sys.disk",
        severity=Severity.WARN,
        message="low disk space",
    )
    outcome = fixer._fix_sys_disk(context, result)

    assert outcome.changed is True
    assert "cleaned pacman cache" in outcome.note
    assert "vacuumed journal logs" in outcome.note


def test_interactive_auto_fixer_apply_skips_outd_and_prompts_warn(
    monkeypatch, tmp_path: Path
) -> None:
    context = _context(tmp_path)
    fixer = InteractiveAutoFixer(Console())
    monkeypatch.setattr(
        fixer,
        "_verify",
        lambda result, ctx: CheckResult(
            check_id=result.check_id, severity=Severity.PASS, message="No orphan packages."
        ),
    )

    prompts = []

    def fake_confirm(prompt, default=True):
        prompts.append((prompt, default))
        return True

    monkeypatch.setattr("dotdoctor.application.auto_fix.typer.confirm", fake_confirm)
    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.InteractiveAutoFixer._fix_sys_orphans",
        lambda self, ctx, res: FixOutcome(changed=True, note="Removed 1 orphan package."),
    )

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.packages",
                severity=Severity.OUTD,
                message="2 updates available",
            ),
            CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="1 orphan package found",
                details={"orphans": ["orphan1"]},
            ),
            CheckResult(
                check_id="sys.reboot",
                severity=Severity.WARN,
                message="reboot required",
            ),
        ],
    )

    # Let sys.reboot confirm be False
    def fake_confirm_conditional(prompt, default=True):
        prompts.append((prompt, default))
        if "reboot" in prompt.lower():
            return False
        return True

    monkeypatch.setattr("dotdoctor.application.auto_fix.typer.confirm", fake_confirm_conditional)

    new_report = fixer.apply(report, context)

    orphans_result = new_report.get_result("sys.orphans")
    assert orphans_result is not None
    assert orphans_result.severity is Severity.PASS
    assert "Auto-fixed" in orphans_result.message

    reboot_result = new_report.get_result("sys.reboot")
    assert reboot_result is not None
    assert reboot_result.severity is Severity.WARN

    # Check defaults: orphans default was True, reboot default was False
    assert prompts[0][1] is True
    assert prompts[1][1] is False


def test_resolve_action_label() -> None:
    fixer = InteractiveAutoFixer(Console())
    assert "orphan" in fixer._resolve_action_label("sys.orphans").lower()
    assert "cache" in fixer._resolve_action_label("sys.cache").lower()
    assert "flatpak" in fixer._resolve_action_label("sys.flatpak-unused").lower()
    assert "pacdiff" in fixer._resolve_action_label("sys.pacnew").lower()
    assert "journal" in fixer._resolve_action_label("sys.journal").lower()
    assert "reboot" in fixer._resolve_action_label("sys.reboot").lower()
    assert "services" in fixer._resolve_action_label("sys.services").lower()
    assert "cache" in fixer._resolve_action_label("sys.disk").lower()
    assert "unknown" in fixer._resolve_action_label("unknown")


def test_apply_uses_status_spinner_when_terminal(monkeypatch, tmp_path: Path) -> None:
    context = _context(tmp_path)
    console = Console()
    monkeypatch.setattr(Console, "is_terminal", property(lambda self: True))
    fixer = InteractiveAutoFixer(console)
    monkeypatch.setattr(
        fixer,
        "_verify",
        lambda result, ctx: CheckResult(
            check_id=result.check_id, severity=Severity.PASS, message="No orphan packages."
        ),
    )

    status_called = []

    class DummyStatus:
        def __init__(self, message: str) -> None:
            self.message = message

        def __enter__(self):
            status_called.append(self.message)
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    monkeypatch.setattr(console, "status", lambda msg, spinner="dots": DummyStatus(msg))
    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.typer.confirm",
        lambda prompt, default=True: True,
    )
    monkeypatch.setattr(
        fixer,
        "_fix_sys_orphans",
        lambda ctx, res: FixOutcome(changed=True, note="Removed 1 package."),
    )

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="orphan found",
            )
        ],
    )

    new_report = fixer.apply(report, context)
    assert len(status_called) == 1
    assert "Removing orphan packages" in status_called[0]
    res = new_report.get_result("sys.orphans")
    assert res is not None
    assert res.severity is Severity.PASS
