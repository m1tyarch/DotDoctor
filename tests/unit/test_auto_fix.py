from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

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


def test_fix_sys_reboot(monkeypatch, tmp_path: Path) -> None:
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
        check_id="sys.reboot",
        severity=Severity.WARN,
        message="reboot required",
    )
    outcome = fixer._fix_sys_reboot(context, result)

    assert outcome.changed is True
    assert outcome.note == "System reboot initiated."
    assert commands == [["sudo", "systemctl", "reboot"]]


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

    assert outcome.changed is True
    assert outcome.note == "Reset failed systemd services."
    assert commands == [["systemctl", "reset-failed"], ["systemctl", "--user", "reset-failed"]]


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
