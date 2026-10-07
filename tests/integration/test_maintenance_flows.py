import io
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

from dotdoctor.application import maintenance as m
from dotdoctor.application import system_update as s
from dotdoctor.application.auto_fix import FixOutcome, InteractiveAutoFixer
from dotdoctor.cli.app import app
from dotdoctor.domain.config import BackupConfig, DotDoctorConfig, MaintenanceConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure import maintenance as readers


def finding(cid, severity=Severity.WARN, **details):
    return CheckResult(check_id=cid, severity=severity, message=f"finding: {cid}", details=details)


@pytest.fixture
def context(tmp_path):
    return ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")


@pytest.fixture
def environment(monkeypatch, tmp_path):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="there is nothing to do", stderr="")

    monkeypatch.setattr(s.subprocess, "run", run)
    monkeypatch.setattr(s.socket, "create_connection", lambda *a, **kw: nullcontext())
    monkeypatch.setattr(s.shutil, "which", lambda name: "/bin/pacman" if name == "pacman" else None)
    monkeypatch.setattr(
        s,
        "detect_disk_space_status",
        lambda: s.DiskSpaceStatus(100 * 1024**3, 1024**3, Severity.PASS, "healthy", None),
    )
    monkeypatch.setattr(
        s, "detect_reboot_status", lambda: s.RebootStatus(False, None, "test", ["test"])
    )
    monkeypatch.setattr(s, "detect_pacnew_files", lambda: [])
    monkeypatch.setattr(m.MaintenanceChecks, "run", lambda self, context, ids: [])
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    return commands


def upgrade():
    return s.SystemUpgradeService(
        is_online_fn=lambda: True, aur_helper_fn=lambda: None, snapshot_tool_fn=lambda: None
    )


@pytest.mark.parametrize("cid", ["sys.smart", "sys.btrfs", "sys.package-db", "sys.backup"])
def test_blocking_preflight_never_starts_a_transaction(monkeypatch, environment, context, cid):
    monkeypatch.setattr(
        m.MaintenanceChecks, "run", lambda self, context, ids: [finding(cid, blocks_upgrade=True)]
    )
    assert upgrade().run(context, Console(file=io.StringIO())) == 2
    assert environment == []


def test_blocking_preflight_prints_items_fix_and_abort_message(monkeypatch, environment, context):
    output = io.StringIO()
    console = Console(file=output)
    finding_result = CheckResult(
        check_id="sys.mounts",
        severity=Severity.FAIL,
        message="1 filesystem capacity findings",
        remediation="df -h; df -i",
        details={
            "items": ["/boot/efi: critically low available space (2 MB free, minimum 9 MB)"],
            "blocks_upgrade": True,
        },
    )
    monkeypatch.setattr(m.MaintenanceChecks, "run", lambda self, ctx, ids: [finding_result])
    code = upgrade().run(context, console)
    assert code == 2
    out = output.getvalue()
    assert "1 filesystem capacity findings" in out
    assert "/boot/efi: critically low available space" in out
    assert "fix: df -h; df -i" in out
    assert "Upgrade aborted — critical preflight check 'sys.mounts' failed." in out


def test_smart_rechecked_after_sudo_before_snapshot(monkeypatch, environment, context):
    def checks(self, context, ids):
        if ids == m.PREFLIGHT_IDS:
            return [finding("sys.smart", verified=False)]
        return [finding("sys.smart", Severity.FAIL, blocks_upgrade=True)]

    monkeypatch.setattr(m.MaintenanceChecks, "run", checks)
    assert upgrade().run(context, Console(file=io.StringIO())) == 2
    assert environment == [["sudo", "true"]]


def test_news_decline_does_not_save_ack_or_start_upgrade(monkeypatch, environment, context):
    notices = [{"title": "Required change", "url": "https://archlinux.org/news/change/"}]
    monkeypatch.setattr(
        m.MaintenanceChecks,
        "run",
        lambda self, context, ids: [finding("sys.news", notices=notices)],
    )
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: False)
    assert upgrade().run(context, Console(file=io.StringIO())) == 2
    assert not readers.MaintenanceState().path.exists()
    assert environment == []


def test_news_accepted_saved_once_and_upgrade_continues(monkeypatch, environment, context):
    notices = [{"title": "Required change", "url": "https://archlinux.org/news/change/"}]
    monkeypatch.setattr(
        m.MaintenanceChecks,
        "run",
        lambda self, context, ids: (
            [finding("sys.news", notices=notices)] if "sys.news" in ids else []
        ),
    )
    prompts = []

    def confirm(prompt, default):
        prompts.append((prompt, default))
        return True

    monkeypatch.setattr(s.typer, "confirm", confirm)
    assert upgrade().run(context, Console(file=io.StringIO())) == 0
    assert readers.MaintenanceState().read()["news"] == [notices[0]["url"]]
    assert len(prompts) == 1
    assert prompts[0][1] is False
    assert any("-Syu" in command for command in environment)


def test_unavailable_news_requires_explicit_override(monkeypatch, environment, context):
    monkeypatch.setattr(
        m.MaintenanceChecks, "run", lambda self, context, ids: [finding("sys.news", verified=False)]
    )
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: False)
    assert upgrade().run(context, Console(file=io.StringIO())) == 2
    assert environment == []


def test_failed_snapshot_stops_before_mirrors_and_packages(monkeypatch, environment, context):
    service = upgrade()
    service._snapshot_tool_fn = lambda: "snapper"
    steps = []

    def step(cmd, console, title):
        steps.append(cmd)
        return True, False, False

    monkeypatch.setattr(service, "_run_step", step)
    assert service.run(context, Console(file=io.StringIO())) == 2
    assert len(steps) == 1
    assert steps[0][:3] == ["sudo", "snapper", "create"]
    assert environment == [["sudo", "true"]]


@pytest.mark.parametrize("fail_second", [False, True])
def test_keyring_preparation_always_completes_full_upgrade(monkeypatch, environment, fail_second):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        s,
        "capture",
        lambda *args: SimpleNamespace(returncode=0, stdout="archlinux-keyring 1 -> 2\n"),
    )
    commands = []
    service = upgrade()

    def step(cmd, console, title):
        commands.append(cmd)
        return bool(fail_second and "-Su" in cmd), False, False

    monkeypatch.setattr(service, "_run_step", step)
    assert service._prepare_keyring(Console(file=io.StringIO())) is not fail_second
    assert commands == [
        ["sudo", "pacman", "-Sy", "--needed", "archlinux-keyring"],
        ["sudo", "pacman", "-Su"],
    ]


def test_signature_failure_retries_after_keyring_without_disabling_trust(
    monkeypatch, environment, context
):
    commands = []
    attempts = 0

    def run(command, **kwargs):
        nonlocal attempts
        commands.append(command)
        if "-Syu" in command:
            attempts += 1
            if attempts == 1:
                return SimpleNamespace(
                    returncode=1, stdout="", stderr="signature is marginal trust"
                )
        return SimpleNamespace(returncode=0, stdout="nothing to do", stderr="")

    monkeypatch.setattr(s.subprocess, "run", run)
    assert upgrade().run(context, Console(file=io.StringIO())) == 0
    assert attempts == 2
    key = commands.index(["sudo", "pacman", "-Sy", "--needed", "archlinux-keyring"])
    assert commands[key + 1] == ["sudo", "pacman", "-Su"]
    assert all(
        "--nodeps" not in cmd and "rm" not in cmd and "--overwrite" not in cmd for cmd in commands
    )


def test_residual_vulnerability_is_reported_after_upgrade(monkeypatch, environment, context):
    monkeypatch.setattr(
        m.MaintenanceChecks,
        "run",
        lambda self, context, ids: (
            [finding("sys.security", Severity.FAIL)] if ids == m.POSTFLIGHT_IDS else []
        ),
    )
    output = io.StringIO()
    assert upgrade().run(context, Console(file=output)) == 2
    assert "FAIL" in output.getvalue()
    assert "All updates completed successfully" not in output.getvalue()


def test_declined_rebuild_does_not_build_anything(monkeypatch, environment, context):
    service = s.SystemUpgradeService(aur_helper_fn=lambda: "paru")
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: False)
    assert service._offer_rebuilds(
        finding("sys.rebuild", rebuild_packages=["custom"]), context, Console(file=io.StringIO())
    )
    assert environment == []


def test_rebuild_is_confirmed_and_rechecked(monkeypatch, environment, context):
    service = s.SystemUpgradeService(aur_helper_fn=lambda: "paru")
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        m.MaintenanceChecks,
        "run",
        lambda self, context, ids: [finding("sys.rebuild", Severity.PASS)],
    )
    assert service._offer_rebuilds(
        finding("sys.rebuild", rebuild_packages=["custom", "custom-bin"]),
        context,
        Console(file=io.StringIO()),
    )
    assert environment == [["paru", "-S", "--rebuild", "yes", "--", "custom"]]


def test_rebuild_command_failure_propagates(monkeypatch, environment, context):
    service = s.SystemUpgradeService(aur_helper_fn=lambda: "paru")
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(service, "_run_step", lambda *args: (True, False, False))
    assert not service._offer_rebuilds(
        finding("sys.rebuild", rebuild_packages=["custom"]), context, Console(file=io.StringIO())
    )


@pytest.mark.parametrize(
    "cid,details",
    [
        ("sys.trim", {"actionable": True}),
        ("sys.btrfs", {"scrub_targets": ["/"]}),
        ("sys.timers", {"timers": [{"unit": "systemd-tmpfiles-clean.timer", "scope": "system"}]}),
        ("sys.integrity", {"reinstall_packages": ["bash"]}),
        ("sys.backup", {}),
    ],
)
def test_successful_action_with_residual_findings_never_becomes_pass(
    monkeypatch, environment, context, cid, details
):
    config = DotDoctorConfig(
        maintenance=MaintenanceConfig(
            backup=BackupConfig(service="backup.service", status_command=["backup-status"])
        )
    )
    fixer = InteractiveAutoFixer(Console(file=io.StringIO()), config=config)
    prompts = []

    def confirm(prompt, default):
        prompts.append(default)
        return True

    monkeypatch.setattr(s.typer, "confirm", confirm)
    monkeypatch.setattr(
        fixer, "_resolve_fix_handler", lambda cid: lambda ctx, r: FixOutcome(True, "executed")
    )
    monkeypatch.setattr(
        m.MaintenanceChecks, "run", lambda self, context, ids: [finding(cid, verified=False)]
    )
    report = fixer.apply(ScanReport(profile="system", results=[finding(cid, **details)]), context)
    assert report.results[0].severity == Severity.WARN
    assert not report.results[0].details.get("auto_fixed")
    assert prompts == [False]


def test_integrity_reinstall_occurs_in_a_full_upgrade(monkeypatch, environment, context):
    fixer = InteractiveAutoFixer(Console(file=io.StringIO()))
    outcome = fixer._fix_maintenance(context, finding("sys.integrity", reinstall_packages=["bash"]))
    assert outcome.changed
    assert ["sudo", "pacman", "-Syu", "--noconfirm", "--", "bash"] in environment
    assert all("-S" not in cmd for cmd in environment)


def test_unconfigured_backup_does_not_offer_a_nonexistent_fix(monkeypatch, environment, context):
    monkeypatch.setattr(s.SystemDryRunService, "build_tasks", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        s.SystemDryRunService,
        "run_with_progress",
        lambda *args, **kwargs: ScanReport(
            profile="system", results=[m.MaintenanceChecks().backup()]
        ),
    )
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 0
    assert "backup is not configured" in result.stdout
    assert "Apply fixes" not in result.stdout


@pytest.mark.parametrize("code", [1, 2, 3])
def test_default_cli_propagates_failed_update(monkeypatch, environment, code):
    monkeypatch.setattr(s.SystemDryRunService, "build_tasks", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        s.SystemDryRunService,
        "run_with_progress",
        lambda *args, **kwargs: ScanReport(
            profile="system", results=[finding("sys.packages", Severity.OUTD)]
        ),
    )
    monkeypatch.setattr(s.SystemUpgradeService, "run", lambda *args: code)
    result = CliRunner().invoke(app, [], input="y\n")
    assert result.exit_code == code


def test_old_package_checker_empty_error_is_not_pass(monkeypatch, environment, context):
    monkeypatch.setattr(s.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        s,
        "_run_capture",
        lambda *args, **kwargs: s._ExecResult(
            SimpleNamespace(returncode=1, stdout="", stderr="network error")
        ),
    )
    assert s.SystemDryRunService()._check_arch_packages(context).severity == Severity.FAIL


def test_feed_reader_validates_items_without_writing_state(monkeypatch, environment):
    payload = b"<rss><channel><item><title>Change</title><link>https://archlinux.org/news/change/</link></item></channel></rss>"
    monkeypatch.setattr(readers.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(payload))
    assert readers.fetch_news() == [
        {"title": "Change", "url": "https://archlinux.org/news/change/"}
    ]
    assert not readers.MaintenanceState().path.exists()


@pytest.mark.parametrize("payload", [b"broken", b"<rss><channel/></rss>", b"<html/>"])
def test_invalid_feed_cannot_become_clean_news(monkeypatch, environment, payload):
    monkeypatch.setattr(readers.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(payload))
    with pytest.raises((ValueError, readers.ElementTree.ParseError)):
        readers.fetch_news()


def test_cache_cleanup_cannot_hide_remaining_disk_pressure(monkeypatch, environment, context):
    fixer = InteractiveAutoFixer(Console(file=io.StringIO()))
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(fixer, "_fix_sys_disk", lambda ctx, result: FixOutcome(True, "cleaned"))
    monkeypatch.setattr(
        s.SystemDryRunService,
        "run",
        lambda *args, **kwargs: ScanReport(
            profile="system", results=[finding("sys.disk", Severity.FAIL)]
        ),
    )
    report = fixer.apply(ScanReport(profile="system", results=[finding("sys.disk")]), context)
    assert report.results[0].severity == Severity.FAIL
    assert "auto_fixed" not in report.results[0].details


@pytest.mark.parametrize("recheck", [[], [finding("sys.rebuild", verified=False)]])
def test_unknown_rebuild_recheck_is_not_success(monkeypatch, environment, context, recheck):
    service = upgrade()
    service._aur_helper_fn = lambda: "paru"
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(service, "_run_step", lambda *args: (False, False, True))
    monkeypatch.setattr(m.MaintenanceChecks, "run", lambda *args: recheck)
    assert not service._offer_rebuilds(
        finding("sys.rebuild", rebuild_packages=["custom"]), context, Console(file=io.StringIO())
    )


@pytest.mark.parametrize(
    "cmd",
    [
        ["sudo", "pacman", "-Sy", "--needed", "archlinux-keyring"],
        ["sudo", "pacman", "-Su"],
        ["paru", "-S", "--rebuild", "yes", "--", "custom"],
    ],
)
def test_package_review_prompts_inherit_the_terminal(monkeypatch, environment, cmd):
    options = []

    def run(command, **kwargs):
        options.append(kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(s.subprocess, "run", run)
    error, _, changed = upgrade()._run_step(cmd, Console(file=io.StringIO()), "Review transaction")
    assert not error
    assert changed
    assert options == [{"check": False}]


@pytest.mark.parametrize("helper,flags", [("paru", ["--rebuild", "yes"]), ("yay", ["--rebuild"])])
def test_rebuild_uses_helper_specific_flags(monkeypatch, environment, context, helper, flags):
    service = upgrade()
    service._aur_helper_fn = lambda: helper
    commands = []
    monkeypatch.setattr(s.typer, "confirm", lambda *args, **kwargs: True)

    def step(cmd, *args):
        commands.append(cmd)
        return False, False, True

    monkeypatch.setattr(service, "_run_step", step)
    monkeypatch.setattr(
        m.MaintenanceChecks, "run", lambda *args: [finding("sys.rebuild", Severity.PASS)]
    )
    assert service._offer_rebuilds(
        finding("sys.rebuild", rebuild_packages=["custom"]), context, Console(file=io.StringIO())
    )
    assert commands == [[helper, "-S", *flags, "--", "custom"]]
