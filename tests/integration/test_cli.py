from pathlib import Path

from typer.testing import CliRunner

from dotdoctor.cli.app import app
from dotdoctor.domain.models import CheckResult, ScanReport, Severity

runner = CliRunner()


def test_root_default_runs_dry_run_report(monkeypatch) -> None:
    def fake_run(self, context, on_task_complete=None):
        if on_task_complete:
            on_task_complete("sys.packages")
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.OUTD,
                    message="2 updates available",
                    remediation="dotdoctor --sysup",
                )
            ],
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )
    monkeypatch.setattr("dotdoctor.application.system_update.SystemDryRunService.run", fake_run)

    result = runner.invoke(app, [], input="n\n")

    assert result.exit_code == 0
    assert "DotDoctor · system" in result.stdout
    assert "sys.packages" in result.stdout


def test_root_sysup_runs_upgrade(monkeypatch) -> None:
    upgraded = []

    def fake_upgrade(self, context, console):
        upgraded.append(True)
        console.print("Upgrade completed successfully.")
        return 0

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemUpgradeService.run", fake_upgrade
    )

    result = runner.invoke(app, ["--sysup"])
    assert result.exit_code == 0
    assert upgraded == [True]
    assert "DotDoctor · system update" in result.stdout


def test_root_fix_runs_system_auto_fix(monkeypatch) -> None:
    called_fix = []

    def fake_run(self, context, on_task_complete=None):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.orphans",
                    severity=Severity.WARN,
                    message="2 orphan packages found",
                    details={"orphans": ["pkg1", "pkg2"]},
                )
            ],
        )

    def fake_apply(self, report, context):
        called_fix.append(report)
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.orphans",
                    severity=Severity.PASS,
                    message="Auto-fixed: Removed 2 orphan packages.",
                )
            ],
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.InteractiveAutoFixer.apply", fake_apply)

    result = runner.invoke(app, ["--fix"])

    assert result.exit_code == 0
    assert len(called_fix) == 1
    assert "sys.orphans" in result.stdout


def test_root_conflicting_options() -> None:
    result = runner.invoke(app, ["--fix", "--sysup"])
    assert result.exit_code != 0
    assert "Use either --sysup or --fix, not both." in result.output


def test_root_prompts_update_everything_when_outd(monkeypatch) -> None:
    upgraded = []

    def fake_run(self, context, on_task_complete=None):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.OUTD,
                    message="3 updates available",
                )
            ],
        )

    def fake_upgrade(self, context, console):
        upgraded.append(True)
        console.print("Upgrade completed successfully.")
        return 0

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )
    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemUpgradeService.run", fake_upgrade
    )

    result = runner.invoke(app, [], input="y\n")

    assert result.exit_code == 0
    assert upgraded == [True]


def test_root_prompts_fixes_when_issues_detected(monkeypatch) -> None:
    fixed = []

    def fake_run(self, context, on_task_complete=None):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.cache",
                    severity=Severity.WARN,
                    message="5.0 GiB in pacman cache",
                )
            ],
        )

    def fake_apply(self, report, context):
        fixed.append(True)
        return report

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.InteractiveAutoFixer.apply", fake_apply)

    result = runner.invoke(app, [], input="y\n")

    assert result.exit_code == 0
    assert fixed == [True]


def test_root_chains_updates_and_fixes(monkeypatch) -> None:
    actions = []

    def fake_run(self, context, on_task_complete=None):
        return ScanReport(
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
                ),
            ],
        )

    def fake_upgrade(self, context, console):
        actions.append("upgrade")
        return 0

    def fake_apply(self, report, context):
        actions.append("fix")
        return report

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )
    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemUpgradeService.run", fake_upgrade
    )
    monkeypatch.setattr("dotdoctor.application.auto_fix.InteractiveAutoFixer.apply", fake_apply)

    result = runner.invoke(app, [], input="y\ny\n")

    assert result.exit_code == 0
    assert actions == ["upgrade", "fix"]


def test_root_critical_update_warning(monkeypatch) -> None:
    def fake_run(self, context):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.OUTD,
                    message="1 update available (reboot required: linux)",
                    details={"critical": ["linux"], "packages": ["linux 6.10.1 -> 6.10.2"]},
                )
            ],
            summary={"PASS": 0, "OUTD": 1, "WARN": 0, "FAIL": 0},
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )

    result = runner.invoke(app, [], input="n\n")
    assert result.exit_code == 0
    assert "Note: Critical updates detected (linux) — reboot will be recommended." in result.stdout
    assert "Update everything now?" in result.stdout


def test_root_verbose_shows_all_packages(monkeypatch) -> None:
    pkgs = [f"pkg{i} 1.0 -> 1.1" for i in range(5)]

    def fake_run(self, context):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.OUTD,
                    message="5 updates available",
                    details={"packages": pkgs},
                )
            ],
            summary={"PASS": 0, "OUTD": 1, "WARN": 0, "FAIL": 0},
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )

    # Without verbose: truncated
    result_normal = runner.invoke(app, [], input="n\n")
    assert result_normal.exit_code == 0
    assert "• (2 more packages, use -v to show all)" in result_normal.stdout

    # With verbose (-v): shows all
    result_verbose = runner.invoke(app, ["-v"], input="n\n")
    assert result_verbose.exit_code == 0
    assert "• pkg4 1.0 -> 1.1" in result_verbose.stdout
    assert "use -v to show all" not in result_verbose.stdout


def test_root_disable_check(monkeypatch) -> None:
    captured_disabled = []

    def fake_run(self, context, on_task_complete=None, disabled_checks=None):
        captured_disabled.append(disabled_checks)
        return ScanReport(profile="system", results=[])

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )

    result = runner.invoke(app, ["--disable-check", "sys.cache"])
    assert result.exit_code == 0
    assert captured_disabled == [["sys.cache"]]


def test_root_with_config_file(monkeypatch, tmp_path: Path) -> None:
    config_file = tmp_path / "config.yml"
    config_file.write_text("disabled_checks: [sys.pacnew]\n", encoding="utf-8")

    captured_disabled = []

    def fake_run(self, context, on_task_complete=None, disabled_checks=None):
        captured_disabled.append(disabled_checks)
        return ScanReport(profile="system", results=[])

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )

    result = runner.invoke(app, ["--config", str(config_file)])
    assert result.exit_code == 0
    assert "sys.pacnew" in captured_disabled[0]


def test_root_json_output(monkeypatch, tmp_path: Path) -> None:
    def fake_run(self, context, on_task_complete=None):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.PASS,
                    message="up to date",
                )
            ],
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )

    out_file = tmp_path / "report.json"
    result = runner.invoke(app, ["--json-output", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()
    assert '"sys.packages"' in out_file.read_text(encoding="utf-8")


def test_root_refreshes_report_after_sysup(monkeypatch) -> None:
    call_count = [0]
    fixed_applied = []

    def fake_run_progress(self, context, on_task_complete=None):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.OUTD,
                    message="1 update available",
                ),
                CheckResult(
                    check_id="sys.cache",
                    severity=Severity.WARN,
                    message="cache needs cleaning",
                ),
            ],
        )

    def fake_upgrade(self, context, console):
        return 0

    def fake_run_refreshed(self, context, disabled_checks=None):
        call_count[0] += 1
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.PASS,
                    message="up to date",
                ),
                CheckResult(
                    check_id="sys.cache",
                    severity=Severity.PASS,
                    message="clean",
                ),
            ],
        )

    def fake_apply(self, report, context):
        fixed_applied.append(True)
        return report

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run_progress,
    )
    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run",
        fake_run_refreshed,
    )
    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemUpgradeService.run",
        fake_upgrade,
    )
    monkeypatch.setattr(
        "dotdoctor.application.auto_fix.InteractiveAutoFixer.apply",
        fake_apply,
    )

    result = runner.invoke(app, [], input="y\n")
    assert result.exit_code == 0
    assert call_count[0] == 1
    assert fixed_applied == []


def test_main_keyboard_interrupt_clean_exit(monkeypatch) -> None:
    import pytest

    from dotdoctor import main

    def fake_app():
        raise KeyboardInterrupt()

    monkeypatch.setattr("dotdoctor.cli.app.app", fake_app)

    with pytest.raises(SystemExit) as exc_info:
        main.run()
    assert exc_info.value.code == 130


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "dotdoctor" in result.stdout
