"""Update-followup reports use mocked services and never execute system commands."""

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from dotdoctor.application import system_update as updates
from dotdoctor.application.auto_fix import InteractiveAutoFixer
from dotdoctor.application.system_update import SystemDryRunService, SystemUpgradeService
from dotdoctor.cli.app import app
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


@pytest.fixture
def flow(monkeypatch):
    state = SimpleNamespace(
        initial=ScanReport(
            profile="system",
            results=[
                CheckResult(check_id="sys.packages", severity=Severity.OUTD, message="21 updates"),
                CheckResult(check_id="sys.orphans", severity=Severity.PASS, message="no orphans"),
            ],
        ),
        fresh=ScanReport(profile="system", results=[]),
        upgrades=0,
        rescans=0,
        fixes=[],
    )

    def initial(*args, **kwargs):
        return state.initial

    def rescan(*args, **kwargs):
        state.rescans += 1
        return state.fresh

    def upgrade(self, context, console):
        state.upgrades += 1
        console.print("All updates completed successfully.")
        return 0

    def fix(self, report, context):
        state.fixes.append(report)
        return report

    monkeypatch.setattr(SystemDryRunService, "build_tasks", lambda *args, **kwargs: [])
    monkeypatch.setattr(SystemDryRunService, "run_with_progress", initial)
    monkeypatch.setattr(SystemDryRunService, "run", rescan)
    monkeypatch.setattr(SystemUpgradeService, "run", upgrade)
    monkeypatch.setattr(InteractiveAutoFixer, "apply", fix)
    return state


def test_new_orphans_are_displayed_before_fix_offer(flow):
    flow.fresh.results = [
        CheckResult(check_id="sys.packages", severity=Severity.PASS, message="up to date"),
        CheckResult(
            check_id="sys.orphans",
            severity=Severity.WARN,
            message="2 orphan packages found after updating",
            remediation="dotdoctor --fix",
            details={"orphans": ["libfoo", "libbar"]},
        ),
    ]
    result = CliRunner().invoke(app, [], input="y\ny\n")
    assert result.exit_code == 0
    output = result.output
    assert output.index("All updates completed") < output.index("Post-update findings:")
    assert output.index("Post-update findings:") < output.index(
        "2 orphan packages found after updating"
    )
    assert output.index("2 orphan packages found after updating") < output.index(
        "Apply fixes for detected issues"
    )
    assert "fix: dotdoctor --fix" in output
    assert flow.upgrades == flow.rescans == 1
    assert flow.fixes == [flow.fresh]


@pytest.mark.parametrize("severity", [Severity.PASS, Severity.SKIP, Severity.OUTD])
def test_clean_or_neutral_rescan_never_offers_fixes(flow, severity):
    # Even an initially actionable issue must not survive the fresh report.
    flow.initial.results[1] = CheckResult(
        check_id="sys.orphans", severity=Severity.WARN, message="initial orphan finding"
    )
    flow.fresh.results = [
        CheckResult(check_id="sys.orphans", severity=severity, message="fresh result")
    ]
    result = CliRunner().invoke(app, [], input="y\n")
    assert result.exit_code == 0
    assert "Apply fixes" not in result.output
    assert "Post-update findings:" not in result.output
    assert flow.upgrades == flow.rescans == 1
    assert flow.fixes == []


@pytest.mark.parametrize("severity", [Severity.WARN, Severity.FAIL])
def test_manual_findings_are_shown_without_fix_offer(flow, severity):
    flow.fresh.results = [
        CheckResult(
            check_id="sys.services",
            severity=severity,
            message="example.service failed",
            remediation="systemctl status example.service",
        )
    ]
    result = CliRunner().invoke(app, [], input="y\n")
    assert result.exit_code == flow.fresh.exit_code
    assert "Post-update findings:" in result.output
    assert "example.service failed" in result.output
    assert "systemctl status example.service" in result.output
    assert "Apply fixes" not in result.output
    assert flow.fixes == []


def test_declining_fixes_keeps_fresh_findings_in_json(flow, tmp_path):
    flow.fresh.results = [
        CheckResult(
            check_id="sys.reboot",
            severity=Severity.WARN,
            message="new kernel requires reboot",
            remediation="systemctl reboot",
        ),
        CheckResult(check_id="sys.timers", severity=Severity.SKIP, message="history unavailable"),
    ]
    path = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["--json-output", str(path)], input="y\nn\n")
    assert result.exit_code == 0
    assert result.output.index("new kernel requires reboot") < result.output.index("Apply fixes")
    assert "history unavailable" not in result.output
    assert flow.fixes == []
    assert json.loads(path.read_text()) == flow.fresh.model_dump(mode="json")


@pytest.mark.parametrize("kernel_changed", [False, True])
def test_reboot_followup_uses_actual_kernel_state_not_pending_package_names(
    monkeypatch, flow, tmp_path, kernel_changed
):
    modules = tmp_path / "modules"
    modules.mkdir()
    (modules / "7.2.9-arch1-1").mkdir()
    detect = updates.detect_reboot_status
    monkeypatch.setattr(
        updates,
        "detect_reboot_status",
        lambda: detect(modules_dir=modules, running_kernel="7.2.9-arch1-1", marker_paths=()),
    )
    monkeypatch.setattr(updates.shutil, "which", lambda name: f"/bin/{name}")
    package = "linux" if kernel_changed else "mesa"
    package_output = f"{package} 1.0-1 -> 1.0-2\n"
    if not kernel_changed:
        package_output += "vulkan-intel 1.0-1 -> 1.0-2\n"
    monkeypatch.setattr(
        updates,
        "_run_capture",
        lambda *a, **kw: updates._ExecResult(
            SimpleNamespace(returncode=0, stdout=package_output, stderr="")
        ),
    )
    checker = updates.SystemDryRunService(is_online_fn=lambda: True)
    context = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    flow.initial.results = [checker._check_arch_packages(context), checker._check_reboot(context)]

    def upgrade(self, ctx, console):
        flow.upgrades += 1
        if kernel_changed:
            (modules / "7.2.9-arch1-1").rmdir()
            (modules / "7.2.10-arch1-1").mkdir()
        console.print("All updates completed successfully.")
        return 0

    def rescan(*args, **kwargs):
        flow.rescans += 1
        flow.fresh = ScanReport(profile="system", results=[checker._check_reboot(context)])
        return flow.fresh

    monkeypatch.setattr(SystemUpgradeService, "run", upgrade)
    monkeypatch.setattr(SystemDryRunService, "run", rescan)
    result = CliRunner().invoke(app, [], input="y\nn\n")
    assert result.exit_code == 0
    assert "Critical updates" not in result.output
    assert "reboot will be recommended" not in result.output
    assert "available (reboot required" not in result.output
    assert ("Apply fixes" in result.output) is kernel_changed
    assert flow.fresh.results[0].details["reboot_required"] is kernel_changed
    if kernel_changed:
        assert "7.2.10-arch1-1" in result.output
        assert "fix: systemctl reboot" in result.output
        assert result.output.index("reboot required:") < result.output.index("Apply fixes")
    else:
        assert "reboot required:" not in result.output
