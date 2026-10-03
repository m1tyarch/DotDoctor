import io
from pathlib import Path
from unittest.mock import MagicMock

from rich.console import Console

from dotdoctor.application.system_update import detect_disk_space_status
from dotdoctor.cli.render import (
    _status_label,
    _status_style,
    format_summary,
    render_terminal_report,
)
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure.checks.registry import normalize_check_id, resolve_checks


def test_status_label_outd_mapped_to_old() -> None:
    assert _status_label(Severity.OUTD) == "OLD"
    assert _status_label(Severity.PASS) == "PASS"
    assert _status_label(Severity.WARN) == "WARN"
    assert _status_label(Severity.FAIL) == "FAIL"


def test_status_styles() -> None:
    assert _status_style(Severity.PASS) == "dim green"
    assert _status_style(Severity.OUTD) == "bold cyan"
    assert _status_style(Severity.WARN) == "bold yellow"
    assert _status_style(Severity.FAIL) == "bold red"


def test_summary_all_passed() -> None:
    text_10 = format_summary({"PASS": 10, "OUTD": 0, "WARN": 0, "FAIL": 0})
    assert text_10.plain == "All 10 checks passed"

    text_1 = format_summary({"PASS": 1, "OUTD": 0, "WARN": 0, "FAIL": 0})
    assert text_1.plain == "All 1 check passed"

    # Interim rolling states with all_passed=True show 'All' prefix immediately
    text_rolling_0 = format_summary(
        {"PASS": 0, "OUTD": 0, "WARN": 0, "FAIL": 0},
        is_final=False,
        all_passed=True,
        total_target=10,
    )
    assert text_rolling_0.plain == "All 0 checks passed"

    text_rolling_5 = format_summary(
        {"PASS": 5, "OUTD": 0, "WARN": 0, "FAIL": 0},
        is_final=False,
        all_passed=True,
        total_target=10,
    )
    assert text_rolling_5.plain == "All 5 checks passed"


def test_summary_mixed_nonzero_only() -> None:
    text = format_summary({"PASS": 9, "OUTD": 0, "WARN": 1, "FAIL": 1})
    assert text.plain == "9 passed · 1 warning · 1 failed"
    assert "outdated" not in text.plain
    assert "0" not in text.plain

    # Verify colors of spans
    spans = {text.plain[span.start : span.end]: span.style for span in text.spans}
    assert spans.get("1 warning") == "yellow"
    assert spans.get("1 failed") == "red"

    # Outdated plural and singular
    text_outd = format_summary({"PASS": 5, "OUTD": 2, "WARN": 0, "FAIL": 0})
    assert text_outd.plain == "5 passed · 2 outdated"
    spans_outd = {text_outd.plain[span.start : span.end]: span.style for span in text_outd.spans}
    assert spans_outd.get("2 outdated") == "cyan"


def test_render_light_list_no_headers_no_frames() -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.packages",
                severity=Severity.PASS,
                message="up to date",
                remediation="should not show",
            ),
            CheckResult(
                check_id="sys.disk",
                severity=Severity.WARN,
                message="low disk space",
                remediation="clean package caches (paccache -r)",
            ),
            CheckResult(
                check_id="sys.firmware",
                severity=Severity.OUTD,
                message="1 update available",
                remediation="fwupdmgr update",
            ),
            CheckResult(
                check_id="sys.network",
                severity=Severity.FAIL,
                message="offline",
                remediation="check network connection",
            ),
        ],
        summary={"PASS": 1, "OUTD": 1, "WARN": 1, "FAIL": 1},
        duration_ms=42.0,
    )

    render_terminal_report(report, console)
    rendered = output.getvalue()

    # Header check
    assert "DotDoctor · system\n\n" in rendered
    # No table frames
    assert "┌" not in rendered and "│" not in rendered and "┼" not in rendered
    assert "Check ID" not in rendered  # no column header

    lines = rendered.splitlines()
    # Line format: 2 spaces, status, 2 spaces, check_id, 2 spaces, message
    # max_status_len = 4 (PASS, WARN, FAIL, OLD)
    # max_id_len = len("sys.packages") = 12
    # prefix = 2 + 4 + 2 + 12 + 2 = 22 spaces
    pass_line = [line for line in lines if "sys.packages" in line][0]
    assert pass_line.startswith("  PASS  sys.packages  up to date")
    # PASS lines must NOT show remediation
    assert "should not show" not in rendered

    # Non-PASS remediation on second line prefixed with fix:
    warn_line_idx = next(i for i, line in enumerate(lines) if "sys.disk" in line)
    assert lines[warn_line_idx].startswith("  WARN  sys.disk      low disk space")
    expected_warn_fix = "                      fix: clean package caches (paccache -r)"
    assert lines[warn_line_idx + 1].startswith(expected_warn_fix)

    # Status OLD for OUTD
    old_line_idx = next(i for i, line in enumerate(lines) if "sys.firmware" in line)
    assert lines[old_line_idx].startswith("  OLD   sys.firmware  1 update available")
    assert lines[old_line_idx + 1].startswith("                      fix: fwupdmgr update")

    # Fail remediation
    fail_line_idx = next(i for i, line in enumerate(lines) if "sys.network" in line)
    assert lines[fail_line_idx].startswith("  FAIL  sys.network   offline")
    expected_fail_fix = "                      fix: check network connection"
    assert lines[fail_line_idx + 1].startswith(expected_fail_fix)

    # Summary
    assert "1 passed · 1 outdated · 1 warning · 1 failed" in lines[-1]


def test_render_hanging_indent_wrapping_at_80_and_60_cols() -> None:
    long_msg = (
        "this is a very long message that definitely needs to wrap "
        "across multiple lines in the terminal"
    )
    long_rem = (
        "this is a very long remediation recommendation that also needs to wrap "
        "properly across multiple lines"
    )

    report = ScanReport(
        profile="dev",
        results=[
            CheckResult(
                check_id="path.integrity",
                severity=Severity.WARN,
                message=long_msg,
                remediation=long_rem,
            )
        ],
        summary={"PASS": 0, "OUTD": 0, "WARN": 1, "FAIL": 0},
        duration_ms=10.0,
    )

    for width in (80, 60):
        output = io.StringIO()
        console = Console(file=output, width=width, color_system=None)
        render_terminal_report(report, console)
        rendered = output.getvalue()
        lines = rendered.splitlines()

        # Prefix len for check_id 'path.integrity' (14) + status 'WARN' (4) + 6 = 24
        prefix_len = 2 + 4 + 2 + 14 + 2
        indent = " " * prefix_len

        for line in lines:
            assert len(line) <= width, f"Line exceeded width {width}: '{line}'"

        # Check continuation lines of message have hanging indent
        assert lines[2].startswith("  WARN  path.integrity  ")
        assert lines[3].startswith(indent)

        # Check fix lines have hanging indent
        fix_lines = [item for item in lines if "fix:" in item]
        assert len(fix_lines) >= 1
        assert fix_lines[0].startswith(f"{indent}fix: ")


def test_render_no_ansi_when_no_color() -> None:
    output = io.StringIO()
    # force no_color
    console = Console(file=output, width=80, no_color=True)

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.packages",
                severity=Severity.PASS,
                message="up to date",
            ),
            CheckResult(
                check_id="sys.disk",
                severity=Severity.WARN,
                message="low space",
                remediation="clean cache",
            ),
        ],
        summary={"PASS": 1, "OUTD": 0, "WARN": 1, "FAIL": 0},
        duration_ms=15.0,
    )

    render_terminal_report(report, console)
    rendered = output.getvalue()
    assert "\x1b[" not in rendered


def test_detect_disk_space_same_fs_merged(monkeypatch, tmp_path: Path) -> None:
    # When root and boot have identical st_dev
    fake_stat_root = MagicMock()
    fake_stat_root.st_dev = 42
    fake_stat_boot = MagicMock()
    fake_stat_boot.st_dev = 42

    monkeypatch.setattr(
        Path,
        "stat",
        lambda self: fake_stat_root if str(self) == "/" else fake_stat_boot,
    )

    status = detect_disk_space_status(
        root_path=Path("/"),
        boot_path=Path("/boot"),
        min_root_warn_bytes=100,
        min_root_crit_bytes=10,
        min_boot_warn_bytes=100,
        min_boot_crit_bytes=10,
    )
    assert "free on / and /boot" in status.message


def test_detect_disk_space_diff_fs_separated(monkeypatch, tmp_path: Path) -> None:
    # When root and boot have different st_dev
    fake_stat_root = MagicMock()
    fake_stat_root.st_dev = 1
    fake_stat_boot = MagicMock()
    fake_stat_boot.st_dev = 2

    def mock_stat(self):
        if str(self) == "/":
            return fake_stat_root
        return fake_stat_boot

    monkeypatch.setattr(Path, "stat", mock_stat)

    status = detect_disk_space_status(
        root_path=Path("/"),
        boot_path=Path("/boot"),
        min_root_warn_bytes=100,
        min_root_crit_bytes=10,
        min_boot_warn_bytes=100,
        min_boot_crit_bytes=10,
    )
    assert "/ " in status.message and "/boot " in status.message
    assert " · " in status.message


def test_legacy_check_id_normalization_and_resolution() -> None:
    assert normalize_check_id("sys:packages") == "sys.packages"
    assert normalize_check_id("sys.packages") == "sys.packages"
    assert normalize_check_id("path:integrity") == "path.integrity"

    from dotdoctor.domain.config import ProfileConfig

    # resolve_checks with legacy enabled_checks and disabled_checks
    profile = ProfileConfig(
        enabled_checks=["path:integrity", "shell.config"],
    )
    checks = resolve_checks(
        profile=profile,
        disabled_checks={"path:integrity"},
    )
    check_ids = [c.check_id for c in checks]
    assert "path.integrity" not in check_ids
    assert "shell.config" in check_ids

    # ScanReport.get_result supports both forms
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="sys.packages", severity=Severity.PASS, message="ok"),
        ],
        summary={"PASS": 1, "OUTD": 0, "WARN": 0, "FAIL": 0},
    )
    assert report.get_result("sys.packages") is not None
    assert report.get_result("sys:packages") is not None
    assert report.get_result("sys:packages").message == "ok"


def test_render_terminal_report_animation_enabled(monkeypatch) -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="sys.packages", severity=Severity.PASS, message="ok"),
            CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="1 orphan",
                remediation="clean it",
            ),
        ],
        summary={"PASS": 1, "OUTD": 0, "WARN": 1, "FAIL": 0},
    )

    sleeps: list[float] = []
    monkeypatch.setattr("dotdoctor.cli.render._sleep", lambda sec: sleeps.append(sec))

    render_terminal_report(report, console, animate=True, delay=0.01, summary_delay=0.02)

    # 3 sleeps for item lines + 7 sleeps for rolling summary count-up (1 initial + 6 steps)
    assert len(sleeps) == 10
    assert sleeps[:3] == [0.01, 0.01, 0.01]
    assert sleeps[3:] == [0.02] * 7


def test_render_terminal_report_animation_disabled_by_default_non_terminal(monkeypatch) -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)
    assert not console.is_terminal

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="sys.packages", severity=Severity.PASS, message="ok"),
        ],
        summary={"PASS": 1, "OUTD": 0, "WARN": 0, "FAIL": 0},
    )

    sleeps: list[float] = []
    monkeypatch.setattr("dotdoctor.cli.render._sleep", lambda sec: sleeps.append(sec))

    render_terminal_report(report, console)
    assert len(sleeps) == 0


def test_render_terminal_report_animation_disabled_by_env(monkeypatch) -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)
    monkeypatch.setattr(Console, "is_terminal", property(lambda self: True))
    monkeypatch.setenv("NO_ANIMATION", "1")

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="sys.packages", severity=Severity.PASS, message="ok"),
        ],
        summary={"PASS": 1, "OUTD": 0, "WARN": 0, "FAIL": 0},
    )

    sleeps: list[float] = []
    monkeypatch.setattr("dotdoctor.cli.render._sleep", lambda sec: sleeps.append(sec))

    render_terminal_report(report, console)
    assert len(sleeps) == 0


def test_render_terminal_report_animation_all_passed(monkeypatch) -> None:
    from rich.live import Live

    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="sys.packages", severity=Severity.PASS, message="ok"),
            CheckResult(check_id="sys.disk", severity=Severity.PASS, message="ok"),
        ],
        summary={"PASS": 2, "OUTD": 0, "WARN": 0, "FAIL": 0},
    )

    updates: list[str] = []
    original_live_update = Live.update

    def intercept_update(self, renderable):
        if hasattr(renderable, "plain"):
            updates.append(renderable.plain)
        return original_live_update(self, renderable)

    monkeypatch.setattr(Live, "update", intercept_update)
    monkeypatch.setattr("dotdoctor.cli.render._sleep", lambda sec: None)

    render_terminal_report(report, console, animate=True, delay=0.01, summary_delay=0.02)

    # Every update frame should start with "All " and end with "checks passed"
    assert len(updates) > 0
    for u in updates:
        assert u.startswith("All ")
        assert u.endswith("checks passed")
    assert updates[-1] == "All 2 checks passed"
