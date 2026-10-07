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
from dotdoctor.domain.models import CheckResult, ScanReport, Severity, normalize_check_id


def test_status_label_outd_mapped_to_old() -> None:
    assert _status_label(Severity.OUTD) == "OLD"
    assert _status_label(Severity.PASS) == "PASS"
    assert _status_label(Severity.WARN) == "WARN"
    assert _status_label(Severity.FAIL) == "FAIL"


def test_status_styles() -> None:
    assert _status_style(Severity.PASS) == "dim green"
    assert _status_style(Severity.OUTD) == "cyan"
    assert _status_style(Severity.WARN) == "yellow"
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


def test_legacy_check_id_normalization() -> None:
    assert normalize_check_id("sys:packages") == "sys.packages"
    assert normalize_check_id("sys.packages") == "sys.packages"

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


def test_render_terminal_report_instant_rendering() -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)

    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.packages",
                severity=Severity.PASS,
                message="all good",
            ),
            CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="1 orphan",
                remediation="clean it",
            ),
        ],
        summary={"PASS": 1, "OUTD": 0, "WARN": 1, "FAIL": 0},
    )

    render_terminal_report(report, console)
    out = output.getvalue()
    assert "sys.packages" in out
    assert "sys.orphans" in out
    assert "1 passed · 1 warning" in out


def test_render_terminal_report_packages_default_truncation() -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)

    pkgs = [
        "linux 6.10.1 -> 6.10.2",
        "vim 9.1.0 -> 9.1.1",
        "git 2.45.0 -> 2.45.1",
        "htop 3.3.0 -> 3.3.1",
        "zsh 5.9 -> 5.10",
    ]
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.packages",
                severity=Severity.OUTD,
                message="5 updates available (reboot required: linux)",
                remediation="run dotdoctor --sysup",
                details={"packages": pkgs, "critical": ["linux"]},
            )
        ],
        summary={"PASS": 0, "OUTD": 1, "WARN": 0, "FAIL": 0},
    )

    render_terminal_report(report, console, verbose=False)
    rendered = output.getvalue()

    assert "• linux 6.10.1 -> 6.10.2" in rendered
    assert "• vim 9.1.0 -> 9.1.1" in rendered
    assert "• git 2.45.0 -> 2.45.1" in rendered
    assert "• (2 more packages, use -v to show all)" in rendered
    assert "• htop" not in rendered
    assert "• zsh" not in rendered


def test_render_terminal_report_packages_verbose() -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)

    pkgs = [
        "linux 6.10.1 -> 6.10.2",
        "vim 9.1.0 -> 9.1.1",
        "git 2.45.0 -> 2.45.1",
        "htop 3.3.0 -> 3.3.1",
        "zsh 5.9 -> 5.10",
    ]
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.packages",
                severity=Severity.OUTD,
                message="5 updates available",
                remediation="run dotdoctor --sysup",
                details={"packages": pkgs},
            )
        ],
        summary={"PASS": 0, "OUTD": 1, "WARN": 0, "FAIL": 0},
    )

    render_terminal_report(report, console, verbose=True)
    rendered = output.getvalue()

    assert "• linux 6.10.1 -> 6.10.2" in rendered
    assert "• vim 9.1.0 -> 9.1.1" in rendered
    assert "• git 2.45.0 -> 2.45.1" in rendered
    assert "• htop 3.3.0 -> 3.3.1" in rendered
    assert "• zsh 5.9 -> 5.10" in rendered
    assert "use -v to show all" not in rendered


def test_render_terminal_report_packages_singular_omitted() -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, color_system=None)

    pkgs = [
        "pkg1 1.0 -> 1.1",
        "pkg2 1.0 -> 1.1",
        "pkg3 1.0 -> 1.1",
        "pkg4 1.0 -> 1.1",
    ]
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(
                check_id="sys.packages",
                severity=Severity.OUTD,
                message="4 updates available",
                details={"packages": pkgs},
            )
        ],
        summary={"PASS": 0, "OUTD": 1, "WARN": 0, "FAIL": 0},
    )

    render_terminal_report(report, console, verbose=False)
    rendered = output.getvalue()

    assert "• (1 more package, use -v to show all)" in rendered
