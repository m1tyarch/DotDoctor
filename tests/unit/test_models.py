from dotdoctor.domain.models import CheckResult, ScanReport, Severity


def test_scan_report_summary_and_exit_code_warn() -> None:
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="a", severity=Severity.PASS, message="ok"),
            CheckResult(check_id="b", severity=Severity.WARN, message="warn"),
        ],
    )

    assert report.summary == {"PASS": 1, "OUTD": 0, "WARN": 1, "FAIL": 0}
    assert report.exit_code == 0


def test_scan_report_exit_code_fail_takes_priority() -> None:
    report = ScanReport(
        profile="system",
        results=[CheckResult(check_id="x", severity=Severity.FAIL, message="fail")],
    )

    assert report.exit_code == 2
