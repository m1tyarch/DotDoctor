from dotdoctor.domain.models import CheckResult, ScanReport, Severity


def test_scan_report_summary_and_exit_code_warn() -> None:
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="a", severity=Severity.PASS, message="ok"),
            CheckResult(check_id="b", severity=Severity.WARN, message="warn"),
        ],
    )

    assert report.summary == {"PASS": 1, "OUTD": 0, "WARN": 1, "FAIL": 0, "SKIP": 0}
    assert report.exit_code == 0


def test_scan_report_exit_code_fail_takes_priority() -> None:
    report = ScanReport(
        profile="system",
        results=[CheckResult(check_id="x", severity=Severity.FAIL, message="fail")],
    )

    assert report.exit_code == 2


def test_neutral_results_are_counted_without_claiming_success_or_failure() -> None:
    report = ScanReport(
        profile="system",
        results=[
            CheckResult(check_id="a", severity=Severity.PASS, message="ok"),
            CheckResult(
                check_id="b",
                severity=Severity.SKIP,
                message="history unavailable",
                details={"verified": False},
            ),
        ],
    )
    assert report.summary == {"PASS": 1, "OUTD": 0, "WARN": 0, "FAIL": 0, "SKIP": 1}
    assert report.exit_code == 0
    assert ScanReport.model_validate_json(report.model_dump_json()) == report
    report.results.append(CheckResult(check_id="c", severity=Severity.FAIL, message="failed"))
    assert report.exit_code == 2
