import time
from pathlib import Path

from dotdoctor.application.use_cases import RunScanUseCase
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity


class BoomCheck:
    check_id = "boom"

    def run(self, context: ScanContext) -> CheckResult:
        raise RuntimeError("kaboom")


class SlowCheck:
    def __init__(self, check_id: str, delay: float) -> None:
        self.check_id = check_id
        self._delay = delay

    def run(self, context: ScanContext) -> CheckResult:
        time.sleep(self._delay)
        return CheckResult(
            check_id=self.check_id,
            severity=Severity.PASS,
            message=f"{self.check_id} completed",
        )


def _make_context() -> ScanContext:
    return ScanContext(
        profile="python-dev",
        cwd=Path.cwd(),
        home=Path.home(),
        path_value="/usr/bin",
        shell="/bin/zsh",
    )


def test_use_case_converts_unhandled_check_exception_to_fail() -> None:
    use_case = RunScanUseCase([BoomCheck()])
    context = _make_context()

    report = use_case.execute(context)

    assert report.results[0].severity is Severity.FAIL
    assert report.results[0].check_id == "boom"
    assert report.exit_code == 2


def test_use_case_empty_checks() -> None:
    use_case = RunScanUseCase([])
    context = _make_context()

    report = use_case.execute(context)
    assert report.results == []
    assert report.exit_code == 0
    assert list(use_case.execute_iter(context)) == []


def test_use_case_execute_preserves_order() -> None:
    # First check sleeps longer than subsequent checks
    checks = [
        SlowCheck("check.first", 0.05),
        SlowCheck("check.second", 0.01),
        SlowCheck("check.third", 0.02),
    ]
    use_case = RunScanUseCase(checks)
    context = _make_context()

    report = use_case.execute(context)

    ids = [r.check_id for r in report.results]
    assert ids == ["check.first", "check.second", "check.third"]


def test_use_case_concurrent_execution_speed() -> None:
    # 3 checks sleeping 0.08s each: sequentially would take >= 0.24s
    checks = [
        SlowCheck("c1", 0.08),
        SlowCheck("c2", 0.08),
        SlowCheck("c3", 0.08),
    ]
    use_case = RunScanUseCase(checks, max_workers=3)
    context = _make_context()

    start = time.perf_counter()
    report = use_case.execute(context)
    elapsed = time.perf_counter() - start

    assert len(report.results) == 3
    # Concurrent execution should finish well under 0.22s
    assert elapsed < 0.22


def test_use_case_execute_iter_yields_all() -> None:
    checks = [
        SlowCheck("c1", 0.01),
        SlowCheck("c2", 0.01),
    ]
    use_case = RunScanUseCase(checks)
    context = _make_context()

    results = list(use_case.execute_iter(context))
    assert len(results) == 2
    assert {r.check_id for r in results} == {"c1", "c2"}
