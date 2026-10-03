from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.domain.ports import EnvironmentCheck


class RunScanUseCase:
    def __init__(
        self,
        checks: list[EnvironmentCheck],
        max_workers: int | None = None,
    ) -> None:
        self._checks = checks
        self._max_workers = max_workers or min(32, max(1, len(checks)))

    @property
    def total_checks(self) -> int:
        return len(self._checks)

    @property
    def checks(self) -> list[EnvironmentCheck]:
        return list(self._checks)

    def execute_iter(self, context: ScanContext) -> Iterator[CheckResult]:
        if not self._checks:
            return

        with ThreadPoolExecutor(max_workers=min(self._max_workers, len(self._checks))) as pool:
            future_to_check = {
                pool.submit(self._run_single_check, check, context): check for check in self._checks
            }
            for future in as_completed(future_to_check):
                yield future.result()

    def execute(self, context: ScanContext) -> ScanReport:
        if not self._checks:
            return ScanReport(profile=context.profile, results=[])

        with ThreadPoolExecutor(max_workers=min(self._max_workers, len(self._checks))) as pool:
            futures = [
                pool.submit(self._run_single_check, check, context) for check in self._checks
            ]
            results = [future.result() for future in futures]

        return ScanReport(profile=context.profile, results=results)

    def _run_single_check(self, check: EnvironmentCheck, context: ScanContext) -> CheckResult:
        try:
            return check.run(context)
        except Exception as exc:  # noqa: BLE001
            return CheckResult(
                check_id=check.check_id,
                severity=Severity.FAIL,
                message="DotDoctor check execution failed",
                remediation=(
                    "Inspect check logs and retry. " "If issue persists, open a bug report."
                ),
                details={"exception": type(exc).__name__, "error": str(exc)},
            )
