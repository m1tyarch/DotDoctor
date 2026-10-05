from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    PASS = "PASS"
    OUTD = "OUTD"
    WARN = "WARN"
    FAIL = "FAIL"


class CheckResult(BaseModel):
    check_id: str = Field(min_length=1)
    severity: Severity
    message: str
    remediation: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ScanReport(BaseModel):
    profile: str
    results: list[CheckResult]

    @property
    def summary(self) -> dict[str, int]:
        pass_count = 0
        outd_count = 0
        warn_count = 0
        fail_count = 0

        for result in self.results:
            if result.severity is Severity.PASS:
                pass_count += 1
            elif result.severity is Severity.OUTD:
                outd_count += 1
            elif result.severity is Severity.WARN:
                warn_count += 1
            else:
                fail_count += 1

        return {
            "PASS": pass_count,
            "OUTD": outd_count,
            "WARN": warn_count,
            "FAIL": fail_count,
        }

    @property
    def exit_code(self) -> int:
        summary = self.summary
        if summary["FAIL"] > 0:
            return 2
        return 0

    def get_result(self, check_id: str) -> CheckResult | None:
        norm = normalize_check_id(check_id)
        for r in self.results:
            if r.check_id == check_id or normalize_check_id(r.check_id) == norm:
                return r
        return None


def normalize_check_id(check_id: str) -> str:
    return check_id.replace(":", ".")
