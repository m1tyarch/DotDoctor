"""Runtime and storage check implementations (reboot status, disk space, failed services)."""

from __future__ import annotations

import shutil

from dotdoctor.application.check_common import _run_capture, _su, _unverified
from dotdoctor.application.disk import detect_disk_space_status
from dotdoctor.application.reboot import detect_reboot_status
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity


class RuntimeChecksMixin:
    """Read-only checks for reboot state, root/boot disk space, and failed systemd units."""

    config: DotDoctorConfig

    def _check_reboot(self, context: ScanContext) -> CheckResult:
        extra_pkgs = getattr(self.config.maintenance, "extra_reboot_packages", [])
        detect_reboot_fn = getattr(_su(), "detect_reboot_status", detect_reboot_status)
        try:
            status = (
                detect_reboot_fn(extra_critical_packages=extra_pkgs)
                if extra_pkgs
                else detect_reboot_fn()
            )
        except TypeError:
            status = detect_reboot_fn()
        if status.required:
            reason = (status.reason or "reboot required").rstrip(".")
            return CheckResult(
                check_id="sys.reboot",
                severity=Severity.WARN,
                message=f"reboot required: {reason}",
                remediation="systemctl reboot",
                details={
                    "running_kernel": status.running_kernel,
                    "installed_kernels": status.installed_kernels,
                    "reboot_required": True,
                    "packages": status.packages,
                },
            )

        if not status.installed_kernels:
            return _unverified(
                "sys.reboot",
                "installed kernels unavailable; reboot state not verified",
                "ls /usr/lib/modules",
            )

        return CheckResult(
            check_id="sys.reboot",
            severity=Severity.PASS,
            message="no reboot required",
            remediation=None,
            details={
                "running_kernel": status.running_kernel,
                "installed_kernels": status.installed_kernels,
                "reboot_required": False,
                "packages": [],
            },
        )

    def _check_disk_space(self, context: ScanContext) -> CheckResult:
        detect_disk_fn = getattr(_su(), "detect_disk_space_status", detect_disk_space_status)
        status = detect_disk_fn()
        return CheckResult(
            check_id="sys.disk",
            severity=status.severity,
            message=status.message,
            remediation=status.remediation,
            details={
                "root_free_bytes": status.root_free_bytes,
                "boot_free_bytes": status.boot_free_bytes,
            },
        )

    def _check_failed_services(self, context: ScanContext) -> CheckResult:
        su = _su()
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("systemctl") is None:
            return _unverified("sys.services", "systemctl not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        failed_units: list[str] = []
        unavailable: list[str] = []
        sys_res = run_cap(
            ["systemctl", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if sys_res.completed and sys_res.completed.returncode == 0:
            for line in sys_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    unit = parts[1] if parts[0] in {"●", "*", "x"} and len(parts) > 1 else parts[0]
                    failed_units.append(unit)
        else:
            unavailable.append("system")

        user_res = run_cap(
            ["systemctl", "--user", "--failed", "--no-legend", "--plain"],
            timeout=10,
        )
        if user_res.completed and user_res.completed.returncode == 0:
            for line in user_res.completed.stdout.splitlines():
                parts = line.strip().split()
                if parts:
                    unit = parts[1] if parts[0] in {"●", "*", "x"} and len(parts) > 1 else parts[0]
                    failed_units.append(f"{unit} (user)")
        else:
            unavailable.append("user")

        if failed_units:
            count = len(failed_units)
            noun = "unit" if count == 1 else "units"
            sample = ", ".join(failed_units[:2])
            first_unit = failed_units[0].split()[0]
            return CheckResult(
                check_id="sys.services",
                severity=Severity.FAIL,
                message=f"{count} failed {noun} ({sample})",
                remediation=f"systemctl status {first_unit}",
                details={
                    "failed_units": failed_units,
                    "unavailable_scopes": unavailable,
                    "verified": not unavailable,
                },
            )

        if unavailable:
            return _unverified(
                "sys.services",
                f"failed units not verified ({', '.join(unavailable)} manager unavailable)",
                "systemctl --failed; systemctl --user --failed",
            )

        return CheckResult(
            check_id="sys.services",
            severity=Severity.PASS,
            message="no failed units",
            remediation=None,
            details={"failed_units": []},
        )
