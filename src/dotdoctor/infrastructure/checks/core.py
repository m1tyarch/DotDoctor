import os
import shutil
import subprocess
from pathlib import Path

from dotdoctor.domain.config import BinaryRequirement, ProfileConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity
from dotdoctor.infrastructure.checks.utils import (
    is_version_at_least,
    parse_version,
    unique_in_order,
)


class BinaryCheck:
    def __init__(self, requirement: BinaryRequirement) -> None:
        self.requirement = requirement
        self.check_id = f"binary.{requirement.name}"

    def run(self, context: ScanContext) -> CheckResult:
        binary_path = shutil.which(self.requirement.name)
        if binary_path is None:
            msg = (
                f"not found (min {self.requirement.min_version})"
                if self.requirement.min_version
                else "not found"
            )
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.FAIL,
                message=msg,
                remediation=f"install {self.requirement.name}",
                details={"binary": self.requirement.name},
            )

        details: dict[str, str] = {"binary": self.requirement.name, "path": binary_path}
        if self.requirement.min_version is None:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.PASS,
                message="found",
                remediation=None,
                details=details,
            )

        try:
            completed = subprocess.run(
                [self.requirement.name, *self.requirement.version_args],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            version_text = (completed.stdout or completed.stderr).strip()
            details["raw_version"] = version_text
            parsed_current = parse_version(version_text)
            parsed_required = parse_version(self.requirement.min_version)
        except (subprocess.SubprocessError, OSError) as exc:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.WARN,
                message="version check failed",
                remediation=f"verify {self.requirement.name} installation",
                details={**details, "error": str(exc)},
            )

        if parsed_current is None or parsed_required is None:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.WARN,
                message="could not parse version",
                remediation="check version output format",
                details=details,
            )

        current_v = ".".join(str(x) for x in parsed_current)
        if not is_version_at_least(parsed_current, parsed_required):
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.FAIL,
                message=f"{current_v} (min {self.requirement.min_version})",
                remediation=(
                    f"upgrade {self.requirement.name} to at least {self.requirement.min_version}"
                ),
                details={
                    **details,
                    "current": current_v,
                    "required": ".".join(str(x) for x in parsed_required),
                },
            )

        return CheckResult(
            check_id=self.check_id,
            severity=Severity.PASS,
            message=f"{current_v} (min {self.requirement.min_version})",
            remediation=None,
            details={
                **details,
                "current": current_v,
                "required": ".".join(str(x) for x in parsed_required),
            },
        )


class PathIntegrityCheck:
    check_id = "path.integrity"

    def run(self, context: ScanContext) -> CheckResult:
        if not context.path_value:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.FAIL,
                message="PATH variable is empty",
                remediation="export PATH in your shell config",
                details={"path": context.path_value},
            )

        entries = context.path_value.split(":")
        empty_entries = [i for i, entry in enumerate(entries) if entry == ""]
        normalized_entries = [
            str(Path(entry).expanduser().resolve(strict=False)) for entry in entries if entry
        ]
        unique_entries = unique_in_order(normalized_entries)

        duplicates: list[str] = []
        seen: set[str] = set()
        for entry in normalized_entries:
            if entry in seen and entry not in duplicates:
                duplicates.append(entry)
            seen.add(entry)

        missing_entries = [entry for entry in unique_entries if not Path(entry).exists()]

        details = {
            "empty_segments": ",".join(str(i) for i in empty_entries),
            "duplicate_entries": duplicates,
            "missing_entries": missing_entries,
        }

        if not empty_entries and not duplicates and not missing_entries:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.PASS,
                message="no empty, duplicate or missing entries",
                remediation=None,
                details=details,
            )

        if duplicates and not missing_entries and not empty_entries:
            dup_str = ", ".join(duplicates)
            prefix = "duplicate entry" if len(duplicates) == 1 else "duplicate entries"
            msg = f"{prefix}: {dup_str}"
            rem = "remove the duplicate from PATH in your shell config"
        elif missing_entries and not duplicates and not empty_entries:
            miss_str = ", ".join(missing_entries)
            prefix = "missing entry" if len(missing_entries) == 1 else "missing entries"
            msg = f"{prefix}: {miss_str}"
            rem = "remove missing directories from PATH in your shell config"
        elif empty_entries and not duplicates and not missing_entries:
            msg = "empty entry in PATH"
            rem = "remove empty colon entries from PATH in your shell config"
        else:
            msg = "empty, duplicate or missing entries in PATH"
            rem = "clean PATH in your shell config"

        return CheckResult(
            check_id=self.check_id,
            severity=Severity.WARN,
            message=msg,
            remediation=rem,
            details=details,
        )


class ShellConfigCheck:
    check_id = "shell.config"

    def __init__(self, profile: ProfileConfig) -> None:
        self._profile = profile

    def run(self, context: ScanContext) -> CheckResult:
        expected_paths = [Path(path).expanduser() for path in self._profile.shell_config_files]
        existing = [path for path in expected_paths if path.exists()]
        missing = [str(path) for path in expected_paths if not path.exists()]

        suspicious_entries: list[str] = []
        for path in existing:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                for line_no, line in enumerate(text.splitlines(), start=1):
                    if "PATH=$PATH:$PATH" in line or "PATH=:$PATH" in line:
                        suspicious_entries.append(f"{path}:{line_no}")
            except OSError as exc:
                return CheckResult(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="could not inspect shell config files",
                    remediation="check file permissions",
                    details={"error": str(exc), "shell": context.shell},
                )

        details = {
            "existing": [str(path) for path in existing],
            "missing": missing,
            "suspicious_entries": suspicious_entries,
            "shell": context.shell or "unknown",
        }

        if not existing:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.WARN,
                message="no known shell config files found",
                remediation="create ~/.bashrc or ~/.zshrc",
                details=details,
            )

        if suspicious_entries:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.WARN,
                message="suspicious PATH patterns in shell config",
                remediation="remove duplicated/self-referential PATH exports",
                details=details,
            )

        return CheckResult(
            check_id=self.check_id,
            severity=Severity.PASS,
            message="ok",
            remediation=None,
            details=details,
        )


class PermissionsCheck:
    check_id = "permissions.dev_dirs"

    def __init__(self, profile: ProfileConfig) -> None:
        self._profile = profile

    def run(self, context: ScanContext) -> CheckResult:
        paths = [Path(item).expanduser() for item in self._profile.permission_paths]
        resolved_paths: list[Path] = []
        for path in paths:
            resolved_paths.append(context.cwd if str(path) == "." else path)

        missing: list[str] = []
        denied: list[str] = []
        checked: list[str] = []

        for path in resolved_paths:
            checked.append(str(path))
            if not path.exists():
                missing.append(str(path))
                continue

            if not os.access(path, os.R_OK | os.W_OK):
                denied.append(str(path))

        details = {"checked": checked, "missing": missing, "denied": denied}

        if denied:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.FAIL,
                message=f"permission denied: {', '.join(denied)}",
                remediation="fix directory permissions with chmod or chown",
                details=details,
            )

        if missing:
            return CheckResult(
                check_id=self.check_id,
                severity=Severity.WARN,
                message=f"missing directories: {', '.join(missing)}",
                remediation="create missing directories",
                details=details,
            )

        return CheckResult(
            check_id=self.check_id,
            severity=Severity.PASS,
            message="ok",
            remediation=None,
            details=details,
        )
