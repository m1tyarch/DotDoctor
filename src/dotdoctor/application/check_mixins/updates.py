"""Update check implementations (pacman, AUR, Flatpak, firmware, Oh-My-Zsh)."""

from __future__ import annotations

import re
import shlex
import shutil

import dotdoctor.application.system_update as su
from dotdoctor.application.check_common import (
    _detect_oh_my_zsh_updates,
    _result_for_count,
    _run_capture,
    _unverified,
)
from dotdoctor.application.parsers import (
    _AUR_FLAGGED_RE,
    _parse_fwupdmgr_json,
    _parse_fwupdmgr_updates,
    parse_package_update_line,
)
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity


class UpdatesChecksMixin:
    """Read-only checks for available package, firmware, and shell updates."""

    def _check_arch_packages(self, context: ScanContext) -> CheckResult:
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("checkupdates") is None:
            if which_fn("pacman") is None:
                return _unverified("sys.packages", "pacman not installed")
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN,
                message="checkupdates not installed",
                remediation="sudo pacman -S pacman-contrib",
            )

        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap(["checkupdates"], timeout=60)
        if result.timed_out:
            return _unverified("sys.packages", "package check timed out", "checkupdates")
        if result.completed is None:
            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN,
                message="could not run checkupdates",
                remediation="checkupdates",
            )
        completed = result.completed
        lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if completed.returncode == 2:
            return _result_for_count("sys.packages", 0)

        if completed.returncode not in {0, 2}:
            error_output = (
                getattr(completed, "stderr", "") or getattr(completed, "stdout", "") or ""
            ).strip()
            missing_fakeroot = "cannot find the fakeroot binary" in error_output.lower()
            is_locked = (
                "db.lck" in error_output.lower()
                or "unable to lock database" in error_output.lower()
            )
            if is_locked:
                msg = "pacman database is locked (/var/lib/pacman/db.lck)"
                remediation = "check running processes or remove /var/lib/pacman/db.lck"
            elif missing_fakeroot:
                msg = "checkupdates requires fakeroot; updates are not verified"
                remediation = "sudo pacman -Syu fakeroot"
            else:
                msg = f"checkupdates failed (exit={completed.returncode})"
                remediation = "checkupdates"

            return CheckResult(
                check_id="sys.packages",
                severity=Severity.WARN if missing_fakeroot else Severity.FAIL,
                message=msg,
                remediation=remediation,
                details={
                    "verified": False,
                    "returncode": completed.returncode,
                    "items": error_output.splitlines() or ["command returned no error output"],
                },
            )

        if not lines:
            return _result_for_count("sys.packages", 0)

        pkg_entries: list[str] = []
        parse_line_fn = getattr(su, "parse_package_update_line", parse_package_update_line)
        for line in lines:
            parsed = parse_line_fn(line)
            if parsed:
                pkg_name, old_v, new_v = parsed
                pkg_entries.append(f"{pkg_name} {old_v} -> {new_v}")
            else:
                pkg_entries.append(line)

        count = len(lines)
        noun = "update" if count == 1 else "updates"

        return CheckResult(
            check_id="sys.packages",
            severity=Severity.OUTD,
            message=f"{count} {noun} available",
            remediation="dotdoctor --sysup",
            details={
                "updates": count,
                "packages": pkg_entries,
            },
        )

    def _check_aur_packages(self, context: ScanContext, aur_helper: str = "yay") -> CheckResult:
        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap([aur_helper, "-Qua"], timeout=60)
        if result.timed_out:
            return _unverified(
                "sys.aur", f"{aur_helper} update check timed out", f"{aur_helper} -Qua"
            )
        if result.completed is None:
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.WARN,
                message=f"could not run {aur_helper} -Qua",
                remediation=f"{aur_helper} -Qua",
            )
        lines = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        no_matches = (
            result.completed.returncode == 1
            and not lines
            and not getattr(result.completed, "stderr", "").strip()
        )
        if result.completed.returncode != 0 and not no_matches:
            return _unverified(
                "sys.aur",
                f"{aur_helper} update check failed (exit={result.completed.returncode})",
                f"{aur_helper} -Qua",
                raw_excerpt=getattr(result.completed, "stderr", "") or result.completed.stdout,
            )
        flagged = [line for line in lines if _AUR_FLAGGED_RE.search(line)]
        regular = [line for line in lines if line not in flagged]

        if not lines:
            return CheckResult(
                check_id="sys.aur",
                severity=Severity.PASS,
                message="up to date",
                remediation=None,
                details={"updates": 0, "flagged": 0, "packages": []},
            )

        aur_entries: list[str] = []
        parse_line_fn = getattr(su, "parse_package_update_line", parse_package_update_line)
        for line in lines:
            parts = line.split()
            pkg_name = parts[0]
            if pkg_name.startswith("aur/"):
                pkg_name = pkg_name[4:]
            parsed = parse_line_fn(line)
            if parsed:
                _, old_v, new_v = parsed
                aur_entries.append(f"{pkg_name} {old_v} -> {new_v}")
            else:
                aur_entries.append(line)

        count = len(lines)
        noun = "update" if count == 1 else "updates"
        if flagged:
            msg = f"{count} AUR {noun} available ({len(flagged)} flagged out-of-date)"
        else:
            msg = f"{len(regular)} AUR {noun} available"

        return CheckResult(
            check_id="sys.aur",
            severity=Severity.OUTD,
            message=msg,
            remediation="dotdoctor --sysup",
            details={
                "updates": len(regular),
                "flagged": len(flagged),
                "packages": aur_entries,
            },
        )

    def _check_flatpak(self, context: ScanContext) -> CheckResult:
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("flatpak") is None:
            return _unverified("sys.flatpak", "flatpak not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap(["flatpak", "remote-ls", "--updates"], timeout=60)
        if result.timed_out:
            return _unverified(
                "sys.flatpak", "Flatpak check timed out", "flatpak remote-ls --updates"
            )
        if result.completed is None:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.WARN,
                message="could not run Flatpak check",
                remediation="flatpak remote-ls --updates",
            )
        if result.completed.returncode != 0:
            return CheckResult(
                check_id="sys.flatpak",
                severity=Severity.FAIL,
                message=f"flatpak check failed (exit={result.completed.returncode})",
                remediation="check Flatpak remote configuration",
            )
        lines = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        if not lines:
            return _result_for_count("sys.flatpak", 0)

        count = len(lines)
        noun = "update" if count == 1 else "updates"
        return CheckResult(
            check_id="sys.flatpak",
            severity=Severity.OUTD,
            message=f"{count} {noun} available",
            remediation="dotdoctor --sysup",
            details={"updates": count, "packages": lines},
        )

    def _check_firmware(self, context: ScanContext) -> CheckResult:
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("fwupdmgr") is None:
            return _unverified("sys.firmware", "fwupd not installed")

        # Read-only audit executes get-updates --json without mutating metadata refresh.
        run_cap = getattr(su, "_run_capture", _run_capture)
        updates_result = run_cap(["fwupdmgr", "get-updates", "--json"], timeout=90)
        if (
            not updates_result.timed_out
            and updates_result.completed is not None
            and updates_result.completed.returncode not in {0, 2}
        ):
            stderr_lower = (getattr(updates_result.completed, "stderr", "") or "").lower()
            if "unknown option" in stderr_lower or "unrecognized option" in stderr_lower:
                updates_result = run_cap(["fwupdmgr", "get-updates"], timeout=90)

        if updates_result.timed_out:
            return _unverified(
                "sys.firmware", "fwupdmgr get-updates timed out", "fwupdmgr get-updates"
            )
        if updates_result.completed is None:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.WARN,
                message="could not run firmware update check",
                remediation="fwupdmgr get-updates",
            )
        completed = updates_result.completed

        if completed.returncode == 2:
            return CheckResult(
                check_id="sys.firmware",
                severity=Severity.PASS,
                message="no firmware updates",
                remediation=None,
                details={"updates": 0},
            )

        parse_json_fn = getattr(su, "_parse_fwupdmgr_json", _parse_fwupdmgr_json)
        json_count = parse_json_fn(completed.stdout)
        if json_count is not None:
            if completed.returncode not in {0, 2} and json_count == 0:
                return _unverified(
                    "sys.firmware",
                    "firmware check returned unexpected exit code",
                    "fwupdmgr get-updates",
                    raw_excerpt=getattr(completed, "stderr", "") or completed.stdout,
                )
            return _result_for_count("sys.firmware", json_count)

        parse_fwupd_fn = getattr(su, "_parse_fwupdmgr_updates", _parse_fwupdmgr_updates)
        update_count = parse_fwupd_fn(completed.stdout)
        if completed.returncode not in {0, 2} and update_count == 0:
            return _unverified(
                "sys.firmware",
                "firmware check returned unexpected exit code",
                "fwupdmgr get-updates",
                raw_excerpt=getattr(completed, "stderr", "") or completed.stdout,
            )

        if update_count == 0:
            lines = [line for line in completed.stdout.splitlines() if line.strip()]
            no_update_heading = re.compile(
                r"^Devices with (?:the latest available firmware version|"
                r"no available firmware updates):$"
            )
            if any(no_update_heading.fullmatch(line) for line in lines) and all(
                no_update_heading.fullmatch(line) or line[0].isspace() for line in lines
            ):
                return _result_for_count("sys.firmware", 0)
            return _unverified(
                "sys.firmware",
                "firmware update output could not be verified",
                "fwupdmgr get-updates",
                raw_excerpt=completed.stdout,
            )

        return _result_for_count("sys.firmware", update_count)

    def _check_oh_my_zsh(self, omz_path: str) -> CheckResult:
        if su.os.geteuid() == 0:
            return CheckResult(
                check_id="sys.shell-omz",
                severity=Severity.SKIP,
                message="skipped when running as root",
                remediation=None,
                details={"updates": 0},
            )
        detect_omz_fn = getattr(su, "_detect_oh_my_zsh_updates", _detect_oh_my_zsh_updates)
        update_count = detect_omz_fn(omz_path)
        if update_count is None:
            return _unverified(
                "sys.shell-omz",
                "Oh-My-Zsh updates could not be verified",
                f"git -C {shlex.quote(omz_path)} status",
            )
        if update_count > 0:
            return CheckResult(
                check_id="sys.shell-omz",
                severity=Severity.OUTD,
                message=f"{update_count} update{'s' if update_count != 1 else ''} available",
                remediation="dotdoctor --sysup",
                details={"updates": update_count},
            )

        return CheckResult(
            check_id="sys.shell-omz",
            severity=Severity.PASS,
            message="up to date",
            remediation=None,
            details={"updates": 0},
        )
