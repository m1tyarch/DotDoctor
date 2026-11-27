"""Hygiene check implementations (pacman cache, orphans, pacnew, flatpak unused, journal)."""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dotdoctor.application.check_common import (
    _ExecResult,
    _run_capture,
    _su,
    _unverified,
    detect_pacnew_files,
)
from dotdoctor.application.disk import _format_bytes
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity
from dotdoctor.infrastructure.audit_processes import check_cancelled


class HygieneChecksMixin:
    """Read-only checks for system hygiene and reclaimable disk space."""

    @staticmethod
    def _dry_run_paccache(
        run_cap: Callable[..., _ExecResult],
        args: list[str],
        total_str: str,
    ) -> tuple[int, str] | CheckResult:
        cmd_display = " ".join(args)
        res = run_cap(args, timeout=20)
        if res.completed is None or res.completed.returncode != 0:
            return _unverified(
                "sys.cache",
                f"{total_str} in cache; cleanup candidates not verified",
                cmd_display,
                raw_excerpt=(
                    (getattr(res.completed, "stderr", "") or res.completed.stdout)
                    if res.completed is not None
                    else None
                ),
            )
        match = re.search(
            r"finished dry run:\s*(\d+)\s*candidates\s*\(disk space saved:\s*([^)]+)\)",
            res.completed.stdout,
        )
        if match:
            return int(match.group(1)), match.group(2).strip()
        if re.search(
            r"^\s*(?:==>\s*)?no candidate packages found for pruning\s*$",
            res.completed.stdout + "\n" + getattr(res.completed, "stderr", ""),
            re.MULTILINE,
        ):
            return 0, ""
        return _unverified(
            "sys.cache",
            f"{total_str} in cache; cleanup output not recognized",
            cmd_display,
            raw_excerpt=res.completed.stdout,
        )

    def _check_pacman_cache(
        self,
        context: ScanContext,
        cache_dir: Path = Path("/var/cache/pacman/pkg"),
    ) -> CheckResult:
        try:
            cache_dir.stat()
        except FileNotFoundError:
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.PASS,
                message="pacman cache clean",
                remediation=None,
            )
        except OSError:
            return _unverified(
                "sys.cache", "pacman cache could not be inspected", "du -sh /var/cache/pacman/pkg"
            )

        total_bytes = 0
        try:
            with os.scandir(cache_dir) as it:
                for entry in it:
                    check_cancelled()
                    if entry.is_file(follow_symlinks=False):
                        total_bytes += entry.stat().st_size
        except OSError:
            return _unverified(
                "sys.cache", "pacman cache could not be inspected", "du -sh /var/cache/pacman/pkg"
            )

        su = _su()
        format_bytes_fn: Callable[[int], str] = getattr(su, "_format_bytes", _format_bytes)
        total_str = format_bytes_fn(total_bytes)
        candidates = 0
        saved_str = ""

        which_fn: Callable[[str], Any] = getattr(su, "shutil", shutil).which
        has_paccache = which_fn("paccache") is not None
        if has_paccache:
            run_cap = getattr(su, "_run_capture", _run_capture)
            probe = self._dry_run_paccache(run_cap, ["paccache", "-d"], total_str)
            if isinstance(probe, CheckResult):
                return probe
            candidates, saved_str = probe

        if candidates > 0 and (total_bytes > 2 * 1024**3 or candidates >= 10):
            return CheckResult(
                check_id="sys.cache",
                severity=Severity.WARN,
                message=f"{total_str} in pacman cache ({saved_str} reclaimable)",
                remediation="sudo paccache -rk2",
                details={
                    "total_bytes": total_bytes,
                    "candidates": candidates,
                    "saved": saved_str,
                    "keep_versions": 2,
                },
            )

        if total_bytes > 5 * 1024**3:
            if not has_paccache:
                return CheckResult(
                    check_id="sys.cache",
                    severity=Severity.WARN,
                    message=f"{total_str} in pacman cache",
                    remediation="sudo pacman -Sc",
                    details={"total_bytes": total_bytes},
                )

            run_cap = getattr(su, "_run_capture", _run_capture)
            k1_probe = self._dry_run_paccache(run_cap, ["paccache", "-d", "-k1"], total_str)
            if isinstance(k1_probe, CheckResult):
                return k1_probe
            k1_candidates, k1_saved = k1_probe
            if k1_candidates > 0:
                return CheckResult(
                    check_id="sys.cache",
                    severity=Severity.WARN,
                    message=(
                        f"{total_str} in pacman cache ({k1_saved} reclaimable by keeping 1 version)"
                    ),
                    remediation="sudo paccache -rk1",
                    details={
                        "total_bytes": total_bytes,
                        "candidates": k1_candidates,
                        "saved": k1_saved,
                        "keep_versions": 1,
                    },
                )

            uninst_probe = self._dry_run_paccache(
                run_cap, ["paccache", "-d", "-u", "-k0"], total_str
            )
            if isinstance(uninst_probe, CheckResult):
                return uninst_probe
            uninst_candidates, uninst_saved = uninst_probe
            if uninst_candidates > 0:
                return CheckResult(
                    check_id="sys.cache",
                    severity=Severity.WARN,
                    message=(
                        f"{total_str} in pacman cache ({uninst_saved} from uninstalled packages)"
                    ),
                    remediation="sudo paccache -ruk0",
                    details={
                        "total_bytes": total_bytes,
                        "candidates": uninst_candidates,
                        "saved": uninst_saved,
                        "uninstalled_only": True,
                    },
                )

        return CheckResult(
            check_id="sys.cache",
            severity=Severity.PASS,
            message=f"{total_str} in pacman cache (clean)",
            remediation=None,
            details={"total_bytes": total_bytes, "candidates": candidates},
        )

    def _check_orphans(self, context: ScanContext) -> CheckResult:
        su = _su()
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("pacman") is None:
            return _unverified("sys.orphans", "pacman not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        result = run_cap(["pacman", "-Qtdq"], timeout=15)
        if result.timed_out:
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="orphan check timed out",
                remediation="pacman -Qtdq",
            )
        if result.completed is None or result.completed.returncode not in {0, 1}:
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message="could not check orphan packages",
                remediation="pacman -Qtdq",
            )
        if result.completed.returncode == 1 and getattr(result.completed, "stderr", "").strip():
            return _unverified(
                "sys.orphans",
                "orphan package query failed",
                "pacman -Qtdq",
                raw_excerpt=getattr(result.completed, "stderr", ""),
            )

        orphans = [line.strip() for line in result.completed.stdout.splitlines() if line.strip()]
        if orphans:
            count = len(orphans)
            noun = "package" if count == 1 else "packages"
            return CheckResult(
                check_id="sys.orphans",
                severity=Severity.WARN,
                message=f"{count} orphan {noun} found",
                remediation="sudo pacman -Rns $(pacman -Qtdq)",
                details={"orphans": orphans},
            )

        return CheckResult(
            check_id="sys.orphans",
            severity=Severity.PASS,
            message="no orphan packages",
            remediation=None,
            details={"orphans": []},
        )

    def _check_pacnew(self, context: ScanContext) -> CheckResult:
        detect_pacnew_fn = getattr(_su(), "detect_pacnew_files", detect_pacnew_files)
        files = detect_pacnew_fn()
        if files:
            count = len(files)
            noun = "file" if count == 1 else "files"
            names = ", ".join(Path(f).name for f in files[:2])
            return CheckResult(
                check_id="sys.pacnew",
                severity=Severity.WARN,
                message=f"{count} .pacnew {noun} found ({names})",
                remediation="pacdiff -s",
                details={"files": files},
            )

        return CheckResult(
            check_id="sys.pacnew",
            severity=Severity.PASS,
            message="no .pacnew files",
            remediation=None,
            details={"files": []},
        )

    def _check_flatpak_unused(self, context: ScanContext) -> CheckResult:
        su = _su()
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("flatpak") is None:
            return _unverified("sys.flatpak-unused", "flatpak not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        res = run_cap(
            ["flatpak", "uninstall", "--unused"],
            timeout=15,
            input_str="n\n",
        )
        if res.timed_out or res.completed is None:
            return _unverified(
                "sys.flatpak-unused",
                "could not check unused flatpaks",
                "flatpak uninstall --unused",
            )

        runtime_lines = [
            line for line in res.completed.stdout.splitlines() if re.match(r"^\s*\d+\.\s+", line)
        ]
        if runtime_lines:
            count = len(runtime_lines)
            noun = "runtime" if count == 1 else "runtimes"
            return CheckResult(
                check_id="sys.flatpak-unused",
                severity=Severity.WARN,
                message=f"{count} unused {noun} found",
                remediation="flatpak uninstall --unused",
                details={"unused_count": count},
            )

        if res.completed.returncode != 0:
            return _unverified(
                "sys.flatpak-unused",
                "unused Flatpak runtime check failed",
                "flatpak uninstall --unused",
                raw_excerpt=getattr(res.completed, "stderr", "") or res.completed.stdout,
            )
        if (
            res.completed.stdout.strip()
            and "Nothing unused to uninstall" not in res.completed.stdout
        ):
            return _unverified(
                "sys.flatpak-unused",
                "unused Flatpak runtime output not recognized",
                "flatpak uninstall --unused",
                raw_excerpt=res.completed.stdout,
            )

        return CheckResult(
            check_id="sys.flatpak-unused",
            severity=Severity.PASS,
            message="no unused runtimes",
            remediation=None,
            details={"unused_count": 0},
        )

    def _check_journal(self, context: ScanContext) -> CheckResult:
        su = _su()
        which_fn = getattr(su, "shutil", shutil).which
        if which_fn("journalctl") is None:
            return _unverified("sys.journal", "journalctl not installed")

        run_cap = getattr(su, "_run_capture", _run_capture)
        res = run_cap(["journalctl", "--disk-usage"], timeout=10)
        if res.completed and res.completed.returncode == 0:
            if re.search(
                r"not seeing messages|permission denied", getattr(res.completed, "stderr", ""), re.I
            ):
                return _unverified(
                    "sys.journal",
                    "journal is only partially accessible",
                    "sudo journalctl --disk-usage",
                    raw_excerpt=getattr(res.completed, "stderr", ""),
                )
            match = re.search(
                r"take up\s+([\d.]+\s*[KMGT]?i?B?)\s+in",
                res.completed.stdout,
                re.IGNORECASE,
            )
            if match:
                size_str = match.group(1).strip()
                value = re.fullmatch(r"([\d.]+)\s*([KMGT]?)I?B?", size_str.upper())
                if value is None:
                    return _unverified(
                        "sys.journal",
                        "unsupported journal size format",
                        "journalctl --disk-usage",
                        raw_excerpt=res.completed.stdout,
                    )
                size_bytes = float(value[1]) * 1024 ** (" KMGT".index(value[2]) if value[2] else 0)
                size_bytes_int = round(size_bytes)
                format_bytes_fn = getattr(su, "_format_bytes", _format_bytes)
                formatted_size = format_bytes_fn(size_bytes_int)
                is_large = size_bytes >= 4 * 1024**3

                return CheckResult(
                    check_id="sys.journal",
                    severity=Severity.WARN if is_large else Severity.PASS,
                    message=f"{formatted_size} in journal logs",
                    remediation="sudo journalctl --vacuum-size=1G" if is_large else None,
                    details={
                        "disk_usage": formatted_size,
                        "disk_usage_bytes": size_bytes_int,
                    },
                )

        return _unverified(
            "sys.journal",
            "journal size could not be verified",
            "journalctl --disk-usage",
            raw_excerpt=(
                (getattr(res.completed, "stderr", "") or res.completed.stdout)
                if res.completed is not None
                else None
            ),
        )
