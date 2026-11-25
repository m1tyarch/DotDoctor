"""Shared helpers, constants, and category registries for diagnostic checks."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import dotdoctor.application.system_update as su
from dotdoctor.application.maintenance import PREFLIGHT_IDS
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity
from dotdoctor.infrastructure.audit_processes import capture as capture_command
from dotdoctor.infrastructure.audit_processes import check_cancelled
from dotdoctor.infrastructure.network_worker import HTTPS_TARGETS


def is_online(
    targets: tuple[str, ...] = HTTPS_TARGETS,
    timeout: float = 1.5,
) -> bool:
    """Check HTTPS reachability with a shared deadline, including DNS resolution."""
    if not targets or timeout <= 0:
        return False
    try:
        cap_fn = getattr(su, "capture_command", capture_command)
        completed = cap_fn(
            [
                sys.executable,
                "-m",
                "dotdoctor.infrastructure.network_worker",
                json.dumps(targets),
                str(timeout),
            ],
            timeout=timeout + 1.0,
        )
        return completed.returncode == 0 and json.loads(completed.stdout) is True
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


@dataclass(frozen=True)
class _ExecResult:
    completed: subprocess.CompletedProcess[str] | None
    timed_out: bool = False


def _unverified(
    check_id: str,
    message: str,
    remediation: str | None = None,
    raw_excerpt: str | None = None,
) -> CheckResult:
    details: dict[str, Any] = {"verified": False}
    if raw_excerpt and raw_excerpt.strip():
        details["raw_excerpt"] = " ".join(raw_excerpt.strip().splitlines())[:240]
    return CheckResult(
        check_id=check_id,
        severity=Severity.WARN,
        message=message,
        remediation=remediation,
        details=details,
    )


def _result_for_count(check_id: str, updates: int) -> CheckResult:
    if updates > 0:
        return CheckResult(
            check_id=check_id,
            severity=Severity.OUTD,
            message=f"{updates} update{'s' if updates != 1 else ''} available",
            remediation="dotdoctor --sysup",
            details={"updates": updates},
        )

    msg = "no firmware updates" if check_id.endswith("firmware") else "up to date"
    return CheckResult(
        check_id=check_id,
        severity=Severity.PASS,
        message=msg,
        remediation=None,
        details={"updates": 0},
    )


def detect_aur_helper(which_fn: Callable[[str], str | None] | None = None) -> str | None:
    fn = which_fn or getattr(su, "shutil", shutil).which
    for helper in ("paru", "yay"):
        if fn(helper) is not None:
            return helper
    return None


def _run_capture(
    command: list[str],
    timeout: int,
    input_str: str | None = None,
) -> _ExecResult:
    custom_run_cap = getattr(su, "_run_capture", None)
    if custom_run_cap is not None and custom_run_cap is not _run_capture:
        res = custom_run_cap(command, timeout=timeout)
        if isinstance(res, _ExecResult):
            return res
        return _ExecResult(completed=res)

    cap_cmd = getattr(su, "capture_command", capture_command)
    try:
        return _ExecResult(
            completed=cap_cmd(command, timeout, input_str, {**os.environ, "LC_ALL": "C"}),
        )
    except subprocess.TimeoutExpired:
        return _ExecResult(completed=None, timed_out=True)
    except (OSError, subprocess.SubprocessError):
        return _ExecResult(completed=None, timed_out=False)


def detect_pacnew_files() -> list[str]:
    which_fn = getattr(su, "shutil", shutil).which
    pacdiff_bin = which_fn("pacdiff")
    if pacdiff_bin is not None:
        run_cap = getattr(su, "_run_capture", _run_capture)
        res = run_cap([pacdiff_bin, "-o"], timeout=15)
        if res.completed and res.completed.returncode == 0:
            return [line.strip() for line in res.completed.stdout.splitlines() if line.strip()]

    path_cls = getattr(su, "Path", Path)
    os_mod = getattr(su, "os", os)
    files: list[str] = []
    etc_dir = path_cls("/etc")
    if etc_dir.exists():

        def inaccessible(error: OSError) -> None:
            if not isinstance(error, PermissionError):
                raise error

        for directory, _, names in os_mod.walk(etc_dir, onerror=inaccessible):
            check_cancelled()
            files.extend(
                str(path_cls(directory) / name)
                for name in names
                if name.endswith((".pacnew", ".pacsave"))
            )
    return sorted(files)


def _resolve_oh_my_zsh_path(context: ScanContext) -> str | None:
    zsh_env = os.environ.get("ZSH")
    if zsh_env:
        env_path = os.path.expanduser(zsh_env)
        if os.path.isdir(env_path):
            return env_path

    default_path = context.home / ".oh-my-zsh"
    if default_path.exists() and default_path.is_dir():
        return str(default_path)

    return None


def _detect_oh_my_zsh_updates(omz_path: str) -> int | None:
    which_fn = getattr(su, "shutil", shutil).which
    if which_fn("git") is None:
        return None

    git_dir = os.path.join(omz_path, ".git")
    if not os.path.isdir(git_dir):
        return None

    run_cap = getattr(su, "_run_capture", _run_capture)
    fetched = run_cap(["git", "-C", omz_path, "fetch", "--quiet", "origin"], timeout=30)
    if fetched.completed is None or fetched.completed.returncode != 0:
        return None
    count_result = run_cap(
        ["git", "-C", omz_path, "rev-list", "--count", "HEAD..origin/master"],
        timeout=30,
    )
    if count_result.completed is None or count_result.completed.returncode != 0:
        return None

    raw = count_result.completed.stdout.strip()
    if not raw.isdigit():
        return None
    return int(raw)


CHECK_CATEGORIES: dict[str, frozenset[str]] = {
    "updates": frozenset(
        {"sys.packages", "sys.aur", "sys.flatpak", "sys.firmware", "sys.shell-omz"}
    ),
    "security": frozenset(
        {
            "sys.keyring",
            "sys.news",
            "sys.security",
            "sys.rebuild",
            "sys.package-db",
            "sys.integrity",
        }
    ),
    "hygiene": frozenset(
        {"sys.orphans", "sys.cache", "sys.flatpak-unused", "sys.pacnew", "sys.journal"}
    ),
    "storage": frozenset({"sys.disk", "sys.mounts", "sys.smart", "sys.btrfs", "sys.trim"}),
    "runtime": frozenset({"sys.services", "sys.timers", "sys.reboot", "sys.backup"}),
}

CATEGORY_ALIASES: dict[str, str] = {
    "hardware": "storage",
    "services": "runtime",
}


def resolve_category_checks(categories: Sequence[str]) -> frozenset[str]:
    """Resolve user-supplied category names into a set of check IDs."""
    selected: set[str] = set()
    valid_names = ", ".join(sorted(CHECK_CATEGORIES))
    for raw in categories:
        key = raw.strip().lower()
        key = CATEGORY_ALIASES.get(key, key)
        if key not in CHECK_CATEGORIES:
            raise ValueError(f"unknown check category '{raw}'. Valid categories: {valid_names}")
        selected.update(CHECK_CATEGORIES[key])
    return frozenset(selected)


UPDATE_CHECK_IDS: frozenset[str] = frozenset(
    {
        "sys.packages",
        "sys.aur",
        "sys.flatpak",
        "sys.firmware",
        "sys.shell-omz",
        "sys.keyring",
        "sys.news",
        "sys.security",
        "sys.rebuild",
        "sys.package-db",
        *PREFLIGHT_IDS,
    }
)

FIX_CHECK_IDS: frozenset[str] = frozenset(
    {
        "sys.orphans",
        "sys.cache",
        "sys.flatpak-unused",
        "sys.pacnew",
        "sys.journal",
        "sys.services",
        "sys.disk",
        "sys.reboot",
        "sys.backup",
        "sys.timers",
        "sys.trim",
        "sys.btrfs",
        "sys.integrity",
        "sys.smart",
        "sys.mounts",
    }
)

ALL_CHECK_IDS: frozenset[str] = frozenset(UPDATE_CHECK_IDS | FIX_CHECK_IDS | {"sys.network"})
