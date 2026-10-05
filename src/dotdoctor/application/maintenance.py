"""Regular maintenance checks. Audits never request privileges or run repairs."""

import json
import math
import os
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any
from xml.etree.ElementTree import ParseError

from dotdoctor.domain.config import DotDoctorConfig, TimerConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity
from dotdoctor.infrastructure.maintenance import (
    MaintenanceState,
    capture,
    fetch_news,
    properties,
    read_json,
)

PACKAGE_RE = re.compile(r"^[a-zA-Z0-9@_+][a-zA-Z0-9@_.+\-]*$")
PREFLIGHT_IDS = frozenset(
    {
        "sys.keyring",
        "sys.news",
        "sys.backup",
        "sys.smart",
        "sys.btrfs",
        "sys.mounts",
        "sys.package-db",
    }
)
POSTFLIGHT_IDS = frozenset({"sys.security", "sys.rebuild", "sys.integrity", "sys.package-db"})


def _result(
    cid: str, severity: Severity, message: str, remediation: str | None = None, **details: Any
) -> CheckResult:
    return CheckResult(
        check_id=cid, severity=severity, message=message, remediation=remediation, details=details
    )


def timestamp(value: str | int | float) -> float:
    if isinstance(value, (int, float)):
        if isinstance(value, bool) or not math.isfinite(value):
            raise ValueError("invalid completion timestamp")
        return float(value)
    if not value or value in {"n/a", "0"}:
        raise ValueError("no completed execution recorded")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        result = capture(["date", "--date", value, "+%s"])
        if result.returncode:
            raise ValueError("invalid completion timestamp") from None
        return float(result.stdout.strip())
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return dt.timestamp()


def _age_days(value: str | int | float) -> float:
    age = (time.time() - timestamp(value)) / 86400
    if age < -5 / 1440:
        raise ValueError("completion timestamp is in the future")
    return max(0, age)


def service_succeeded(values: dict[str, str]) -> bool:
    return (
        values.get("Result") == "success"
        and values.get("ExecMainStatus") == "0"
        and values.get("ConditionResult") != "no"
        and values.get("AssertResult") != "no"
    )


def privileged(command: list[str]) -> list[str]:
    # Read-only audits may use cached sudo, but must never stop for a password.
    return command if os.geteuid() == 0 else ["sudo", "-n", *command]


def _devices(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
        raise ValueError("invalid block device information")
    collected = []
    for value in values:
        collected.append(value)
        collected.extend(_devices(value.get("children", [])))
    return collected


def mounted_filesystems() -> list[dict[str, Any]]:
    data = read_json(
        ["findmnt", "--json", "--list", "--output", "TARGET,SOURCE,FSTYPE,OPTIONS,UUID"]
    )
    if not isinstance(data, dict) or not isinstance(data.get("filesystems"), list):
        raise ValueError("invalid mount information")
    return data["filesystems"]


class MaintenanceChecks:
    def __init__(self, config: DotDoctorConfig | None = None) -> None:
        self.config = config or DotDoctorConfig()

    def registrations(
        self, context: ScanContext
    ) -> list[tuple[str, str, Callable[[], CheckResult]]]:
        checks: list[tuple[str, str, Callable[[], CheckResult]]] = []
        if shutil.which("pacman"):
            checks.extend(
                [
                    ("sys.keyring", "Package signing keys", self.keyring),
                    ("sys.news", "Arch upgrade notices", self.news),
                    ("sys.package-db", "Package database", self.package_database),
                    ("sys.integrity", "Installed package files", self.integrity),
                ]
            )
            if shutil.which("arch-audit"):
                checks.append(("sys.security", "Known package vulnerabilities", self.security))
            if shutil.which("checkrebuild"):
                checks.append(("sys.rebuild", "Package rebuilds", self.rebuild))
        checks.append(("sys.backup", "Backup freshness", self.backup))
        if shutil.which("systemctl"):
            checks.append(("sys.timers", "Scheduled maintenance", self.timers))
        if shutil.which("lsblk"):
            checks.append(("sys.trim", "SSD discard maintenance", self.trim))
            if shutil.which("smartctl"):
                checks.append(("sys.smart", "Storage health", self.smart))
        if shutil.which("findmnt"):
            if shutil.which("btrfs"):
                checks.append(("sys.btrfs", "Btrfs health and scrub", self.btrfs))
            checks.append(("sys.mounts", "Filesystem capacity", self.mounts))
        return [(cid, label, self._checked(cid, fn)) for cid, label, fn in checks]

    def _checked(self, cid: str, fn: Callable[[], CheckResult]) -> Callable[[], CheckResult]:
        def run() -> CheckResult:
            try:
                return fn()
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                subprocess.SubprocessError,
                ParseError,
            ) as exc:
                backup = self.config.maintenance.backup
                return _result(
                    cid,
                    Severity.WARN,
                    f"not verified: {str(exc)[:160]}",
                    verified=False,
                    blocks_upgrade=bool(
                        cid == "sys.backup" and backup and backup.required_before_upgrade
                    ),
                )

        return run

    def run(self, context: ScanContext, ids: frozenset[str]) -> list[CheckResult]:
        disabled = {cid.replace(":", ".") for cid in self.config.disabled_checks}
        return [
            fn() for cid, _, fn in self.registrations(context) if cid in ids and cid not in disabled
        ]

    def keyring(self) -> CheckResult:
        cid = "sys.keyring"
        packages = self.config.maintenance.keyring_packages
        if not packages or any(not PACKAGE_RE.fullmatch(p) for p in packages):
            return _result(
                cid, Severity.WARN, "configure valid keyring package names", verified=False
            )
        res = capture(["pacman", "-Q", "--", *packages])
        if res.returncode:
            return _result(
                cid,
                Severity.FAIL,
                "required keyring package is missing",
                f"sudo pacman -Sy {shlex.join(packages)} && sudo pacman -Su",
                blocks_upgrade=True,
            )
        files = capture(["pacman", "-Qk", "--", *packages])
        if files.returncode:
            return _result(
                cid,
                Severity.FAIL,
                "keyring files could not be verified",
                f"sudo pacman -Sy {shlex.join(packages)} && sudo pacman -Su",
                blocks_upgrade=True,
            )
        clock = capture(["timedatectl", "show", "--property=NTPSynchronized", "--value"])
        if clock.returncode or clock.stdout.strip() != "yes":
            return _result(
                cid,
                Severity.WARN,
                "clock synchronization is not verified; signatures depend on time",
                "timedatectl status",
                keyrings=packages,
            )
        return _result(
            cid,
            Severity.PASS,
            "keyring files present; clock synchronized",
            keyrings=packages,
            signatures_verified=False,
        )

    def news(self) -> CheckResult:
        seen = MaintenanceState().read().get("news", [])
        items = [item for item in fetch_news() if item["url"] not in seen]
        if items:
            return _result(
                "sys.news",
                Severity.WARN,
                f"{len(items)} unread Arch upgrade notices",
                "https://archlinux.org/news/",
                notices=items,
                items=[f'{item["title"]} {item["url"]}' for item in items],
                requires_review=True,
            )
        return _result("sys.news", Severity.PASS, "current Arch notices acknowledged")

    def backup(self) -> CheckResult:
        cid = "sys.backup"
        config = self.config.maintenance.backup
        if config is None:
            return _result(
                cid,
                Severity.WARN,
                "backup is not configured; recovery is not verified",
                "configure maintenance.backup in dotdoctor.yml",
                verified=False,
            )
        service = properties(config.service, config.scope)
        info = read_json(config.status_command)
        if (
            not isinstance(info, dict)
            or "completed_at" not in info
            or info.get("verified") is not True
        ):
            return _result(
                cid,
                Severity.WARN,
                "backup adapter has not verified a completed copy",
                verified=False,
                blocks_upgrade=config.required_before_upgrade,
            )
        age = _age_days(info["completed_at"])
        healthy = service_succeeded(service)
        details: dict[str, Any] = dict(
            service=config.service,
            scope=config.scope,
            age_days=round(age, 2),
            verified=True,
            blocks_upgrade=config.required_before_upgrade,
        )
        if not healthy or age > config.max_age_days:
            reason = (
                "last backup job failed"
                if not healthy
                else f"last verified backup is {age:.1f} days old"
            )
            return _result(
                cid,
                Severity.WARN,
                reason,
                shlex.join(self.service_command(config.service, config.scope)),
                **details,
            )
        details["blocks_upgrade"] = False
        return _result(
            cid, Severity.PASS, f"verified backup completed {age:.1f} days ago", **details
        )

    @staticmethod
    def service_command(unit: str, scope: str) -> list[str]:
        return (["systemctl", "--user"] if scope == "user" else ["sudo", "systemctl"]) + [
            "start",
            unit,
        ]

    def timers(self) -> CheckResult:
        configs = [
            TimerConfig(unit="systemd-tmpfiles-clean.timer", max_age_days=2),
            *self.config.maintenance.timers,
        ]
        if (
            shutil.which("pacman")
            and "archlinux-keyring" in self.config.maintenance.keyring_packages
        ):
            configs.append(TimerConfig(unit="archlinux-keyring-wkd-sync.timer", max_age_days=8))
        issues: list[str] = []
        repairs: list[dict[str, str]] = []
        for config in configs:
            try:
                timer = properties(config.unit, config.scope, timer=True)
                if timer.get("ActiveState") == "inactive":
                    issues.append(f"{config.unit}: expected timer is inactive")
                    repairs.append({"unit": config.unit, "scope": config.scope})
                trigger = timer.get("Triggers", "").split()
                if not trigger:
                    raise ValueError("no triggered service")
                service = properties(trigger[0], config.scope)
                if not service_succeeded(service):
                    issues.append(f"{config.unit}: triggered service has not succeeded")
                else:
                    age = _age_days(service.get("ExecMainExitTimestamp", ""))
                    if age > config.max_age_days:
                        issues.append(f"{config.unit}: last success {age:.1f} days ago")
                if timer.get("ActiveState") != "active":
                    if timer.get("ActiveState") != "inactive":
                        issues.append(f"{config.unit}: expected timer is not active")
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                issues.append(f"{config.unit}: {exc}")
        if issues:
            return _result(
                "sys.timers",
                Severity.WARN,
                f"{len(issues)} scheduled maintenance findings",
                "inspect the listed timer and service logs",
                items=issues,
                timers=repairs,
            )
        return _result(
            "sys.timers", Severity.PASS, "expected timers and their latest jobs succeeded"
        )

    def trim(self) -> CheckResult:
        cid = "sys.trim"
        data = read_json(
            ["lsblk", "--json", "--bytes", "--output", "PATH,TYPE,DISC-MAX,MOUNTPOINTS"]
        )
        if not isinstance(data, dict) or "blockdevices" not in data:
            raise ValueError("block device information unavailable")
        devices = _devices(data["blockdevices"])
        mounts = {
            m
            for d in devices
            if int(d.get("disc-max") or 0) > 0
            for m in (d.get("mountpoints") or [])
            if m
        }
        if not mounts:
            return _result(
                cid, Severity.PASS, "no mounted discard-capable devices detected", applicable=False
            )
        fs = mounted_filesystems()
        continuous = {
            m["target"]
            for m in fs
            if any(
                o in {"discard", "discard=async", "discard=sync"}
                for o in m.get("options", "").split(",")
            )
        }
        if mounts.issubset(continuous):
            return _result(cid, Severity.PASS, "continuous discard enabled on applicable mounts")
        timer = properties("fstrim.timer", timer=True)
        service = properties("fstrim.service")
        healthy = service_succeeded(service)
        try:
            age = _age_days(service.get("ExecMainExitTimestamp", "")) if healthy else None
        except ValueError:
            age = None
        if timer.get("ActiveState") != "active" or age is None or age > 7:
            return _result(
                cid,
                Severity.WARN,
                "periodic TRIM is inactive, failed, or overdue",
                "sudo systemctl enable --now fstrim.timer && sudo systemctl start fstrim.service",
                actionable=True,
                mounts=sorted(mounts - continuous),
            )
        return _result(cid, Severity.PASS, f"periodic TRIM succeeded {age:.1f} days ago")

    def smart(self) -> CheckResult:
        cid = "sys.smart"
        if not shutil.which("smartctl"):
            return _result(
                cid,
                Severity.WARN,
                "smartctl not installed; disk health not verified",
                "sudo pacman -Syu smartmontools",
                verified=False,
            )
        data = read_json(["lsblk", "--json", "--output", "PATH,TYPE"])
        disks = [
            d["path"]
            for d in _devices(data.get("blockdevices", []))
            if d.get("type") == "disk"
            and d.get("path")
            and not os.path.basename(str(d["path"])).startswith(("zram", "loop", "ram"))
        ]
        issues: list[str] = []
        critical = False
        if not disks:
            return _result(
                cid,
                Severity.WARN,
                "no physical disks detected; health not verified",
                verified=False,
            )
        for disk in dict.fromkeys(disks):
            result = capture(privileged(["smartctl", "-x", "-j", "-n", "standby,3", disk]), 20)
            try:
                report = json.loads(result.stdout)
            except ValueError:
                issues.append(
                    f"{disk}: SMART unavailable (permission, sleeping disk, or unsupported device)"
                )
                continue
            if result.returncode & 7 or not isinstance(
                report.get("smart_status", {}).get("passed"), bool
            ):
                issues.append(f"{disk}: SMART status could not be verified")
                continue
            nvme = report.get("nvme_smart_health_information_log", {})
            if report["smart_status"]["passed"] is False or int(nvme.get("critical_warning", 0)):
                critical = True
                issues.append(f"{disk}: current SMART health failure")
            elif result.returncode & 248 or int(nvme.get("media_errors", 0)):
                issues.append(f"{disk}: SMART error history requires review")
            attributes = report.get("ata_smart_attributes", {}).get("table", [])
            if any(
                a.get("id") in {197, 198} and a.get("raw", {}).get("value", 0) > 0
                for a in attributes
            ):
                critical = True
                issues.append(f"{disk}: pending or uncorrectable sectors")
        if issues:
            has_hardware_issues = critical or any(
                "history" in i or "failure" in i or "sectors" in i for i in issues
            )
            remediation = (
                "back up data and inspect the affected device"
                if has_hardware_issues
                else "sudo smartctl -x <device>"
            )
            return _result(
                cid,
                Severity.FAIL if critical else Severity.WARN,
                f"{len(issues)} disk health findings",
                remediation,
                items=issues,
                blocks_upgrade=critical,
                verified=False,
            )
        return _result(
            cid,
            Severity.PASS,
            f"SMART health checked on {len(set(disks))} devices",
            verified=True,
            blocks_upgrade=False,
        )

    def btrfs(self) -> CheckResult:
        cid = "sys.btrfs"
        filesystems = [fs for fs in mounted_filesystems() if fs.get("fstype") == "btrfs"]
        if not filesystems:
            return _result(cid, Severity.PASS, "no mounted Btrfs filesystems", applicable=False)
        if not shutil.which("btrfs"):
            return _result(
                cid,
                Severity.WARN,
                "btrfs tools missing; scrub and errors not verified",
                "sudo pacman -Syu btrfs-progs",
                verified=False,
            )
        issues: list[str] = []
        due: list[str] = []
        seen: set[str] = set()
        critical = False
        for fs in filesystems:
            identity = fs.get("uuid") or fs["source"].split("[")[0]
            if identity in seen:
                continue
            seen.add(identity)
            target = fs["target"]
            stats = capture(privileged(["btrfs", "device", "stats", target]))
            if stats.returncode:
                issues.append(f"{target}: device statistics unavailable")
                continue
            counters = re.findall(
                r"\.(?:write_io_errs|read_io_errs|flush_io_errs|corruption_errs|generation_errs)\s+(\d+)",
                stats.stdout,
            )
            if not counters:
                issues.append(f"{target}: device statistics could not be parsed")
                continue
            if any(int(n) > 0 for n in counters):
                issues.append(f"{target}: cumulative device errors; inspect before another scrub")
                continue
            scrub = capture(privileged(["btrfs", "scrub", "status", "-R", target]))
            output = scrub.stdout
            if "no stats available" in (output + scrub.stderr).lower():
                issues.append(f"{target}: no completed scrub recorded")
                due.append(target)
                continue
            if scrub.returncode and "no stats available" not in (output + scrub.stderr).lower():
                issues.append(f"{target}: scrub status unavailable")
                continue
            uncorrectable = re.search(r"uncorrectable(?:_errors)?\s*:\s*(\d+)", output, re.I)
            if uncorrectable and int(uncorrectable[1]) > 0:
                critical = True
                issues.append(f"{target}: uncorrectable scrub errors")
                continue
            if not uncorrectable:
                issues.append(f"{target}: scrub error counters could not be verified")
                continue
            corrected = re.search(r"corrected(?:_errors)?\s*:\s*(\d+)", output, re.I)
            if corrected and int(corrected[1]) > 0:
                issues.append(f"{target}: scrub corrected errors; inspect device health")
                continue
            if re.search(r"(?:status:\s*running|status:\s*paused|running for)", output, re.I):
                issues.append(f"{target}: scrub has not completed")
                continue
            started = re.search(r"(?:scrub started at|scrub started:)\s*(.+)", output, re.I)
            if not started or not re.search(r"finished", output, re.I):
                issues.append(f"{target}: no completed scrub recorded")
                due.append(target)
            elif _age_days(started[1].strip()) > self.config.maintenance.scrub_max_age_days:
                issues.append(f"{target}: scrub is overdue")
                due.append(target)
        if issues:
            return _result(
                cid,
                Severity.FAIL if critical else Severity.WARN,
                f"{len(issues)} Btrfs findings",
                "inspect Btrfs findings before starting maintenance",
                items=issues,
                scrub_targets=due if not critical else [],
                blocks_upgrade=critical,
            )
        return _result(
            cid, Severity.PASS, f"{len(seen)} Btrfs filesystems have recent completed scrubs"
        )

    def mounts(self) -> CheckResult:
        targets = {"/", "/home", "/var", "/boot", "/boot/efi", "/efi"}
        issues = []
        critical = False
        filesystems = mounted_filesystems()
        if not any(fs.get("target") == "/" for fs in filesystems):
            raise ValueError("root mount information unavailable")
        for fs in filesystems:
            if fs.get("target") not in targets:
                continue
            target = fs["target"]
            values = os.statvfs(target)
            available = values.f_bavail * values.f_frsize
            total = getattr(values, "f_blocks", 0) * values.f_frsize
            if target in {"/", "/home", "/var"}:
                minimum = 500 * 1024**2
            elif target in {"/boot/efi", "/efi"} or (0 < total < 256 * 1024**2):
                minimum = (
                    min(15 * 1024**2, max(5 * 1024**2, int(total * 0.10)))
                    if total > 0
                    else 15 * 1024**2
                )
            else:
                minimum = 50 * 1024**2
            if "ro" in fs.get("options", "").split(","):
                critical = True
                issues.append(f"{target}: read-only filesystem")
            if available < minimum:
                critical = True
                free_mb = available // (1024**2)
                min_mb = minimum // (1024**2)
                avail_text = f"{available // 1024} KB" if free_mb == 0 else f"{free_mb} MB"
                issues.append(
                    f"{target}: critically low available space "
                    f"({avail_text} free, minimum {min_mb} MB)"
                )
            if values.f_files and values.f_favail / values.f_files < 0.01:
                issues.append(f"{target}: fewer than 1% free inodes")
                critical |= values.f_favail == 0
        if issues:
            return _result(
                "sys.mounts",
                Severity.FAIL if critical else Severity.WARN,
                f"{len(issues)} filesystem capacity findings",
                "df -h; df -i",
                items=issues,
                blocks_upgrade=critical,
            )
        return _result("sys.mounts", Severity.PASS, "system mounts have available space and inodes")

    def security(self) -> CheckResult:
        cid = "sys.security"
        if not shutil.which("arch-audit"):
            return _result(
                cid,
                Severity.WARN,
                "arch-audit not installed; advisories not checked",
                "sudo pacman -Syu arch-audit",
                verified=False,
            )
        result = capture(["arch-audit", "--format", "%n\t%s\t%v\t%c"], 30)
        if result.returncode:
            raise ValueError(result.stderr.strip() or "security audit failed")
        data = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            fields = line.split("\t", 3)
            if len(fields) != 4 or not PACKAGE_RE.fullmatch(fields[0]):
                raise ValueError("unsupported security audit output")
            data.append(
                dict(package=fields[0], severity=fields[1], fixed_version=fields[2], cves=fields[3])
            )
        if data:
            return _result(
                cid,
                Severity.FAIL,
                f"{len(data)} known vulnerable package findings",
                "dotdoctor --sysup",
                advisories=data,
                items=[
                    f'{entry["package"]}: {entry["severity"]} {entry["cves"]}; '
                    f'fixed version: {entry["fixed_version"] or "not available"}'
                    for entry in data
                ],
                blocks_upgrade=False,
                verified=True,
                coverage="Arch Security Tracker; excludes AUR and Flatpak",
            )
        return _result(
            cid,
            Severity.PASS,
            "no known vulnerabilities in Arch Security Tracker coverage",
            verified=True,
            coverage="Arch Security Tracker; excludes AUR and Flatpak",
        )

    def package_database(self) -> CheckResult:
        result = capture(["pacman", "-Dk"], 30)
        if result.returncode:
            return _result(
                "sys.package-db",
                Severity.FAIL,
                "package database is inconsistent or inaccessible",
                "pacman -Dk",
                items=(result.stdout + result.stderr).splitlines()[-10:],
                blocks_upgrade=True,
            )
        return _result("sys.package-db", Severity.PASS, "local package database is consistent")

    def integrity(self) -> CheckResult:
        result = capture(["pacman", "-Qkq"], self.config.maintenance.integrity_timeout_seconds)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        packages = sorted(
            {
                line.split()[0]
                for line in lines
                if len(line.split()) >= 2 and PACKAGE_RE.fullmatch(line.split()[0])
            }
        )
        if result.returncode and not packages:
            raise ValueError(result.stderr.strip() or "package file check failed")
        if packages:
            # Limit auto-reinstallation to native packages, without guessing foreign provenance.
            native = capture(["pacman", "-Qnq", "--", *packages])
            official = [p for p in native.stdout.splitlines() if p in packages]
            return _result(
                "sys.integrity",
                Severity.FAIL,
                f"{len(packages)} packages have missing files",
                "dotdoctor --fix",
                packages=packages,
                reinstall_packages=official,
                items=lines[:20],
                blocks_upgrade=False,
            )
        return _result(
            "sys.integrity", Severity.PASS, "package files present (contents not hashed)"
        )

    def rebuild(self) -> CheckResult:
        cid = "sys.rebuild"
        foreign = capture(["pacman", "-Qmq"])
        if foreign.returncode:
            raise ValueError("foreign package list unavailable")
        if not foreign.stdout.strip():
            return _result(cid, Severity.PASS, "no foreign packages require rebuild checks")
        if not shutil.which("checkrebuild"):
            return _result(
                cid,
                Severity.WARN,
                "checkrebuild not installed; foreign package compatibility not verified",
                "sudo pacman -Syu rebuild-detector",
                verified=False,
            )
        result = capture(["checkrebuild"], 60)
        if result.returncode:
            raise ValueError(result.stderr.strip() or "rebuild check failed")
        entries = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        candidates = [
            line.split()[0]
            for line in entries
            if PACKAGE_RE.fullmatch(line.split()[0])
            and line.split()[0] in foreign.stdout.splitlines()
        ]
        if entries:
            return _result(
                cid,
                Severity.WARN,
                f"{len(entries)} foreign package compatibility findings",
                "checkrebuild -v",
                items=entries,
                rebuild_packages=candidates,
                blocks_upgrade=False,
            )
        return _result(cid, Severity.PASS, "no foreign package rebuild findings")
