import json
import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from dotdoctor.application import maintenance as m
from dotdoctor.domain.config import BackupConfig, DotDoctorConfig, MaintenanceConfig, TimerConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import Severity
from dotdoctor.infrastructure import maintenance as readers

NOW = datetime(2026, 10, 5, tzinfo=UTC).timestamp()
RECENT = "2026-10-04T00:00:00+00:00"
OLD = "2026-08-01T00:00:00+00:00"


def response(stdout="", returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def healthy_service():
    return {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "Result": "success",
        "ExecMainStatus": "0",
        "ExecMainExitTimestamp": RECENT,
    }


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError(f"Unmocked I/O: {args}")

    monkeypatch.setattr(m, "capture", forbidden)
    monkeypatch.setattr(m, "read_json", forbidden)
    monkeypatch.setattr(m, "properties", forbidden)
    monkeypatch.setattr(m, "mounted_filesystems", forbidden)
    monkeypatch.setattr(m.time, "time", lambda: NOW)
    monkeypatch.setattr(m.shutil, "which", lambda name: None)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(readers.urllib.request, "urlopen", forbidden)


def checked(checks, cid, fn):
    return checks._checked(cid, fn)()


def test_unconfigured_backup_is_not_a_pass():
    result = m.MaintenanceChecks().backup()
    assert result.severity == Severity.WARN
    assert result.details["verified"] is False


@pytest.mark.parametrize(
    "verified,completed,status,expected",
    [
        (True, RECENT, "success", Severity.PASS),
        (True, OLD, "success", Severity.WARN),
        (False, RECENT, "success", Severity.WARN),
        (True, RECENT, "exit-code", Severity.WARN),
    ],
)
def test_backup_requires_verified_recent_copy(monkeypatch, verified, completed, status, expected):
    config = DotDoctorConfig(
        maintenance=MaintenanceConfig(
            backup=BackupConfig(
                service="backup.service",
                status_command=["backup-status"],
                required_before_upgrade=True,
            )
        )
    )
    checks = m.MaintenanceChecks(config)
    monkeypatch.setattr(m, "properties", lambda *args: {**healthy_service(), "Result": status})
    monkeypatch.setattr(
        m, "read_json", lambda *args: {"completed_at": completed, "verified": verified}
    )
    result = checks.backup()
    assert result.severity == expected
    assert result.details["blocks_upgrade"] == (expected != Severity.PASS)


def test_required_backup_unavailable_blocks_upgrade(monkeypatch):
    config = DotDoctorConfig(
        maintenance=MaintenanceConfig(
            backup=BackupConfig(
                service="backup.service",
                status_command=["backup-status"],
                required_before_upgrade=True,
            )
        )
    )

    def unavailable(*args):
        raise ValueError("permission denied")

    monkeypatch.setattr(m, "properties", unavailable)
    checks = m.MaintenanceChecks(config)
    result = checked(checks, "sys.backup", checks.backup)
    assert result.details["blocks_upgrade"] is True
    assert result.severity == Severity.WARN


def test_future_backup_not_accepted(monkeypatch):
    checks = m.MaintenanceChecks(
        DotDoctorConfig(
            maintenance=MaintenanceConfig(
                backup=BackupConfig(service="backup.service", status_command=["status"])
            )
        )
    )
    monkeypatch.setattr(m, "properties", lambda *args: healthy_service())
    monkeypatch.setattr(
        m, "read_json", lambda *args: {"completed_at": NOW + 3600, "verified": True}
    )
    assert checked(checks, "sys.backup", checks.backup).severity == Severity.WARN


def test_active_timer_with_failed_service_is_not_healthy(monkeypatch):
    def props(unit, scope="system", timer=False):
        if timer:
            return {"ActiveState": "active", "Triggers": unit.replace(".timer", ".service")}
        return {**healthy_service(), "Result": "exit-code", "ExecMainStatus": "1"}

    monkeypatch.setattr(m, "properties", props)
    result = m.MaintenanceChecks().timers()
    assert result.severity == Severity.WARN
    assert "last job failed (Result=exit-code, exit=1)" in result.details["items"][0]
    assert result.details["timers"] == []


@pytest.mark.parametrize(
    ("values", "finding"),
    [
        ({"ExecMainExitTimestamp": ""}, "no completed execution recorded"),
        ({"ConditionResult": "no"}, "service skipped by condition"),
        ({"AssertResult": "no"}, "service assertion failed"),
    ],
)
def test_timer_distinguishes_unverified_jobs_from_failed_executions(monkeypatch, values, finding):
    def props(unit, scope="system", timer=False):
        if timer:
            return {"ActiveState": "active", "Triggers": "clean.service"}
        return {**healthy_service(), **values}

    monkeypatch.setattr(m, "properties", props)
    result = m.MaintenanceChecks().timers()
    assert result.severity == Severity.WARN
    assert finding in result.details["items"][0]
    assert "last job failed" not in result.details["items"][0]
    assert result.details["timers"] == []


def test_timer_success_never_inferred_from_last_trigger(monkeypatch):
    def props(unit, scope="system", timer=False):
        if timer:
            return {"ActiveState": "active", "LastTriggerUSec": RECENT, "Triggers": "clean.service"}
        return {**healthy_service(), "ExecMainExitTimestamp": OLD}

    monkeypatch.setattr(m, "properties", props)
    assert m.MaintenanceChecks().timers().severity == Severity.WARN


def test_only_expected_timers_get_repair_actions(monkeypatch):
    config = DotDoctorConfig(
        maintenance=MaintenanceConfig(timers=[TimerConfig(unit="backup.timer", scope="user")])
    )

    def props(unit, scope="system", timer=False):
        if timer:
            return {"ActiveState": "inactive", "Triggers": "clean.service"}
        return healthy_service()

    monkeypatch.setattr(m, "properties", props)
    result = m.MaintenanceChecks(config).timers()
    assert {t["unit"] for t in result.details["timers"]} == {
        "backup.timer",
        "systemd-tmpfiles-clean.timer",
    }


@pytest.mark.parametrize("discard", ["discard", "discard=async", "discard=sync"])
def test_continuous_trim_does_not_require_timer(monkeypatch, discard):
    monkeypatch.setattr(
        m,
        "read_json",
        lambda *args: {
            "blockdevices": [{"path": "/dev/nvme0n1", "disc-max": 100, "mountpoints": ["/"]}]
        },
    )
    monkeypatch.setattr(
        m, "mounted_filesystems", lambda: [{"target": "/", "options": f"rw,{discard}"}]
    )
    assert m.MaintenanceChecks().trim().severity == Severity.PASS


@pytest.mark.parametrize("completion", [RECENT, OLD, ""])
def test_trim_uses_last_success_and_handles_never_run(monkeypatch, completion):
    monkeypatch.setattr(
        m, "read_json", lambda *args: {"blockdevices": [{"disc-max": 100, "mountpoints": ["/"]}]}
    )
    monkeypatch.setattr(m, "mounted_filesystems", lambda: [{"target": "/", "options": "rw"}])

    def props(unit, **kwargs):
        return {**healthy_service(), "ActiveState": "active", "ExecMainExitTimestamp": completion}

    monkeypatch.setattr(m, "properties", props)
    result = m.MaintenanceChecks().trim()
    assert result.severity == (Severity.PASS if completion == RECENT else Severity.WARN)
    if completion != RECENT:
        assert result.details["actionable"] is True


def test_news_acknowledgement_persists_only_reviewed_links(monkeypatch, tmp_path):
    items = [{"title": "Manual intervention", "url": "https://archlinux.org/news/test/"}]
    monkeypatch.setattr(m, "fetch_news", lambda: items)
    checks = m.MaintenanceChecks()
    assert checks.news().details["requires_review"]
    m.MaintenanceState().acknowledge_news([items[0]["url"]])
    assert checks.news().severity == Severity.PASS
    items.append({"title": "Another change", "url": "https://archlinux.org/news/another/"})
    assert len(checks.news().details["notices"]) == 1
    assert oct(m.MaintenanceState().path.stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize("data", ["{broken", "[]", '{"news": {}}'])
def test_corrupt_news_state_is_never_a_pass(tmp_path, data):
    state = m.MaintenanceState()
    state.path.parent.mkdir(parents=True)
    state.path.write_text(data)
    checks = m.MaintenanceChecks()
    assert checked(checks, "sys.news", checks.news).severity == Severity.WARN


@pytest.mark.parametrize(
    "stdout,code,expected",
    [
        ("", 0, Severity.PASS),
        ("openssl\tHigh\t3.0-2\tCVE-2026-0001\n", 0, Severity.FAIL),
        ("openssl\tHigh\t\tCVE-2026-0001\n", 0, Severity.FAIL),
        ("", 1, Severity.WARN),
        ("unknown format", 0, Severity.WARN),
    ],
)
def test_security_includes_unfixed_and_rejects_errors(monkeypatch, stdout, code, expected):
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/arch-audit")
    commands = []

    def capture(cmd, *args):
        commands.append(cmd)
        return response(stdout, code)

    monkeypatch.setattr(m, "capture", capture)
    checks = m.MaintenanceChecks()
    result = checked(checks, "sys.security", checks.security)
    assert result.severity == expected
    assert "--upgradable" not in commands[0]
    if expected == Severity.FAIL:
        assert result.details["blocks_upgrade"] is False


def test_missing_security_tool_is_unknown():
    assert m.MaintenanceChecks().security().severity == Severity.WARN


@pytest.mark.parametrize(
    "payload,code,expected,block",
    [
        ({"smart_status": {"passed": True}}, 0, Severity.PASS, False),
        ({"smart_status": {"passed": False}}, 8, Severity.FAIL, True),
        ({"smart_status": {"passed": True}}, 64, Severity.WARN, False),
        ({"smart_status": {"passed": True}}, 2, Severity.WARN, False),
        ({}, 3, Severity.WARN, False),
        (
            {
                "smart_status": {"passed": True},
                "nvme_smart_health_information_log": {"critical_warning": 1},
            },
            0,
            Severity.FAIL,
            True,
        ),
        (
            {
                "smart_status": {"passed": True},
                "nvme_smart_health_information_log": {"media_errors": 1},
            },
            0,
            Severity.WARN,
            False,
        ),
    ],
)
def test_smart_decodes_bitmask_and_current_health(monkeypatch, payload, code, expected, block):
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/smartctl")
    monkeypatch.setattr(
        m, "read_json", lambda *args: {"blockdevices": [{"path": "/dev/nvme0n1", "type": "disk"}]}
    )
    commands = []

    def capture(cmd, *args):
        commands.append(cmd)
        return response(json.dumps(payload), code)

    monkeypatch.setattr(m, "capture", capture)
    result = m.MaintenanceChecks().smart()
    assert result.severity == expected
    assert result.details["blocks_upgrade"] is block
    assert "-t" not in commands[0]
    if commands[0][0] == "sudo":
        assert commands[0][1] == "-n"


def test_smart_pending_sectors_are_critical(monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/smartctl")
    monkeypatch.setattr(
        m, "read_json", lambda *args: {"blockdevices": [{"path": "/dev/sda", "type": "disk"}]}
    )
    payload = {
        "smart_status": {"passed": True},
        "ata_smart_attributes": {"table": [{"id": 197, "raw": {"value": 2}}]},
    }
    monkeypatch.setattr(m, "capture", lambda *args: response(json.dumps(payload)))
    assert m.MaintenanceChecks().smart().details["blocks_upgrade"]


@pytest.mark.parametrize(
    "stats,scrub,expected,targets",
    [
        (
            0,
            f"Scrub started: {RECENT}\nStatus: finished\nuncorrectable_errors: 0\n",
            Severity.PASS,
            [],
        ),
        (
            0,
            f"Scrub started: {OLD}\nStatus: finished\nuncorrectable_errors: 0\n",
            Severity.WARN,
            ["/"],
        ),
        (
            0,
            f"Scrub started: {RECENT}\nStatus: finished\nuncorrectable_errors: 2\n",
            Severity.FAIL,
            [],
        ),
        (1, "", Severity.WARN, []),
        (0, "Status: running\nuncorrectable_errors: 0", Severity.WARN, []),
    ],
)
def test_btrfs_deduplicates_subvolumes_and_never_repairs_errors(
    monkeypatch, stats, scrub, expected, targets
):
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/btrfs")
    monkeypatch.setattr(
        m,
        "mounted_filesystems",
        lambda: [
            {"target": "/", "fstype": "btrfs", "uuid": "same", "source": "/dev/sda[/@]"},
            {"target": "/home", "fstype": "btrfs", "uuid": "same", "source": "/dev/sda[/@home]"},
        ],
    )
    commands = []

    def capture(cmd, *args):
        commands.append(cmd)
        return response(f"[/dev/sda].read_io_errs {stats}\n" if "stats" in cmd else scrub)

    monkeypatch.setattr(m, "capture", capture)
    result = m.MaintenanceChecks().btrfs()
    assert result.severity == expected
    assert result.details.get("scrub_targets", []) == targets
    assert len(commands) <= 2
    assert all("start" not in command for command in commands)


def test_integrity_filters_native_repair_targets(monkeypatch):
    def capture(cmd, *args):
        if cmd[:2] == ["pacman", "-Qkq"]:
            return response("bash /usr/bin/bash\ncustom /usr/bin/custom\n", 1)
        assert cmd[:2] == ["pacman", "-Qnq"]
        return response("bash\n", 1)

    monkeypatch.setattr(m, "capture", capture)
    result = m.MaintenanceChecks().integrity()
    assert result.severity == Severity.FAIL
    assert result.details["reinstall_packages"] == ["bash"]


def test_integrity_failed_empty_output_is_unknown(monkeypatch):
    monkeypatch.setattr(m, "capture", lambda *args: response("", 1))
    checks = m.MaintenanceChecks()
    assert checked(checks, "sys.integrity", checks.integrity).severity == Severity.WARN


def test_rebuild_parses_actual_package_repository_columns(monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda name: "/bin/checkrebuild")
    monkeypatch.setattr(
        m,
        "capture",
        lambda cmd, *args: response("custom\n" if cmd[0] == "pacman" else "custom\tforeign\n"),
    )
    assert m.MaintenanceChecks().rebuild().details["rebuild_packages"] == ["custom"]


def test_checked_timeout_is_unknown(monkeypatch):
    def timed_out(*args):
        raise subprocess.TimeoutExpired(["pacman"], 60)

    monkeypatch.setattr(m, "capture", timed_out)
    checks = m.MaintenanceChecks()
    assert checked(checks, "sys.integrity", checks.integrity).severity == Severity.WARN


def test_disabled_preflight_checks_are_not_run(monkeypatch, tmp_path):
    checks = m.MaintenanceChecks(DotDoctorConfig(disabled_checks=["sys:backup"]))
    monkeypatch.setattr(
        checks,
        "registrations",
        lambda context: [("sys.backup", "backup", lambda: pytest.fail("disabled check executed"))],
    )
    context = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    assert checks.run(context, m.PREFLIGHT_IDS) == []


def test_reader_never_requests_stdin_and_sets_locale(monkeypatch):
    calls = []

    def fake(cmd, **kwargs):
        calls.append(kwargs)
        return response()

    monkeypatch.setattr(readers.subprocess, "run", fake)
    readers.capture(["systemctl", "show", "test.timer"])
    assert calls[0]["stdin"] == subprocess.DEVNULL
    assert calls[0]["env"]["LC_ALL"] == "C"


def test_corrupt_state_not_overwritten(tmp_path):
    state = readers.MaintenanceState(tmp_path / "state.json")
    state.path.write_text("bad")
    with pytest.raises(ValueError):
        state.acknowledge_news(["https://archlinux.org/news/test/"])
    assert state.path.read_text() == "bad"


@pytest.mark.parametrize("failure", ["none", "missing", "files", "clock"])
def test_keyring_distinguishes_missing_files_and_unsynchronized_clock(monkeypatch, failure):
    commands = []

    def capture(cmd, *args):
        commands.append(cmd)
        if cmd[0] == "timedatectl":
            return response("no" if failure == "clock" else "yes")
        return response(
            returncode=int(
                (failure == "missing" and "-Q" in cmd) or (failure == "files" and "-Qk" in cmd)
            )
        )

    monkeypatch.setattr(m, "capture", capture)
    result = m.MaintenanceChecks().keyring()
    expected = {
        "none": Severity.PASS,
        "missing": Severity.FAIL,
        "files": Severity.FAIL,
        "clock": Severity.WARN,
    }
    assert result.severity == expected[failure]
    assert result.details.get("blocks_upgrade", False) == (failure in {"missing", "files"})
    assert commands[0] == ["pacman", "-Q", "--", "archlinux-keyring"]


@pytest.mark.parametrize(
    "options,free_bytes,inodes,expected",
    [
        ("rw", 1024**3, 100, Severity.PASS),
        ("ro", 1024**3, 100, Severity.FAIL),
        ("rw", 10, 100, Severity.FAIL),
        ("rw", 1024**3, 5, Severity.WARN),
        ("rw", 1024**3, 0, Severity.FAIL),
    ],
)
def test_capacity_checks_read_only_mounts_space_and_inodes(
    monkeypatch, options, free_bytes, inodes, expected
):
    monkeypatch.setattr(m, "mounted_filesystems", lambda: [{"target": "/", "options": options}])
    monkeypatch.setattr(
        m.os,
        "statvfs",
        lambda path: SimpleNamespace(
            f_bavail=free_bytes, f_frsize=1, f_files=1000, f_favail=inodes
        ),
    )
    result = m.MaintenanceChecks().mounts()
    assert result.severity == expected
    assert result.details.get("blocks_upgrade", False) == (expected == Severity.FAIL)


@pytest.mark.parametrize("property_name", ["ConditionResult", "AssertResult"])
def test_skipped_service_does_not_count_as_a_successful_job(property_name):
    assert not m.service_succeeded({**healthy_service(), property_name: "no"})


@pytest.mark.parametrize(
    "value",
    [
        {"backup": {"service": "--bad.service", "status_command": ["status"]}},
        {"backup": {"service": "ok.service", "status_command": [""]}},
        {"timers": [{"unit": "--bad.timer"}]},
        {"keyring_packages": ["--noconfirm"]},
        {"keyring_packages": []},
    ],
)
def test_config_rejects_invalid_command_targets(value):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        MaintenanceConfig.model_validate(value)


def test_parallel_scan_routes_registered_checks_and_respects_disables(monkeypatch, tmp_path):
    from dotdoctor.application.system_update import SystemDryRunService
    from dotdoctor.domain.models import CheckResult

    monkeypatch.setattr(m.shutil, "which", lambda name: f"/bin/{name}")
    config = DotDoctorConfig(disabled_checks=["sys:keyring"])
    monkeypatch.setattr(
        m.MaintenanceChecks,
        "security",
        lambda self: CheckResult(
            check_id="sys.security", severity=Severity.FAIL, message="known vulnerability"
        ),
    )
    ctx = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    report = SystemDryRunService(is_online_fn=lambda: True, config=config).run(
        ctx,
        disabled_checks=config.disabled_checks,
        include_checks=frozenset({"sys.keyring", "sys.backup", "sys.security"}),
    )
    assert {item.check_id for item in report.results} == {"sys.backup", "sys.security"}
    assert report.exit_code == 2


def test_offline_scan_never_fetches_news_or_security(monkeypatch, tmp_path):
    from dotdoctor.application.system_update import SystemDryRunService

    monkeypatch.setattr(m.shutil, "which", lambda name: f"/bin/{name}")
    ctx = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    report = SystemDryRunService(is_online_fn=lambda: False).run(
        ctx, include_checks=frozenset({"sys.news", "sys.security"})
    )
    offline = [item for item in report.results if item.check_id in {"sys.news", "sys.security"}]
    assert len(offline) == 2
    assert all(item.severity == Severity.WARN for item in offline)


def test_missing_mount_information_cannot_report_healthy_capacity(monkeypatch):
    monkeypatch.setattr(m, "mounted_filesystems", lambda: [])
    checks = m.MaintenanceChecks()
    result = checked(checks, "sys.mounts", checks.mounts)
    assert result.severity == Severity.WARN
    assert result.details["verified"] is False


def test_expected_inactive_timer_can_be_enabled_before_its_first_run(monkeypatch):
    monkeypatch.setattr(
        m,
        "properties",
        lambda unit, scope="system", timer=False: (
            {"ActiveState": "inactive", "Triggers": "systemd-tmpfiles-clean.service"}
            if timer
            else {**healthy_service(), "ExecMainExitTimestamp": ""}
        ),
    )
    result = m.MaintenanceChecks().timers()
    assert result.severity == Severity.WARN
    assert result.details["timers"] == [{"unit": "systemd-tmpfiles-clean.timer", "scope": "system"}]


def test_smart_ignores_virtual_and_zram_devices(monkeypatch):
    monkeypatch.setattr(m.shutil, "which", lambda name: "/usr/bin/smartctl")
    monkeypatch.setattr(
        m,
        "read_json",
        lambda *args: {
            "blockdevices": [
                {"path": "/dev/zram0", "type": "disk"},
                {"path": "/dev/loop0", "type": "disk"},
                {"path": "/dev/ram0", "type": "disk"},
                {"path": "/dev/nvme0n1", "type": "disk"},
            ]
        },
    )
    checked_devices = []

    def capture(cmd, *args):
        checked_devices.append(cmd[-1])
        return response(json.dumps({"smart_status": {"passed": True}}), 0)

    monkeypatch.setattr(m, "capture", capture)
    result = m.MaintenanceChecks().smart()
    assert result.severity == Severity.PASS
    assert checked_devices == ["/dev/nvme0n1"]


def test_mounts_esp_threshold(monkeypatch):
    monkeypatch.setattr(
        m,
        "mounted_filesystems",
        lambda: [
            {"target": "/", "options": "rw"},
            {"target": "/boot/efi", "options": "rw"},
        ],
    )

    def statvfs(target):
        if target == "/":
            return SimpleNamespace(
                f_bavail=10 * 1024**3,
                f_frsize=1,
                f_blocks=100 * 1024**3,
                f_files=1000,
                f_favail=500,
            )
        return SimpleNamespace(
            f_bavail=33 * 1024**2,
            f_frsize=1,
            f_blocks=96 * 1024**2,
            f_files=1000,
            f_favail=500,
        )

    monkeypatch.setattr(m.os, "statvfs", statvfs)
    result = m.MaintenanceChecks().mounts()
    assert result.severity == Severity.PASS


def test_mounts_esp_fails_when_critically_low(monkeypatch):
    monkeypatch.setattr(
        m,
        "mounted_filesystems",
        lambda: [
            {"target": "/", "options": "rw"},
            {"target": "/boot/efi", "options": "rw"},
        ],
    )

    def statvfs(target):
        if target == "/":
            return SimpleNamespace(
                f_bavail=10 * 1024**3,
                f_frsize=1,
                f_blocks=100 * 1024**3,
                f_files=1000,
                f_favail=500,
            )
        return SimpleNamespace(
            f_bavail=2 * 1024**2,
            f_frsize=1,
            f_blocks=96 * 1024**2,
            f_files=1000,
            f_favail=500,
        )

    monkeypatch.setattr(m.os, "statvfs", statvfs)
    result = m.MaintenanceChecks().mounts()
    assert result.severity == Severity.FAIL
    assert result.details["blocks_upgrade"] is True
    assert any(
        "/boot/efi: critically low available space" in item for item in result.details["items"]
    )


def test_uninstalled_tools_not_registered(monkeypatch, tmp_path):
    ctx = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    installed = {
        "pacman": "/usr/bin/pacman",
        "lsblk": "/usr/bin/lsblk",
        "findmnt": "/usr/bin/findmnt",
    }
    monkeypatch.setattr(m.shutil, "which", lambda name: installed.get(name))
    checks = m.MaintenanceChecks()
    registered_ids = {cid for cid, _, _ in checks.registrations(ctx)}

    assert "sys.security" not in registered_ids
    assert "sys.rebuild" not in registered_ids
    assert "sys.smart" not in registered_ids
    assert "sys.btrfs" not in registered_ids

    assert "sys.keyring" in registered_ids
    assert "sys.package-db" in registered_ids
    assert "sys.trim" in registered_ids
    assert "sys.mounts" in registered_ids


def test_installed_tools_are_registered(monkeypatch, tmp_path):
    ctx = ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")
    monkeypatch.setattr(m.shutil, "which", lambda name: f"/usr/bin/{name}")
    checks = m.MaintenanceChecks()
    registered_ids = {cid for cid, _, _ in checks.registrations(ctx)}

    assert "sys.security" in registered_ids
    assert "sys.rebuild" in registered_ids
    assert "sys.smart" in registered_ids
    assert "sys.btrfs" in registered_ids
