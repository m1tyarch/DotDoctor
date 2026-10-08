import io
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from dotdoctor.application.system_update import (
    FIX_CHECK_IDS,
    UPDATE_CHECK_IDS,
    DiskSpaceStatus,
    RebootStatus,
    SystemDryRunService,
    SystemUpgradeService,
    detect_aur_helper,
    detect_disk_space_status,
    detect_pacnew_files,
    detect_reboot_status,
    is_online,
)
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import Severity


class DummyConsole:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.width: int = 80

    def print(self, message: object = "") -> None:
        self.messages.append(getattr(message, "plain", str(message)))


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        profile="system",
        cwd=tmp_path,
        home=tmp_path,
        path_value="/usr/bin",
        shell="/bin/bash",
    )


def test_system_dry_run_marks_outd_when_updates_detected(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        return f"/usr/bin/{name}"

    def fake_run(*args, **kwargs):
        command = args[0]
        if command[:1] == ["checkupdates"]:
            return SimpleNamespace(stdout="pkg1\npkg2\n", returncode=0)
        if command[:3] == ["flatpak", "remote-ls", "--updates"]:
            return SimpleNamespace(stdout="app.one\n", returncode=0)
        if command[:2] == ["fwupdmgr", "refresh"]:
            return SimpleNamespace(stdout="", returncode=0)
        if command[:2] == ["fwupdmgr", "get-updates"]:
            return SimpleNamespace(stdout="1.2.3 -> 1.2.4\n", returncode=0)
        if command[:2] in (["yay", "-Qua"], ["paru", "-Qua"]):
            return SimpleNamespace(stdout="aur/pkg-a 1.0-1 2.0-1\n", returncode=0)
        if "rev-list" in command:
            return SimpleNamespace(stdout="0\n", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_reboot_status",
        lambda: RebootStatus(
            required=False,
            reason=None,
            running_kernel="7.1.9",
            installed_kernels=["7.1.9"],
        ),
    )
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_disk_space_status",
        lambda: DiskSpaceStatus(
            root_free_bytes=50 * 1024**3,
            boot_free_bytes=500 * 1024**2,
            severity=Severity.PASS,
            message="Disk space is healthy.",
            remediation=None,
        ),
    )

    (tmp_path / ".oh-my-zsh" / ".git").mkdir(parents=True)
    report = service.run(_context(tmp_path))

    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.packages"].severity is Severity.OUTD
    assert by_id["sys.flatpak"].severity is Severity.OUTD
    assert by_id["sys.firmware"].severity is Severity.OUTD
    assert by_id["sys.aur"].severity is Severity.OUTD
    assert by_id["sys.shell-omz"].severity is Severity.PASS
    assert by_id["sys.reboot"].severity is Severity.PASS
    assert by_id["sys.disk"].severity is Severity.PASS


def test_system_dry_run_skips_missing_components(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_reboot_status",
        lambda: RebootStatus(
            required=False,
            reason=None,
            running_kernel="7.1.9",
            installed_kernels=["7.1.9"],
        ),
    )
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_disk_space_status",
        lambda: DiskSpaceStatus(
            root_free_bytes=50 * 1024**3,
            boot_free_bytes=500 * 1024**2,
            severity=Severity.PASS,
            message="Disk space is healthy.",
            remediation=None,
        ),
    )

    report = service.run(_context(tmp_path))

    assert "sys.shell-omz" not in {item.check_id for item in report.results}
    assert all(item.severity is Severity.PASS for item in report.results)


def test_system_dry_run_omz_uses_zsh_env_and_detects_updates(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    omz = tmp_path / "custom-omz"
    (omz / ".git").mkdir(parents=True)

    monkeypatch.setenv("ZSH", str(omz))

    def fake_which(name: str) -> str | None:
        if name in {"git"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command[:3] == ["git", "-C", str(omz)] and command[3:] == ["fetch", "--quiet", "origin"]:
            return SimpleNamespace(stdout="", returncode=0)
        if command[:3] == ["git", "-C", str(omz)] and command[3:] == [
            "rev-list",
            "--count",
            "HEAD..origin/master",
        ]:
            return SimpleNamespace(stdout="2\n", returncode=0)
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.shell-omz"].severity is Severity.OUTD


def test_system_dry_run_treats_checkupdates_exit_two_as_no_updates(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "checkupdates":
            return "/usr/bin/checkupdates"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command[:1] == ["checkupdates"]:
            return SimpleNamespace(stdout="", returncode=2)
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.packages"].severity is Severity.PASS


@pytest.mark.parametrize("output_stream", ["stdout", "stderr"])
@pytest.mark.parametrize(
    ("error", "severity", "remediation"),
    [
        ("==> ERROR: Cannot find the fakeroot binary", Severity.WARN, "sudo pacman -Syu fakeroot"),
        ("error: failed to synchronize all databases", Severity.FAIL, "checkupdates"),
        ("", Severity.FAIL, "checkupdates"),
    ],
)
def test_checkupdates_failure_explains_the_cause(
    monkeypatch, tmp_path, output_stream, error, severity, remediation
):
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda name: f"/usr/bin/{name}"
    )
    completed = SimpleNamespace(returncode=1, stdout="", stderr="")
    setattr(completed, output_stream, error)
    monkeypatch.setattr(
        "dotdoctor.application.system_update.subprocess.run", lambda *args, **kwargs: completed
    )

    result = SystemDryRunService()._check_arch_packages(_context(tmp_path))

    assert result.severity == severity
    assert result.remediation == remediation
    assert result.details["verified"] is False
    assert result.details["returncode"] == 1
    assert result.details["items"] == [error or "command returned no error output"]
    if severity == Severity.WARN:
        assert "fakeroot" in result.message
        assert "updates are not verified" in result.message
    else:
        assert "exit=1" in result.message


def test_system_dry_run_firmware_latest_available_is_not_counted_as_updates(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "fwupdmgr":
            return "/usr/bin/fwupdmgr"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command[:2] == ["fwupdmgr", "refresh"]:
            return SimpleNamespace(stdout="", returncode=0)
        if command[:2] == ["fwupdmgr", "get-updates"]:
            return SimpleNamespace(
                stdout=(
                    "Devices with the latest available firmware version:\n"
                    "  Device A\n"
                    "\n"
                    "Devices with no available firmware updates:\n"
                    "  Device B\n"
                ),
                returncode=0,
            )
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.firmware"].severity is Severity.PASS
    assert by_id["sys.firmware"].message == "no firmware updates"


def test_system_dry_run_firmware_detects_explicit_version_transition(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "fwupdmgr":
            return "/usr/bin/fwupdmgr"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command[:2] == ["fwupdmgr", "refresh"]:
            return SimpleNamespace(stdout="", returncode=0)
        if command[:2] == ["fwupdmgr", "get-updates"]:
            return SimpleNamespace(
                stdout=("Device: Sample Device\n" "Current version: 1.2.3\n" "1.2.3 -> 1.2.4\n"),
                returncode=0,
            )
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.firmware"].severity is Severity.OUTD


def test_system_upgrade_runs_steps_and_reports_success(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()

    commands: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        if name in {"yay", "flatpak", "fwupdmgr", "cachyos-rate-mirrors"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        commands.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    omz_dir = tmp_path / ".oh-my-zsh" / "tools"
    omz_dir.mkdir(parents=True)
    (omz_dir / "upgrade.sh").write_text("echo upgrade", encoding="utf-8")

    code = service.run(_context(tmp_path), console)

    assert code == 0
    assert ["sudo", "true"] in commands
    assert ["sudo", "cachyos-rate-mirrors"] in commands
    assert [
        "yay",
        "-Syu",
        "--noconfirm",
        "--sudoloop",
        "--answerclean",
        "None",
        "--answerdiff",
        "None",
    ] in commands
    assert ["flatpak", "update", "-y"] in commands
    assert ["fwupdmgr", "update", "-y"] in commands
    assert ["sh", str(omz_dir / "upgrade.sh")] in commands


def test_check_aur_detects_flagged_packages(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "yay":
            return "/usr/bin/yay"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command[:2] == ["yay", "-Qua"]:
            return SimpleNamespace(
                stdout="aur/pkg-a 1.0-1 2.0-1\naur/pkg-b 3.0-1 [out-of-date]\n",
                returncode=0,
            )
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.aur"].severity is Severity.OUTD
    assert by_id["sys.aur"].details["flagged"] == 1
    assert by_id["sys.aur"].details["updates"] == 1


def test_check_arch_timeout_produces_unverified_warning(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "checkupdates":
            return "/usr/bin/checkupdates"
        return None

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=60)

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.packages"].severity is Severity.WARN
    assert by_id["sys.packages"].details["verified"] is False


def test_system_upgrade_network_failure_triggers_mirror_recovery(
    monkeypatch, tmp_path: Path
) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()
    commands: list[list[str]] = []
    yay_attempt = [0]
    expected_yay_cmd = [
        "yay",
        "-Syu",
        "--noconfirm",
        "--sudoloop",
        "--answerclean",
        "None",
        "--answerdiff",
        "None",
    ]

    def fake_which(name: str) -> str | None:
        if name in {"yay", "cachyos-rate-mirrors"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        commands.append(command)
        if command == ["sudo", "true"]:
            return SimpleNamespace(returncode=0, stderr="")
        if command == ["sudo", "cachyos-rate-mirrors"]:
            return SimpleNamespace(returncode=0, stderr="")
        if command == expected_yay_cmd:
            yay_attempt[0] += 1
            if yay_attempt[0] == 1:
                return SimpleNamespace(returncode=1, stderr="failed to retrieve some files")
            return SimpleNamespace(returncode=0, stderr="")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)

    yay_calls = sum(1 for c in commands if c == expected_yay_cmd)
    mirror_calls = sum(1 for c in commands if c == ["sudo", "cachyos-rate-mirrors"])
    assert yay_calls == 2
    assert mirror_calls == 2
    assert code == 0
    assert any("mirror" in msg.lower() or "network" in msg.lower() for msg in console.messages)


def test_system_upgrade_fatal_network_error_returns_exit_one(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()
    expected_yay_cmd = [
        "yay",
        "-Syu",
        "--noconfirm",
        "--sudoloop",
        "--answerclean",
        "None",
        "--answerdiff",
        "None",
    ]

    def fake_which(name: str) -> str | None:
        if name in {"yay", "cachyos-rate-mirrors"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command == ["sudo", "true"]:
            return SimpleNamespace(returncode=0, stderr="")
        if command == ["sudo", "cachyos-rate-mirrors"]:
            return SimpleNamespace(returncode=0, stderr="")
        if command == expected_yay_cmd:
            return SimpleNamespace(returncode=1, stderr="failed to retrieve some files")
        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)
    assert code == 1
    assert any("FAIL" in msg for msg in console.messages)


def test_detect_reboot_status_matching_kernel(tmp_path: Path) -> None:
    modules_dir = tmp_path / "modules"
    (modules_dir / "7.1.9-arch1-2").mkdir(parents=True)

    status = detect_reboot_status(
        modules_dir=modules_dir,
        running_kernel="7.1.9-arch1-2",
        marker_paths=(),
    )
    assert status.required is False
    assert status.reason is None
    assert status.installed_kernels == ["7.1.9-arch1-2"]


def test_detect_reboot_status_kernel_mismatch(tmp_path: Path) -> None:
    modules_dir = tmp_path / "modules"
    (modules_dir / "7.1.11-arch1-1").mkdir(parents=True)

    status = detect_reboot_status(
        modules_dir=modules_dir,
        running_kernel="7.1.9-arch1-2",
        marker_paths=(),
    )
    assert status.required is True
    assert "7.1.9-arch1-2" in status.reason
    assert "7.1.11-arch1-1" in status.reason
    assert status.installed_kernels == ["7.1.11-arch1-1"]


def test_detect_reboot_status_marker_file(tmp_path: Path) -> None:
    modules_dir = tmp_path / "modules"
    (modules_dir / "7.1.9").mkdir(parents=True)
    marker = tmp_path / "reboot-required"
    marker.write_text("", encoding="utf-8")

    status = detect_reboot_status(
        modules_dir=modules_dir,
        running_kernel="7.1.9",
        marker_paths=(str(marker),),
    )
    assert status.required is True
    assert "reboot-required" in status.reason


def test_detect_reboot_status_marker_file_with_packages(tmp_path: Path) -> None:
    modules_dir = tmp_path / "modules"
    (modules_dir / "7.1.9").mkdir(parents=True)
    marker = tmp_path / "reboot-required"
    marker.write_text("", encoding="utf-8")
    pkgs = tmp_path / "reboot-required.pkgs"
    pkgs.write_text("linux\nsystemd\n", encoding="utf-8")

    status = detect_reboot_status(
        modules_dir=modules_dir,
        running_kernel="7.1.9",
        marker_paths=(str(marker),),
    )
    assert status.required is True
    assert "linux, systemd" in status.reason


def test_system_dry_run_warns_when_reboot_required(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", lambda _: None)
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_reboot_status",
        lambda: RebootStatus(
            required=True,
            reason="Running kernel (7.1.9) differs from installed kernel (7.1.11).",
            running_kernel="7.1.9",
            installed_kernels=["7.1.11"],
        ),
    )

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}
    assert by_id["sys.reboot"].severity is Severity.WARN
    assert "7.1.9" in by_id["sys.reboot"].message
    assert by_id["sys.reboot"].details["reboot_required"] is True


def test_system_upgrade_prints_reboot_warning_when_needed(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()

    def fake_which(name: str) -> str | None:
        if name in {"yay"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_reboot_status",
        lambda: RebootStatus(
            required=True,
            reason="Running kernel (7.1.9) differs from installed kernel (7.1.11).",
            running_kernel="7.1.9",
            installed_kernels=["7.1.11"],
        ),
    )

    code = service.run(_context(tmp_path), console)
    assert code == 0
    assert any("reboot recommended" in msg.lower() for msg in console.messages)
    assert any("7.1.11" in msg for msg in console.messages)


def test_detect_disk_space_status_healthy(tmp_path: Path) -> None:
    status = detect_disk_space_status(
        root_path=tmp_path,
        boot_path=tmp_path,
        min_root_warn_bytes=1000,
        min_root_crit_bytes=100,
        min_boot_warn_bytes=1000,
        min_boot_crit_bytes=100,
    )
    assert status.severity is Severity.PASS
    assert "free on" in status.message


def test_detect_disk_space_status_warn(tmp_path: Path) -> None:
    status = detect_disk_space_status(
        root_path=tmp_path,
        boot_path=tmp_path,
        min_root_warn_bytes=10**15,  # huge threshold to trigger WARN
        min_root_crit_bytes=100,
        min_boot_warn_bytes=1000,
        min_boot_crit_bytes=100,
    )
    assert status.severity is Severity.WARN
    assert "low disk space" in status.message


def test_detect_disk_space_status_critical_fail(tmp_path: Path) -> None:
    status = detect_disk_space_status(
        root_path=tmp_path,
        boot_path=tmp_path,
        min_root_warn_bytes=10**15,
        min_root_crit_bytes=10**15,  # huge threshold to trigger FAIL
        min_boot_warn_bytes=1000,
        min_boot_crit_bytes=100,
    )
    assert status.severity is Severity.FAIL
    assert "critically low disk space" in status.message


def test_system_upgrade_aborts_on_critical_disk_space(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()

    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_disk_space_status",
        lambda: DiskSpaceStatus(
            root_free_bytes=100 * 1024**2,
            boot_free_bytes=10 * 1024**2,
            severity=Severity.FAIL,
            message="Critically low disk space (/ free: 100.0 MiB, /boot free: 10.0 MiB).",
            remediation="Free up space.",
        ),
    )

    code = service.run(_context(tmp_path), console)
    assert code == 1
    assert any("Aborting update to prevent system corruption" in msg for msg in console.messages)


def test_is_online_success(monkeypatch) -> None:
    class DummySocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: DummySocket())
    assert is_online() is True


def test_is_online_failure(monkeypatch) -> None:
    def fake_connect(*args, **kwargs):
        raise OSError("Network unreachable")

    monkeypatch.setattr("socket.create_connection", fake_connect)
    assert is_online() is False


def test_system_dry_run_offline_skips_network_checks(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "dotdoctor.application.system_update.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout="", stderr="", returncode=0),
    )
    service = SystemDryRunService(is_online_fn=lambda: False)

    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_reboot_status",
        lambda: RebootStatus(
            required=False,
            reason=None,
            running_kernel="7.1.9",
            installed_kernels=["7.1.9"],
        ),
    )
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_disk_space_status",
        lambda: DiskSpaceStatus(
            root_free_bytes=50 * 1024**3,
            boot_free_bytes=500 * 1024**2,
            severity=Severity.PASS,
            message="Disk space is healthy.",
            remediation=None,
        ),
    )

    report = service.run(_context(tmp_path))
    by_id = {item.check_id: item for item in report.results}

    assert "sys.network" in by_id
    assert by_id["sys.network"].severity is Severity.FAIL
    assert "no active internet connection" in by_id["sys.network"].message
    assert "sys.packages" not in by_id
    assert "sys.aur" not in by_id
    assert "sys.flatpak" not in by_id
    assert "sys.firmware" not in by_id
    assert "sys.reboot" in by_id
    assert "sys.disk" in by_id


def test_system_upgrade_offline_aborts_immediately(tmp_path: Path) -> None:
    service = SystemUpgradeService(is_online_fn=lambda: False)
    console = DummyConsole()

    code = service.run(_context(tmp_path), console)
    assert code == 1
    assert any("No active internet connection detected" in msg for msg in console.messages)


def test_detect_aur_helper_prefers_paru_then_yay() -> None:
    assert detect_aur_helper(lambda x: "/usr/bin/paru" if x == "paru" else "/usr/bin/yay") == "paru"
    assert detect_aur_helper(lambda x: "/usr/bin/yay" if x == "yay" else None) == "yay"
    assert detect_aur_helper(lambda x: None) is None


def test_check_orphans_detects_unneeded_packages(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda x: "/usr/bin/pacman"
    )

    # With orphans
    def fake_run_with_orphans(*args, **kwargs):
        return SimpleNamespace(stdout="pkg-orphan-1\npkg-orphan-2\n", returncode=0)

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run_with_orphans)
    res = service._check_orphans(_context(tmp_path))
    assert res.severity is Severity.WARN
    assert "2 orphan packages found" in res.message
    assert res.remediation is not None
    assert "pacman -Rns" in res.remediation

    # Without orphans (pacman returns 1 when no orphans)
    def fake_run_no_orphans(*args, **kwargs):
        return SimpleNamespace(stdout="", returncode=1)

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run_no_orphans)
    res_clean = service._check_orphans(_context(tmp_path))
    assert res_clean.severity is Severity.PASS
    assert "no orphan packages" in res_clean.message


def test_detect_pacnew_files_fallback_uses_isolated_tree(monkeypatch, tmp_path: Path) -> None:
    etc_dir = tmp_path / "etc"
    nested_dir = etc_dir / "nested"
    nested_dir.mkdir(parents=True)
    pending = [etc_dir / "z.conf.pacnew", nested_dir / "a.conf.pacsave"]
    for path in [*pending, etc_dir / "regular.conf"]:
        path.write_text("test configuration", encoding="utf-8")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", lambda name: None)
    monkeypatch.setattr(
        "dotdoctor.application.system_update.Path",
        lambda value: etc_dir if value == "/etc" else Path(value),
    )

    assert detect_pacnew_files() == sorted(str(path) for path in pending)


def test_check_pacnew_detects_pending_merges(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda x: "/usr/bin/pacdiff"
    )

    # With pacnew files
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_pacnew_files",
        lambda: ["/etc/pacman.conf.pacnew", "/etc/sudoers.pacnew"],
    )
    res = service._check_pacnew(_context(tmp_path))
    assert res.severity is Severity.WARN
    assert "2 .pacnew files found" in res.message
    assert "pacdiff" in (res.remediation or "")

    # Clean
    monkeypatch.setattr("dotdoctor.application.system_update.detect_pacnew_files", lambda: [])
    res_clean = service._check_pacnew(_context(tmp_path))
    assert res_clean.severity is Severity.PASS
    assert "no .pacnew files" in res_clean.message


def test_check_failed_services_detects_failures(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda x: "/usr/bin/systemctl"
    )

    # With failed service
    def fake_run_failed(*args, **kwargs):
        cmd = args[0]
        if "--user" in cmd:
            return SimpleNamespace(stdout="", returncode=0)
        return SimpleNamespace(
            stdout="failing.service loaded failed failed My Service\n", returncode=0
        )

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run_failed)
    res = service._check_failed_services(_context(tmp_path))
    assert res.severity is Severity.FAIL
    assert "1 failed unit (failing.service)" in res.message
    assert "systemctl status failing.service" in (res.remediation or "")

    # Clean
    def fake_run_clean(*args, **kwargs):
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run_clean)
    res_clean = service._check_failed_services(_context(tmp_path))
    assert res_clean.severity is Severity.PASS
    assert "no failed units" in res_clean.message


def test_check_flatpak_unused_detects_unused(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda x: "/usr/bin/flatpak"
    )

    def fake_run_unused(*args, **kwargs):
        out = (
            "\n        ID                                           Branch\n"
            " 1.     org.freedesktop.Platform.GL.default          25.08\n"
            " 2.     org.freedesktop.Platform.GL.default          25.08-extra\n"
            "\nProceed with these changes? [Y/n]:"
        )
        return SimpleNamespace(stdout=out, returncode=1)

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run_unused)
    res = service._check_flatpak_unused(_context(tmp_path))
    assert res.severity is Severity.WARN
    assert "2 unused runtimes found" in res.message
    assert "flatpak uninstall --unused" in (res.remediation or "")

    def fake_run_clean(*args, **kwargs):
        return SimpleNamespace(stdout="Nothing unused to uninstall\n", returncode=0)

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run_clean)
    res_clean = service._check_flatpak_unused(_context(tmp_path))
    assert res_clean.severity is Severity.PASS
    assert "no unused runtimes" in res_clean.message


def test_check_journal_disk_usage(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda x: "/usr/bin/journalctl"
    )

    # Normal usage
    monkeypatch.setattr(
        "dotdoctor.application.system_update.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="Archived and active journals take up 500M in the file system.\n",
            returncode=0,
        ),
    )
    res = service._check_journal(_context(tmp_path))
    assert res.severity is Severity.PASS
    assert "500M in journal logs" in res.message

    # High usage > 4G
    monkeypatch.setattr(
        "dotdoctor.application.system_update.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="Archived and active journals take up 6.2G in the file system.\n",
            returncode=0,
        ),
    )
    res_high = service._check_journal(_context(tmp_path))
    assert res_high.severity is Severity.WARN
    assert "6.2G in journal logs" in res_high.message
    assert "journalctl --vacuum-size" in (res_high.remediation or "")


def test_system_upgrade_with_paru_and_maintenance_cleanup(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService(aur_helper_fn=lambda: "paru")
    console = DummyConsole()
    commands: list[list[str]] = []

    def fake_which(name: str) -> str | None:
        if name in {"paru", "flatpak", "paccache", "cachyos-rate-mirrors"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        commands.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)
    monkeypatch.setattr(
        "dotdoctor.application.system_update.detect_pacnew_files",
        lambda: ["/etc/pacman.conf.pacnew"],
    )

    code = service.run(_context(tmp_path), console)

    assert code == 0
    assert ["paru", "-Syu", "--noconfirm"] in commands
    assert ["flatpak", "update", "-y"] in commands
    assert ["flatpak", "uninstall", "--unused", "-y"] in commands
    assert ["sudo", "paccache", "-rk2"] in commands
    assert ["sudo", "paccache", "-ruk0"] in commands
    assert any(".pacnew configuration files found" in msg for msg in console.messages)


def test_run_step_success_formatting(monkeypatch) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()

    monkeypatch.setattr(
        "dotdoctor.application.system_update.subprocess.run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stderr="", stdout=""),
    )

    had_error, is_net_fail, had_updates = service._run_step(["test"], console, "Test Step")
    assert had_error is False
    assert is_net_fail is False
    assert had_updates is False
    assert any("DONE" in msg and "Test Step" in msg for msg in console.messages)


def test_run_step_failure_reveals_error_lines(monkeypatch) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()

    monkeypatch.setattr(
        "dotdoctor.application.system_update.subprocess.run",
        lambda *a, **kw: SimpleNamespace(
            returncode=1,
            stderr="error: file conflict\n/usr/bin/foo exists",
            stdout="",
        ),
    )

    had_error, is_net_fail, had_updates = service._run_step(["test"], console, "Test Step")
    assert had_error is True
    assert is_net_fail is False
    assert had_updates is False
    assert any("FAIL" in msg and "Test Step" in msg for msg in console.messages)
    assert any("error: file conflict" in msg for msg in console.messages)
    assert any("│" in msg for msg in console.messages)


def test_run_step_timeout_and_oserror(monkeypatch) -> None:
    service = SystemUpgradeService()
    console = DummyConsole()

    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd=["test"], timeout=1)

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", raise_timeout)
    had_error, is_net_fail, had_updates = service._run_step(["test"], console, "Timeout Step")
    assert had_error is True
    assert is_net_fail is True
    assert had_updates is False
    assert any("timed out" in msg for msg in console.messages)

    def raise_oserror(*a, **kw):
        raise OSError("binary not found")

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", raise_oserror)
    had_error, is_net_fail, had_updates = service._run_step(["test"], console, "Error Step")
    assert had_error is True
    assert is_net_fail is False
    assert had_updates is False
    assert any("failed to start" in msg for msg in console.messages)


def test_system_upgrade_console_layout_and_no_ansi_no_color(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = SystemUpgradeService()
    output = io.StringIO()
    console = Console(file=output, width=80, no_color=True)

    def fake_which(name: str) -> str | None:
        if name in {"yay", "flatpak", "fwupdmgr", "paccache"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)
    assert code == 0

    rendered = output.getvalue()
    # No ANSI escape sequences
    assert "\x1b[" not in rendered
    # No exclamation marks or trailing ellipsis in service strings
    assert "!" not in rendered
    # Status column is left aligned with 4 chars
    assert "  DONE  System and AUR update (yay)" in rendered
    assert "  DONE  Flatpak update" in rendered
    assert "  DONE  Flatpak cleanup (unused runtimes)" in rendered
    assert "  DONE  Pacman cache cleanup (keep 2 versions)" in rendered
    assert "  DONE  Pacman cache cleanup (uninstalled packages)" in rendered
    assert "  SKIP  Oh-My-Zsh update (not installed)" in rendered
    assert "  DONE  Firmware update" in rendered
    # Final summary in scan format
    assert "6 done · 3 skipped" in rendered
    assert "Nothing to update. All packages and components are up to date." in rendered


def test_system_upgrade_summary_counters_on_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = SystemUpgradeService()
    output = io.StringIO()
    console = Console(file=output, width=80, no_color=True)

    def fake_which(name: str) -> str | None:
        if name in {"yay"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command == ["sudo", "true"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if command[:1] == ["yay"]:
            return SimpleNamespace(returncode=1, stderr="fatal package conflict", stdout="")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)
    assert code == 2

    rendered = output.getvalue()
    assert "\x1b[" not in rendered
    assert "  FAIL  System and AUR update (yay) (exit=1)" in rendered
    assert "fatal package conflict" in rendered
    assert "1 failed" in rendered


def test_system_upgrade_with_actual_updates_applied(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = SystemUpgradeService()
    output = io.StringIO()
    console = Console(file=output, width=80, no_color=True)

    def fake_which(name: str) -> str | None:
        if name in {"yay"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        command = args[0]
        if command == ["sudo", "true"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if command[:1] == ["yay"]:
            stdout = (
                "Packages (2) linux-6.10.arch1-1 systemd-256-1\n" "Total Installed Size: 150 MiB\n"
            )
            return SimpleNamespace(returncode=0, stderr="", stdout=stdout)
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)
    assert code == 0

    rendered = output.getvalue()
    assert "1 done · 5 skipped" in rendered
    assert "All updates completed successfully." in rendered
    assert "Nothing to update" not in rendered


def test_detect_step_updates_variants() -> None:
    from dotdoctor.application.system_update import _detect_step_updates

    # Package manager
    assert not _detect_step_updates(["yay", "-Syu"], " there is nothing to do\n", "")
    assert not _detect_step_updates(
        ["sudo", "pacman", "-Syu"], ":: Synchronizing...\nthere is nothing to do", ""
    )
    assert _detect_step_updates(
        ["yay", "-Syu"], "Packages (2) pkg-a pkg-b\nTotal Installed Size: 10 MiB\n", ""
    )

    # Flatpak
    assert not _detect_step_updates(
        ["flatpak", "update", "-y"], "Looking for updates...\nNothing to update.\n", ""
    )
    assert not _detect_step_updates(["flatpak", "update", "-y"], "Nothing to do.\n", "")
    assert _detect_step_updates(
        ["flatpak", "update", "-y"], "Updating runtime org.gnome.Platform\n", ""
    )

    # Flatpak unused
    assert not _detect_step_updates(
        ["flatpak", "uninstall", "--unused", "-y"], "Nothing unused to uninstall\n", ""
    )
    assert _detect_step_updates(
        ["flatpak", "uninstall", "--unused", "-y"], "Uninstalling org.freedesktop.Platform\n", ""
    )

    # Paccache
    assert not _detect_step_updates(
        ["sudo", "paccache", "-rk2"], "==> finished: 0 packages removed\n", ""
    )
    assert not _detect_step_updates(
        ["sudo", "paccache", "-rk2"], "==> no candidate packages found for pruning\n", ""
    )
    assert _detect_step_updates(
        ["sudo", "paccache", "-rk2"], "==> finished: 12 packages removed\n", ""
    )

    # Oh-My-Zsh
    assert not _detect_step_updates(
        ["sh", "upgrade.sh"], "Oh My Zsh is already at the latest version.\n", ""
    )
    assert _detect_step_updates(["sh", "upgrade.sh"], "Updating Oh My Zsh\n", "")

    # fwupdmgr
    assert not _detect_step_updates(["fwupdmgr", "update", "-y"], "No updates available\n", "")
    assert not _detect_step_updates(
        ["fwupdmgr", "update", "-y"],
        "Devices with no available firmware updates:\n • Device A\n",
        "",
    )
    assert _detect_step_updates(
        ["fwupdmgr", "update", "-y"], "Updating Device A...\nSuccessfully installed\n", ""
    )


def test_parse_package_update_line() -> None:
    from dotdoctor.application.system_update import parse_package_update_line

    assert parse_package_update_line("linux 6.10.1-arch1-1 -> 6.10.2-arch1-1") == (
        "linux",
        "6.10.1-arch1-1",
        "6.10.2-arch1-1",
    )
    assert parse_package_update_line("nvidia 555.58.02-1 → 560.35.03-1") == (
        "nvidia",
        "555.58.02-1",
        "560.35.03-1",
    )
    assert parse_package_update_line("mesa 24.1.2-1 24.1.3-1") == (
        "mesa",
        "24.1.2-1",
        "24.1.3-1",
    )
    assert parse_package_update_line("invalid") is None
    assert parse_package_update_line("") is None


def test_detect_snapshot_tool_selection(monkeypatch) -> None:
    from dotdoctor.application.system_update import detect_snapshot_tool

    # 1. snapper available with valid configs
    def fake_which_snapper(name: str) -> str | None:
        if name in {"snapper", "timeshift"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run_snapper_ok(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="Config | Subvolume\nroot   | /@\n", stderr="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which_snapper)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run_snapper_ok)
    assert detect_snapshot_tool() == "snapper"

    # 2. snapper has no configs -> fallback to timeshift
    def fake_run_snapper_no_configs(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="Config | Subvolume\n", stderr="")

    monkeypatch.setattr(
        "dotdoctor.application.system_update.subprocess.run",
        fake_run_snapper_no_configs,
    )
    assert detect_snapshot_tool() == "timeshift"

    # 3. Only timeshift available
    def fake_which_timeshift_only(name: str) -> str | None:
        if name == "timeshift":
            return "/usr/bin/timeshift"
        return None

    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which",
        fake_which_timeshift_only,
    )
    assert detect_snapshot_tool() == "timeshift"

    # 4. Neither available
    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", lambda _: None)
    assert detect_snapshot_tool() is None


def test_system_upgrade_with_snapper_rollback_advice(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService(snapshot_tool_fn=lambda: "snapper")
    output = io.StringIO()
    console = Console(file=output, width=80, no_color=True)

    def fake_which(name: str) -> str | None:
        if name in {"yay", "snapper"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        cmd = args[0]
        if cmd == ["sudo", "true"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if cmd[:3] == ["sudo", "snapper", "create"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if cmd[:1] == ["yay"]:
            return SimpleNamespace(returncode=1, stderr="fatal error", stdout="")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)
    assert code == 2

    rendered = output.getvalue()
    assert "DONE  Pre-update snapshot (snapper)" in rendered
    assert "FAIL  System and AUR update (yay)" in rendered
    assert "Rollback available: sudo snapper rollback or select snapshot in bootloader" in rendered


def test_system_upgrade_with_timeshift_rollback_advice(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService(snapshot_tool_fn=lambda: "timeshift")
    output = io.StringIO()
    console = Console(file=output, width=80, no_color=True)

    def fake_which(name: str) -> str | None:
        if name in {"yay", "timeshift"}:
            return f"/usr/bin/{name}"
        return None

    def fake_run(*args, **kwargs):
        cmd = args[0]
        if cmd == ["sudo", "true"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if cmd[:3] == ["sudo", "timeshift", "--create"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if cmd[:1] == ["yay"]:
            return SimpleNamespace(returncode=1, stderr="fatal error", stdout="")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)
    assert code == 2

    rendered = output.getvalue()
    assert "DONE  Pre-update snapshot (timeshift)" in rendered
    assert "FAIL  System and AUR update (yay)" in rendered
    assert "Rollback available: sudo timeshift --restore" in rendered


def test_system_upgrade_snapshot_creation_fails(monkeypatch, tmp_path: Path) -> None:
    service = SystemUpgradeService(snapshot_tool_fn=lambda: "snapper")
    output = io.StringIO()
    console = Console(file=output, width=80, no_color=True)

    def fake_which(name: str) -> str | None:
        return f"/usr/bin/{name}"

    def fake_run(*args, **kwargs):
        cmd = args[0]
        if cmd == ["sudo", "true"]:
            return SimpleNamespace(returncode=0, stderr="", stdout="")
        if cmd[:3] == ["sudo", "snapper", "create"]:
            return SimpleNamespace(returncode=1, stderr="no space left", stdout="")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    code = service.run(_context(tmp_path), console)
    assert code == 2

    rendered = output.getvalue()
    assert "FAIL  Pre-update snapshot (snapper)" in rendered
    assert "1 failed" in rendered


def test_check_arch_packages_critical_detection(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "checkupdates":
            return "/usr/bin/checkupdates"
        return None

    def fake_run(*args, **kwargs):
        stdout = (
            "linux 6.10.1-arch1-1 -> 6.10.2-arch1-1\n"
            "systemd 256.1-1 -> 256.2-1\n"
            "htop 3.3.0-1 -> 3.3.0-2\n"
        )
        return SimpleNamespace(returncode=0, stderr="", stdout=stdout)

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    result = service._check_arch_packages(_context(tmp_path))
    assert result.severity is Severity.OUTD
    assert "3 updates available (reboot required: linux, systemd)" in result.message
    assert result.details["critical"] == ["linux", "systemd"]
    assert result.details["packages"] == [
        "linux 6.10.1-arch1-1 -> 6.10.2-arch1-1",
        "systemd 256.1-1 -> 256.2-1",
        "htop 3.3.0-1 -> 3.3.0-2",
    ]


def test_check_aur_packages_critical_detection(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "yay":
            return "/usr/bin/yay"
        return None

    def fake_run(*args, **kwargs):
        stdout = "aur/nvidia-dkms 555.58-1 -> 560.35-1\n" "aur/spotify 1:1.2.42-1 -> 1:1.2.45-1\n"
        return SimpleNamespace(returncode=0, stderr="", stdout=stdout)

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)
    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    result = service._check_aur_packages(_context(tmp_path), aur_helper="yay")
    assert result.severity is Severity.OUTD
    assert "2 AUR updates available (reboot required: nvidia-dkms)" in result.message
    assert result.details["critical"] == ["nvidia-dkms"]
    assert result.details["packages"] == [
        "nvidia-dkms 555.58-1 -> 560.35-1",
        "spotify 1:1.2.42-1 -> 1:1.2.45-1",
    ]


def test_check_arch_packages_warns_when_checkupdates_missing_but_pacman_present(
    monkeypatch, tmp_path: Path
) -> None:
    service = SystemDryRunService()

    def fake_which(name: str) -> str | None:
        if name == "pacman":
            return "/usr/bin/pacman"
        return None

    monkeypatch.setattr("dotdoctor.application.system_update.shutil.which", fake_which)

    result = service._check_arch_packages(_context(tmp_path))
    assert result.severity is Severity.WARN
    assert "checkupdates not installed" in result.message
    assert result.remediation == "sudo pacman -S pacman-contrib"


def test_system_dry_run_disabled_checks(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda n: f"/usr/bin/{n}"
    )

    tasks = service.build_tasks(_context(tmp_path), disabled_checks={"sys.packages", "sys.cache"})
    task_ids = {t.check_id for t in tasks}
    assert "sys.packages" not in task_ids
    assert "sys.cache" not in task_ids
    assert "sys.firmware" in task_ids


def test_system_dry_run_disabled_checks_via_env(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda n: f"/usr/bin/{n}"
    )
    monkeypatch.setenv("DOTDOCTOR_DISABLE_CHECKS", "sys.packages, sys.cache")

    tasks = service.build_tasks(_context(tmp_path))
    task_ids = {t.check_id for t in tasks}
    assert "sys.packages" not in task_ids
    assert "sys.cache" not in task_ids


def test_system_dry_run_firmware_omitted_when_not_installed(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which",
        lambda n: None if n == "fwupdmgr" else f"/usr/bin/{n}",
    )
    tasks = service.build_tasks(_context(tmp_path))
    task_ids = {t.check_id for t in tasks}
    assert "sys.firmware" not in task_ids


def test_system_dry_run_remediations_have_no_run_prefix(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda n: f"/usr/bin/{n}"
    )

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="test\n", stderr="")

    monkeypatch.setattr("dotdoctor.application.system_update.subprocess.run", fake_run)

    report = service.run(_context(tmp_path))
    for res in report.results:
        if res.remediation:
            assert not res.remediation.startswith("run "), f"Remediation '{res.remediation}'"
            assert not res.remediation.startswith("Run "), f"Remediation '{res.remediation}'"


def test_run_streaming_step() -> None:
    service = SystemUpgradeService()
    console = Console(file=io.StringIO(), force_terminal=True, width=80)
    result = service._run_streaming_step(
        ["python3", "-c", "import sys; sys.stdout.write('hello\\n'); sys.stderr.write('err\\n')"],
        console=console,
        title="Streaming test",
        console_width=80,
    )
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert "err" in result.stderr


def test_system_dry_run_include_checks_update_and_fix(monkeypatch, tmp_path: Path) -> None:
    service = SystemDryRunService()
    monkeypatch.setattr(
        "dotdoctor.application.system_update.shutil.which", lambda n: f"/usr/bin/{n}"
    )

    update_tasks = service.build_tasks(_context(tmp_path), include_checks=UPDATE_CHECK_IDS)
    update_ids = {t.check_id for t in update_tasks}
    assert update_ids.issubset(UPDATE_CHECK_IDS)
    assert "sys.packages" in update_ids
    assert "sys.orphans" not in update_ids
    assert "sys.cache" not in update_ids

    fix_tasks = service.build_tasks(_context(tmp_path), include_checks=FIX_CHECK_IDS)
    fix_ids = {t.check_id for t in fix_tasks}
    assert fix_ids.issubset(FIX_CHECK_IDS)
    assert "sys.packages" not in fix_ids
    assert "sys.aur" not in fix_ids
    assert "sys.orphans" in fix_ids
    assert "sys.cache" in fix_ids
    assert "sys.flatpak-unused" in fix_ids
