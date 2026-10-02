import subprocess
from pathlib import Path
from types import SimpleNamespace

from dotdoctor.application.system_update import (
    DiskSpaceStatus,
    RebootStatus,
    SystemDryRunService,
    SystemUpgradeService,
    detect_disk_space_status,
    detect_reboot_status,
    is_online,
)
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import Severity


class DummyConsole:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, message: str) -> None:
        self.messages.append(message)


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
        if command[:2] == ["yay", "-Qua"]:
            return SimpleNamespace(stdout="aur/pkg-a 1.0-1 2.0-1\n", returncode=0)
        raise AssertionError(f"Unexpected command: {command}")

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

    (tmp_path / ".oh-my-zsh").mkdir()
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


def test_check_arch_timeout_produces_fail(monkeypatch, tmp_path: Path) -> None:
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
    assert by_id["sys.packages"].severity is Severity.FAIL


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
