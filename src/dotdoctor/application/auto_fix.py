import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

import typer
from rich.console import Console

from dotdoctor.application.maintenance import PACKAGE_RE, MaintenanceChecks
from dotdoctor.cli.theme import format_status_line
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


@dataclass
class FixOutcome:
    changed: bool
    note: str


class InteractiveAutoFixer:
    """Interactive auto-fix orchestrator for system hygiene WARN/FAIL findings."""

    def __init__(self, console: Console, config: DotDoctorConfig | None = None) -> None:
        self._console = console
        self.config = config or DotDoctorConfig()

    def apply(self, report: ScanReport, context: ScanContext) -> ScanReport:
        results = list(report.results)
        changed_any = False
        had_issues = False

        for index, result in enumerate(results):
            if result.severity in {Severity.PASS, Severity.OUTD}:
                continue

            had_issues = True

            fix_handler = self._resolve_fix_handler(result.check_id)
            if fix_handler is None or (
                result.check_id.startswith("sys.")
                and result.check_id
                in {"sys.trim", "sys.btrfs", "sys.timers", "sys.integrity", "sys.backup"}
                and not self._has_maintenance_action(result)
            ):
                for line in format_status_line("SKIP", result.check_id, "(manual review required)"):
                    self._console.print(line)
                continue

            for target in self._action_targets(result):
                self._console.print(f"        {target}", markup=False)

            prompt = self._build_prompt_message(result)
            default_choice = result.check_id not in {
                "sys.reboot",
                "sys.trim",
                "sys.btrfs",
                "sys.timers",
                "sys.integrity",
                "sys.backup",
            }

            try:
                should_fix = typer.confirm(prompt, default=default_choice)
            except (typer.Abort, Exception):
                self._console.print("[dim]Skipped by user.[/dim]")
                continue

            if not should_fix:
                self._console.print("[dim]Skipped by user.[/dim]")
                continue

            action_label = self._resolve_action_label(result.check_id)
            try:
                if (
                    result.check_id
                    in {
                        "sys.pacnew",
                        "sys.trim",
                        "sys.btrfs",
                        "sys.timers",
                        "sys.integrity",
                        "sys.backup",
                    }
                    or not self._console.is_terminal
                ):
                    outcome = fix_handler(context, result)
                else:
                    with self._console.status(f"[dim]{action_label}[/dim]", spinner="dots"):
                        outcome = fix_handler(context, result)
            except (OSError, subprocess.SubprocessError) as exc:
                self._console.print(f"[red]Auto-fix failed:[/red] {exc}")
                continue

            if outcome.changed:
                verified = self._verify(result, context)
                results[index] = verified
                if verified.severity != Severity.PASS:
                    for line in format_status_line(
                        "WARN", result.check_id, "(action completed; findings remain)"
                    ):
                        self._console.print(line)
                    continue
                changed_any = True
                for line in format_status_line("DONE", result.check_id, outcome.note):
                    self._console.print(line)
                results[index] = CheckResult(
                    check_id=result.check_id,
                    severity=Severity.PASS,
                    message=f"Auto-fixed: {outcome.note} {verified.message}",
                    remediation=None,
                    details={**verified.details, "auto_fixed": True},
                )
            else:
                self._console.print(
                    f"[yellow]No changes applied[/yellow] for {result.check_id}: {outcome.note}"
                )

        if not had_issues:
            if any(r.severity is Severity.OUTD for r in results):
                self._console.print(
                    "[dim]No issues found. To update packages, run dotdoctor --sysup.[/dim]"
                )
            else:
                self._console.print("[dim]Nothing to fix. All checks are PASS.[/dim]")
        elif changed_any:
            self._console.print("[dim]Auto-fix phase completed.[/dim]")
        return ScanReport(profile=report.profile, results=results)

    def _verify(self, result: CheckResult, context: ScanContext) -> CheckResult:
        ids = frozenset({result.check_id})
        if result.check_id in {
            "sys.trim",
            "sys.btrfs",
            "sys.timers",
            "sys.integrity",
            "sys.backup",
        }:
            checks = MaintenanceChecks(self.config).run(context, ids)
        else:
            from dotdoctor.application.system_update import SystemDryRunService

            checks = (
                SystemDryRunService(config=self.config).run(context, include_checks=ids).results
            )
        if checks:
            return checks[0]
        return CheckResult(
            check_id=result.check_id,
            severity=Severity.WARN,
            message="Action completed; unable to verify the result.",
            details={"verified": False},
        )

    def _resolve_fix_handler(
        self,
        check_id: str,
    ) -> Callable[[ScanContext, CheckResult], FixOutcome] | None:
        handlers: dict[str, Callable[[ScanContext, CheckResult], FixOutcome]] = {
            "sys.orphans": self._fix_sys_orphans,
            "sys.cache": self._fix_sys_cache,
            "sys.flatpak-unused": self._fix_sys_flatpak_unused,
            "sys.pacnew": self._fix_sys_pacnew,
            "sys.journal": self._fix_sys_journal,
            "sys.reboot": self._fix_sys_reboot,
            "sys.disk": self._fix_sys_disk,
            "sys.trim": self._fix_maintenance,
            "sys.btrfs": self._fix_maintenance,
            "sys.timers": self._fix_maintenance,
            "sys.backup": self._fix_maintenance,
            "sys.integrity": self._fix_maintenance,
        }
        return handlers.get(check_id)

    def _resolve_action_label(self, check_id: str) -> str:
        labels: dict[str, str] = {
            "sys.orphans": "Removing orphan packages",
            "sys.cache": "Cleaning pacman package cache",
            "sys.flatpak-unused": "Removing unused Flatpak runtimes",
            "sys.pacnew": "Reviewing .pacnew files with pacdiff",
            "sys.journal": "Vacuuming systemd journal logs to 1G",
            "sys.reboot": "Initiating system reboot",
            "sys.services": "Resetting failed systemd services",
            "sys.disk": "Cleaning package cache and journal logs",
        }
        return labels.get(check_id, f"Remediating {check_id}")

    def _build_prompt_message(self, result: CheckResult) -> str:
        prompts = {
            "sys.trim": "Enable weekly TRIM and run the existing fstrim service now?",
            "sys.btrfs": "Start overdue Btrfs scrubs now? This may take a long time.",
            "sys.timers": "Enable the listed expected maintenance timers?",
            "sys.backup": "Run the configured backup service now?",
            "sys.integrity": "Reinstall the listed official packages with a full system upgrade?",
        }
        if result.check_id in prompts:
            return prompts[result.check_id]
        if result.check_id == "sys.orphans":
            orphans = result.details.get("orphans", [])
            count = len(orphans)
            noun = "package" if count == 1 else "packages"
            return f"Orphan {noun} detected ({count}). Remove them now?"

        if result.check_id == "sys.cache":
            return "Pacman cache can be reclaimed. Clean cache now?"

        if result.check_id == "sys.flatpak-unused":
            count = result.details.get("unused_count", 0)
            noun = "runtime" if count == 1 else "runtimes"
            return f"Unused Flatpak {noun} detected ({count}). Remove unused runtimes now?"

        if result.check_id == "sys.pacnew":
            files = result.details.get("files", [])
            count = len(files)
            noun = "file" if count == 1 else "files"
            return f"{count} .pacnew {noun} detected. Review and merge with pacdiff now?"

        if result.check_id == "sys.journal":
            return "Systemd journal size is large. Vacuum journal logs to 1G now?"

        if result.check_id == "sys.reboot":
            return "System reboot is required. Reboot the system now?"

        if result.check_id == "sys.services":
            failed = result.details.get("failed_units", [])
            count = len(failed)
            noun = "unit" if count == 1 else "units"
            return f"{count} failed systemd {noun} detected. Reset failed services now?"

        if result.check_id == "sys.disk":
            return "Disk space is low. Clean package cache and journal logs now?"

        return f"Issue found in {result.check_id}. Try automated remediation if available?"

    def _fix_sys_orphans(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        if shutil.which("pacman") is None:
            return FixOutcome(changed=False, note="pacman is not installed.")

        orphans = list(result.details.get("orphans", []))
        if not orphans:
            res = subprocess.run(
                ["pacman", "-Qtdq"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                orphans = [line.strip() for line in res.stdout.splitlines() if line.strip()]

        if not orphans:
            return FixOutcome(changed=False, note="No orphan packages to remove.")

        cmd = ["sudo", "pacman", "-Rns", "--noconfirm", *orphans]
        remove_res = subprocess.run(cmd, check=False)
        if remove_res.returncode == 0:
            count = len(orphans)
            noun = "package" if count == 1 else "packages"
            return FixOutcome(changed=True, note=f"Removed {count} orphan {noun}.")
        return FixOutcome(
            changed=False,
            note=f"Failed to remove orphan packages (exit={remove_res.returncode}).",
        )

    def _fix_sys_cache(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        if shutil.which("paccache") is not None:
            r1 = subprocess.run(["sudo", "paccache", "-rk2"], check=False)
            r2 = subprocess.run(["sudo", "paccache", "-ruk0"], check=False)
            if r1.returncode == 0 and r2.returncode == 0:
                return FixOutcome(changed=True, note="Cleaned pacman package cache.")
            return FixOutcome(changed=False, note="paccache commands failed.")

        if shutil.which("pacman") is not None:
            r = subprocess.run(["sudo", "pacman", "-Sc", "--noconfirm"], check=False)
            if r.returncode == 0:
                return FixOutcome(changed=True, note="Cleaned pacman package cache.")
            return FixOutcome(changed=False, note="pacman -Sc failed.")

        return FixOutcome(changed=False, note="No pacman cache tools installed.")

    def _fix_sys_flatpak_unused(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        if shutil.which("flatpak") is None:
            return FixOutcome(changed=False, note="flatpak is not installed.")

        res = subprocess.run(["flatpak", "uninstall", "--unused", "-y"], check=False)
        if res.returncode == 0:
            return FixOutcome(changed=True, note="Removed unused Flatpak runtimes.")
        return FixOutcome(changed=False, note=f"Flatpak cleanup failed (exit={res.returncode}).")

    def _fix_sys_pacnew(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        if shutil.which("pacdiff") is None:
            return FixOutcome(
                changed=False,
                note="pacdiff is not installed (install pacman-contrib).",
            )

        res = subprocess.run(["sudo", "pacdiff"], check=False)
        if res.returncode == 0:
            return FixOutcome(changed=True, note="Reviewed .pacnew files with pacdiff.")
        return FixOutcome(changed=False, note=f"pacdiff exited with code {res.returncode}.")

    def _fix_sys_journal(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        if shutil.which("journalctl") is None:
            return FixOutcome(changed=False, note="journalctl is not installed.")

        res = subprocess.run(["sudo", "journalctl", "--vacuum-size=1G"], check=False)
        if res.returncode == 0:
            return FixOutcome(changed=True, note="Vacuumed systemd journal logs to 1G.")
        return FixOutcome(
            changed=False,
            note=f"journalctl vacuum failed (exit={res.returncode}).",
        )

    def _fix_sys_reboot(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        cmd = ["sudo", "systemctl", "reboot"] if shutil.which("systemctl") else ["sudo", "reboot"]
        res = subprocess.run(cmd, check=False)
        if res.returncode == 0:
            return FixOutcome(changed=True, note="System reboot initiated.")
        return FixOutcome(changed=False, note=f"Reboot command failed (exit={res.returncode}).")

    def _fix_sys_services(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        if shutil.which("systemctl") is None:
            return FixOutcome(changed=False, note="systemctl is not installed.")

        return FixOutcome(
            changed=False,
            note="Inspect failed service logs and resolve the cause before restarting.",
        )

    def _has_maintenance_action(self, result: CheckResult) -> bool:
        keys = {
            "sys.trim": "actionable",
            "sys.btrfs": "scrub_targets",
            "sys.timers": "timers",
            "sys.integrity": "reinstall_packages",
        }
        if result.check_id == "sys.backup":
            return self.config.maintenance.backup is not None
        return bool(result.details.get(keys.get(result.check_id, "")))

    def can_fix(self, result: CheckResult) -> bool:
        if result.severity not in {Severity.WARN, Severity.FAIL}:
            return False
        if self._resolve_fix_handler(result.check_id) is None:
            return False
        if result.check_id in {
            "sys.trim",
            "sys.btrfs",
            "sys.timers",
            "sys.integrity",
            "sys.backup",
        }:
            return self._has_maintenance_action(result)
        return True

    @staticmethod
    def _action_targets(result: CheckResult) -> list[str]:
        if result.check_id == "sys.integrity":
            return list(result.details.get("reinstall_packages", []))
        if result.check_id == "sys.btrfs":
            return list(result.details.get("scrub_targets", []))
        if result.check_id == "sys.timers":
            return [
                f'{timer["unit"]} ({timer["scope"]})' for timer in result.details.get("timers", [])
            ]
        return []

    def _fix_maintenance(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        commands: list[list[str]] = []
        if result.check_id == "sys.trim":
            commands = [
                ["sudo", "systemctl", "enable", "--now", "fstrim.timer"],
                ["sudo", "systemctl", "start", "fstrim.service"],
            ]
        elif result.check_id == "sys.btrfs":
            commands = [
                ["sudo", "btrfs", "scrub", "start", "-B", target]
                for target in result.details.get("scrub_targets", [])
                if isinstance(target, str) and target.startswith("/")
            ]
        elif result.check_id == "sys.timers":
            expected = {(timer.unit, timer.scope) for timer in self.config.maintenance.timers}
            expected.add(("systemd-tmpfiles-clean.timer", "system"))
            if shutil.which("pacman"):
                expected.add(("archlinux-keyring-wkd-sync.timer", "system"))
            for timer in result.details.get("timers", []):
                if (timer["unit"], timer["scope"]) in expected:
                    prefix = (
                        ["systemctl", "--user"]
                        if timer["scope"] == "user"
                        else ["sudo", "systemctl"]
                    )
                    commands.append([*prefix, "enable", "--now", timer["unit"]])
        elif result.check_id == "sys.backup":
            backup = self.config.maintenance.backup
            if backup:
                commands = [MaintenanceChecks.service_command(backup.service, backup.scope)]
        elif result.check_id == "sys.integrity":
            packages = result.details.get("reinstall_packages", [])
            if packages and all(isinstance(p, str) and PACKAGE_RE.fullmatch(p) for p in packages):
                # Reinstall only after the same safety checks as --sysup.
                from dotdoctor.application.system_update import SystemUpgradeService

                upgrade = SystemUpgradeService(config=self.config)
                upgrade.reinstall_packages = packages
                code = upgrade.run(context, self._console)
                if code:
                    return FixOutcome(
                        False, "System upgrade did not complete; package repair cancelled."
                    )
                return FixOutcome(
                    True, "Selected packages reinstalled during a full system upgrade."
                )
        if not commands:
            return FixOutcome(False, "No safe automated action is available.")
        for command in commands:
            completed = subprocess.run(command, check=False)
            if completed.returncode:
                return FixOutcome(False, f"Action failed (exit={completed.returncode}).")
        return FixOutcome(True, "Maintenance action completed.")

    def _fix_sys_disk(self, context: ScanContext, result: CheckResult) -> FixOutcome:
        notes: list[str] = []
        if shutil.which("paccache") is not None:
            r1 = subprocess.run(["sudo", "paccache", "-rk2"], check=False)
            if r1.returncode == 0:
                notes.append("cleaned pacman cache")
        if shutil.which("journalctl") is not None:
            r2 = subprocess.run(["sudo", "journalctl", "--vacuum-size=1G"], check=False)
            if r2.returncode == 0:
                notes.append("vacuumed journal logs")
        if notes:
            return FixOutcome(changed=True, note=" and ".join(notes) + ".")
        return FixOutcome(changed=False, note="No disk cleanup actions available.")
