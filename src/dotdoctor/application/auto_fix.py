import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

import typer
from rich.console import Console

from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


@dataclass
class FixOutcome:
    changed: bool
    note: str


class InteractiveAutoFixer:
    """Interactive auto-fix orchestrator for system hygiene WARN/FAIL findings."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def apply(self, report: ScanReport, context: ScanContext) -> ScanReport:
        results = list(report.results)
        changed_any = False
        had_issues = False

        for index, result in enumerate(results):
            if result.severity in {Severity.PASS, Severity.OUTD}:
                continue

            had_issues = True

            prompt = self._build_prompt_message(result)
            default_choice = False if result.check_id == "sys.reboot" else True

            try:
                should_fix = typer.confirm(prompt, default=default_choice)
            except (typer.Abort, Exception):
                self._console.print("[dim]Skipped by user.[/dim]")
                continue

            if not should_fix:
                self._console.print("[dim]Skipped by user.[/dim]")
                continue

            fix_handler = self._resolve_fix_handler(result.check_id)
            if fix_handler is None:
                self._console.print(
                    f"[yellow]No automated fixer is registered for {result.check_id} yet.[/yellow]"
                )
                continue

            action_label = self._resolve_action_label(result.check_id)
            try:
                if result.check_id == "sys.pacnew" or not self._console.is_terminal:
                    outcome = fix_handler(context, result)
                else:
                    with self._console.status(f"[dim]{action_label}[/dim]", spinner="dots"):
                        outcome = fix_handler(context, result)
            except (OSError, subprocess.SubprocessError) as exc:
                self._console.print(f"[red]Auto-fix failed:[/red] {exc}")
                continue

            if outcome.changed:
                changed_any = True
                self._console.print(
                    f"[dim green]FIXED[/dim green] {result.check_id}: {outcome.note}"
                )
                results[index] = CheckResult(
                    check_id=result.check_id,
                    severity=Severity.PASS,
                    message=f"Auto-fixed: {outcome.note}",
                    remediation=None,
                    details={**result.details, "auto_fixed": True},
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
            "sys.services": self._fix_sys_services,
            "sys.disk": self._fix_sys_disk,
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
            if r1.returncode == 0 or r2.returncode == 0:
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

        subprocess.run(["systemctl", "reset-failed"], check=False)
        subprocess.run(["systemctl", "--user", "reset-failed"], check=False)
        return FixOutcome(changed=True, note="Reset failed systemd services.")

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
