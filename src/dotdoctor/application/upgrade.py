"""System upgrade runner and snapshot management."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from types import SimpleNamespace
from typing import Any

import typer
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

import dotdoctor.application.system_update as su
from dotdoctor.application.checks import detect_aur_helper, detect_pacnew_files, is_online
from dotdoctor.application.disk import detect_disk_space_status
from dotdoctor.application.maintenance import (
    PACKAGE_RE,
    POSTFLIGHT_IDS,
    PREFLIGHT_IDS,
    MaintenanceChecks,
)
from dotdoctor.application.parsers import (
    _detect_step_updates,
    _is_mirror_failure,
)
from dotdoctor.application.reboot import detect_reboot_status
from dotdoctor.cli.theme import (
    GAP,
    INDENT,
    STATUS_DONE,
    STATUS_FAIL,
    STATUS_SKIP,
    STATUS_WIDTH,
    format_status_line,
    format_sysup_summary,
)
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity
from dotdoctor.infrastructure.maintenance import MaintenanceState, capture

_ORIGINAL_SUBPROCESS_RUN = subprocess.run


def detect_snapshot_tool() -> str | None:
    """Detect available and configured snapshot tool: 'snapper' or 'timeshift'."""
    which_fn = getattr(su, "shutil", shutil).which
    sub_run = getattr(su, "subprocess", subprocess).run
    if which_fn("snapper") is not None:
        try:
            res = sub_run(
                ["snapper", "list-configs"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and len(res.stdout.strip().splitlines()) > 1:
                return "snapper"
        except (OSError, subprocess.SubprocessError):
            pass

    if which_fn("timeshift") is not None:
        return "timeshift"

    return None


class SystemUpgradeService:
    """Runs sequential interactive system update commands."""

    def __init__(
        self,
        is_online_fn: Callable[[], bool] = is_online,
        aur_helper_fn: Callable[[], str | None] = detect_aur_helper,
        snapshot_tool_fn: Callable[[], str | None] = detect_snapshot_tool,
        config: DotDoctorConfig | None = None,
        reboot_fn: Callable[[], bool] | None = None,
        interactive: bool | None = None,
        confirm_fn: Callable[[str], bool] | None = None,
    ) -> None:
        self._is_online_fn = is_online_fn
        self._aur_helper_fn = aur_helper_fn
        self._snapshot_tool_fn = snapshot_tool_fn
        self.config = config or DotDoctorConfig()
        self._reboot_fn = reboot_fn
        self._interactive = interactive
        self._confirm_fn = confirm_fn
        self.reinstall_packages: list[str] = []
        self._last_step_output = ""
        self._keyring_steps = 0
        self._keyring_updated = False

    @contextmanager
    def _sudo_keepalive(self) -> Iterator[None]:
        """Keep sudo credentials alive during upgrade in a daemon thread."""
        if os.geteuid() == 0:
            yield
            return

        stop_event = threading.Event()

        def _keepalive_loop() -> None:
            sub_run = getattr(su, "_ORIGINAL_SUBPROCESS_RUN", subprocess.run)
            while not stop_event.wait(60.0):
                with suppress(Exception):
                    sub_run(["sudo", "-v", "-n"], check=False, timeout=10)

        t = threading.Thread(target=_keepalive_loop, daemon=True, name="dotdoctor-sudo-keepalive")
        t.start()
        try:
            yield
        finally:
            stop_event.set()

    def run(self, context: ScanContext, console: Console) -> int:
        with self._sudo_keepalive():
            return self._run_impl(context, console)

    def _run_impl(self, context: ScanContext, console: Console) -> int:
        # Authentication is the first operation after upgrade confirmation.
        # All guards still run before snapshots or package/system mutations.
        if os.geteuid() != 0:
            console.print("  [dim]Caching sudo credentials[/dim]")
            try:
                sub_run = getattr(su, "subprocess", subprocess).run
                sudo_cache = sub_run(["sudo", "-v"], check=False, timeout=120)
            except subprocess.TimeoutExpired:
                console.print("[red]Sudo authentication timed out. Aborting update phase.[/red]")
                return 3
            except (OSError, subprocess.SubprocessError) as exc:
                console.print(f"[red]Could not authenticate sudo: {escape(str(exc))}[/red]")
                return 3
            if sudo_cache.returncode != 0:
                console.print("[red]Failed to cache sudo credentials. Aborting update phase.[/red]")
                return 3

        with self._preflight_progress(console, "Checking internet connection"):
            online = (
                getattr(su, "is_online", self._is_online_fn)()
                if self._is_online_fn is is_online
                else self._is_online_fn()
            )
        if not online:
            console.print(
                "[red]FAIL: HTTPS connectivity checks failed. "
                "Check connection, DNS and proxy settings. "
                "Aborting system upgrade.[/red]"
            )
            return 1

        try:
            with self._preflight_progress(console, "Checking disk space"):
                disk_fn = getattr(su, "detect_disk_space_status", detect_disk_space_status)
            disk_status = disk_fn()
        except OSError as exc:
            for line in format_status_line(STATUS_FAIL, f"Update aborted: {exc}"):
                console.print(line)
            return 2
        if disk_status.severity == Severity.FAIL:
            console.print(
                f"[red]FAIL: {disk_status.message} "
                "Aborting update to prevent system corruption.[/red]"
            )
            return 1
        if disk_status.severity == Severity.WARN:
            console.print(
                f"[yellow]Warning: {disk_status.message} Proceeding with caution[/yellow]"
            )

        if not self._maintenance_preflight(context, console):
            return 2

        had_error = False
        any_updates = False
        done_count = 0
        fail_count = 0
        skip_count = 0
        console_width = getattr(console, "width", 80) or 80

        snap_err, snap_status, created_snap = self._create_pre_update_snapshot(console)
        had_error |= snap_err
        if snap_status == "done":
            done_count += 1
        elif snap_status == "fail":
            fail_count += 1
        else:
            skip_count += 1

        if snap_err:
            console.print(
                format_sysup_summary(done=done_count, failed=fail_count, skipped=skip_count)
            )
            for line in format_status_line(
                STATUS_FAIL, "Update aborted: pre-update snapshot failed"
            ):
                console.print(line)
            return 2

        mirror_err, mirror_status = self._refresh_mirrors(console)
        had_error |= mirror_err
        if mirror_status == "done":
            done_count += 1
        elif mirror_status == "fail":
            fail_count += 1
        else:
            skip_count += 1

        # Prepare a newly available keyring before the full upgrade. Never leave a
        # synchronized database behind and proceed with unrelated package installs.
        if not self._prepare_keyring(console):
            return 2
        done_count += self._keyring_steps
        any_updates |= self._keyring_updated

        aur_helper = (
            getattr(su, "detect_aur_helper", self._aur_helper_fn)()
            if self._aur_helper_fn is detect_aur_helper
            else self._aur_helper_fn()
        )
        update_cmd: list[str] | None = None
        update_title = "System update"

        if aur_helper in {"paru", "yay"} and os.geteuid() == 0:
            console.print(
                f"  [yellow]Warning: Running as root; skipping {aur_helper} "
                f"(AUR helpers cannot build packages as root).[/yellow]"
            )
            aur_helper = None

        if aur_helper == "paru":
            update_cmd = ["paru", "-Syu", "--noconfirm", "--sudoloop"]
            update_title = "System and AUR update (paru)"
        elif aur_helper == "yay":
            update_cmd = [
                "yay",
                "-Syu",
                "--noconfirm",
                "--sudoloop",
                "--answerclean",
                "None",
                "--answerdiff",
                "None",
            ]
            update_title = "System and AUR update (yay)"
        elif getattr(su, "shutil", shutil).which("pacman") is not None:
            update_cmd = ["sudo", "pacman", "-Syu", "--noconfirm"]
            update_title = "System update (pacman)"

        if update_cmd is not None:
            if self.reinstall_packages:
                update_cmd += ["--", *self.reinstall_packages]
            aur_error, is_net_failure, aur_updated = self._run_step(
                update_cmd, console, update_title
            )
            if aur_error and re.search(
                r"marginal trust|unknown trust|unknown public key|"
                r"invalid or corrupted package.*signature",
                self._last_step_output,
                re.I,
            ):
                if not self._prepare_keyring(console, force=True):
                    return 2
                done_count += self._keyring_steps
                any_updates |= self._keyring_updated
                aur_error, is_net_failure, aur_updated = self._run_step(
                    update_cmd, console, f"{update_title} (retry after keyring update)"
                )
            if aur_error and is_net_failure:
                console.print(
                    "[yellow]Mirror or network failure detected. "
                    "Attempting mirror recovery[/yellow]"
                )
                mirror_failed, _ = self._refresh_mirrors(console)
                if mirror_failed:
                    console.print(
                        "[red]FAIL: Mirror recovery failed. Package upgrade aborted.[/red]"
                    )
                    return 1
                retry_error, _, retry_updated = self._run_step(
                    update_cmd,
                    console,
                    f"{update_title} (retry after mirror recovery)",
                )
                if retry_error:
                    had_error = True
                    fail_count += 1
                    console.print(
                        "[red]FAIL: Package upgrade aborted — persistent network failure.[/red]"
                    )
                    return 1
                done_count += 1
                if retry_updated:
                    any_updates = True
            elif aur_error:
                had_error = True
                fail_count += 1
                if created_snap:
                    command = (
                        "sudo snapper rollback or select snapshot in bootloader"
                        if created_snap == "snapper"
                        else "sudo timeshift --restore"
                    )
                    console.print(f"  [dim]Rollback available: {command}[/dim]")
                console.print(
                    format_sysup_summary(done=done_count, failed=fail_count, skipped=skip_count)
                )
                return 2
            else:
                done_count += 1
                if aur_updated:
                    any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Package update",
                detail="(no supported package manager installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        if getattr(su, "shutil", shutil).which("flatpak") is not None:
            flatpak_error, _, flatpak_updated = self._run_step(
                ["flatpak", "update", "-y"], console, "Flatpak update"
            )
            had_error |= flatpak_error
            if flatpak_error:
                fail_count += 1
            else:
                done_count += 1
                if flatpak_updated:
                    any_updates = True

            unused_error, _, unused_updated = self._run_step(
                ["flatpak", "uninstall", "--unused", "-y"],
                console,
                "Flatpak cleanup (unused runtimes)",
            )
            had_error |= unused_error
            if unused_error:
                fail_count += 1
            else:
                done_count += 1
                if unused_updated:
                    any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Flatpak update",
                detail="(not installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        if getattr(su, "shutil", shutil).which("paccache") is not None:
            cache_error, _, cache_updated = self._run_step(
                ["sudo", "paccache", "-rk2"],
                console,
                "Pacman cache cleanup (keep 2 versions)",
            )
            had_error |= cache_error
            if cache_error:
                fail_count += 1
            else:
                done_count += 1
                if cache_updated:
                    any_updates = True

            uninstalled_error, _, uninstalled_updated = self._run_step(
                ["sudo", "paccache", "-ruk0"],
                console,
                "Pacman cache cleanup (uninstalled packages)",
            )
            had_error |= uninstalled_error
            if uninstalled_error:
                fail_count += 1
            else:
                done_count += 1
                if uninstalled_updated:
                    any_updates = True

        omz_upgrade = context.home / ".oh-my-zsh" / "tools" / "upgrade.sh"
        if omz_upgrade.exists():
            if os.geteuid() == 0:
                for line_text in format_status_line(
                    STATUS_SKIP,
                    "Oh-My-Zsh update",
                    detail="(skipped: cannot run shell script as root)",
                    width=console_width,
                ):
                    console.print(line_text)
                skip_count += 1
            else:
                omz_error, _, omz_updated = self._run_step(
                    ["sh", str(omz_upgrade)],
                    console,
                    "Oh-My-Zsh update",
                )
                had_error |= omz_error
                if omz_error:
                    fail_count += 1
                else:
                    done_count += 1
                    if omz_updated:
                        any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Oh-My-Zsh update",
                detail="(not installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        if getattr(su, "shutil", shutil).which("fwupdmgr") is not None:
            fw_error, _, fw_updated = self._run_step(
                ["fwupdmgr", "update", "-y"], console, "Firmware update"
            )
            had_error |= fw_error
            if fw_error:
                fail_count += 1
            else:
                done_count += 1
                if fw_updated:
                    any_updates = True
        else:
            for line_text in format_status_line(
                STATUS_SKIP,
                "Firmware update",
                detail="(not installed)",
                width=console_width,
            ):
                console.print(line_text)
            skip_count += 1

        try:
            pacnew_fn = getattr(su, "detect_pacnew_files", detect_pacnew_files)
            pacnew_files = pacnew_fn()
        except OSError:
            pacnew_files = []
            for line in format_status_line("WARN", "configuration files could not be verified"):
                console.print(line)
        if pacnew_files:
            console.print(
                f"\n[bold yellow]Note: {len(pacnew_files)} .pacnew "
                "configuration files found:[/bold yellow]"
            )
            for f in pacnew_files[:5]:
                console.print(f"  [yellow]{escape(str(f))}[/yellow]")
            console.print(
                "[yellow]Run 'pacdiff' to review and merge configuration updates.[/yellow]"
            )

        maint_cls = getattr(su, "MaintenanceChecks", MaintenanceChecks)
        postflight = maint_cls(self.config).run(context, POSTFLIGHT_IDS)
        for result in postflight:
            if result.severity not in {Severity.PASS, Severity.SKIP}:
                for line in format_status_line(
                    result.severity.value if result.severity != Severity.OUTD else "OLD",
                    f"{result.check_id}  {result.message}",
                    width=console_width,
                ):
                    console.print(line)
                items = result.details.get("items") or result.details.get("packages")
                if isinstance(items, list):
                    for item in items:
                        for line in format_status_line("", f"• {item}", width=console_width):
                            line.stylize("dim")
                            console.print(line)
                if result.remediation:
                    for line in format_status_line(
                        "", f"fix: {result.remediation}", width=console_width
                    ):
                        line.stylize("dim")
                        console.print(line)
            if (
                result.check_id == "sys.rebuild"
                and result.details.get("rebuild_packages")
                and not self._offer_rebuilds(result, context, console)
            ):
                had_error = True
                fail_count += 1
        if any(r.severity == Severity.FAIL for r in postflight):
            had_error = True
        console.print()
        console.print(format_sysup_summary(done=done_count, failed=fail_count, skipped=skip_count))
        if any(r.severity not in {Severity.PASS, Severity.SKIP} for r in postflight):
            console.print(
                "[dim]Post-update checks require attention; review the findings above.[/dim]"
            )
        elif not had_error:
            if not any_updates:
                console.print(
                    "[dim]Nothing to update. All packages and components are up to date.[/dim]"
                )
            else:
                console.print("[dim]All updates completed successfully.[/dim]")
        if had_error and created_snap:
            if created_snap == "snapper":
                console.print(
                    "\n[dim]Rollback available: sudo snapper rollback "
                    "or select snapshot in bootloader[/dim]"
                )
            elif created_snap == "timeshift":
                console.print("\n[dim]Rollback available: sudo timeshift --restore[/dim]")

        extra_pkgs = getattr(self.config.maintenance, "extra_reboot_packages", [])
        reboot_fn = getattr(su, "detect_reboot_status", detect_reboot_status)
        try:
            reboot_status = (
                reboot_fn(extra_critical_packages=extra_pkgs) if extra_pkgs else reboot_fn()
            )
        except TypeError:
            reboot_status = reboot_fn()
        if reboot_status.required:
            console.print(
                f"\n[bold yellow]System reboot recommended:[/bold yellow] "
                f"[yellow]{reboot_status.reason}[/yellow]"
            )
            if self._confirm("System reboot is recommended. Reboot the system now?"):
                self._trigger_reboot(console)
        return 2 if had_error else 0

    @staticmethod
    @contextmanager
    def _preflight_progress(console: Console, label: str) -> Iterator[None]:
        animated = (
            bool(getattr(console, "is_terminal", False))
            and not getattr(console, "is_dumb_terminal", False)
            and not any(
                os.environ.get(flag)
                for flag in ("NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR")
            )
        )
        if not animated:
            for line in format_status_line("", label):
                line.stylize("dim")
                console.print(line)
            yield
            return
        table_cls = getattr(su, "Table", Table)
        spinner_cls = getattr(su, "Spinner", Spinner)
        text_cls = getattr(su, "Text", Text)
        live_cls = getattr(su, "Live", Live)
        grid = table_cls.grid(expand=False)
        grid.add_column()
        grid.add_column(width=STATUS_WIDTH)
        grid.add_column()
        grid.add_column()
        grid.add_row(INDENT, spinner_cls("dots"), GAP, text_cls(label, style="dim"))
        with live_cls(grid, console=console, transient=True, refresh_per_second=10):
            yield

    def _maintenance_preflight(
        self, context: ScanContext, console: Console, ids: frozenset[str] = PREFLIGHT_IDS
    ) -> bool:
        with self._preflight_progress(console, "Checking update prerequisites"):
            maint_cls = getattr(su, "MaintenanceChecks", MaintenanceChecks)
            checks = maint_cls(self.config).run(context, ids)
        has_blocking = any(r.details.get("blocks_upgrade") for r in checks)
        for result in checks:
            if result.severity in {Severity.PASS, Severity.SKIP}:
                continue
            for line in format_status_line(result.severity.value, result.message):
                console.print(line)
            if result.check_id == "sys.news":
                notices = result.details.get("notices", [])
                for item in notices:
                    console.print(f"        {item['title']}\n        {item['url']}", markup=False)
                if not has_blocking:
                    prompt = (
                        "Have you read these notices and completed any required steps?"
                        if notices
                        else "Arch notices could not be verified. Continue without reviewing them?"
                    )
                    if not self._confirm(prompt):
                        return False
                    if notices:
                        try:
                            state_cls = getattr(su, "MaintenanceState", MaintenanceState)
                            urls = [n["url"] for n in notices]
                            state_cls().acknowledge_news(urls)
                        except (OSError, ValueError) as exc:
                            for line in format_status_line(
                                "FAIL", f"Could not save reviewed notices: {exc}"
                            ):
                                console.print(line)
                            return False
            else:
                items = result.details.get("items") or result.details.get("packages")
                if items and isinstance(items, list):
                    for item in items:
                        console.print(f"        [dim]• {escape(str(item))}[/dim]")
            if result.check_id != "sys.news" and result.remediation:
                console.print(f"        [dim]fix: {escape(str(result.remediation))}[/dim]")

        if has_blocking:
            blocking_ids = [r.check_id for r in checks if r.details.get("blocks_upgrade")]
            noun = "check" if len(blocking_ids) == 1 else "checks"
            blocked_str = ", ".join(f"'{cid}'" for cid in blocking_ids)
            console.print(
                f"\n  [bold red]FAIL: Upgrade aborted — "
                f"critical preflight {noun} {blocked_str} failed.[/bold red]\n"
            )
            return False
        return True

    def _confirm(self, prompt: str) -> bool:
        if self._confirm_fn is not None:
            return self._confirm_fn(prompt)
        interactive = (
            self._interactive
            if self._interactive is not None
            else (
                (sys.stdin.isatty() and sys.stdout.isatty())
                or getattr(sys.stdin, "__module__", "").startswith(
                    ("click.testing", "typer.testing", "_pytest.capture")
                )
            )
        )
        if not interactive:
            return False
        try:
            typer_mod = getattr(su, "typer", typer)
            return bool(typer_mod.confirm(prompt, default=False))
        except (typer.Abort, EOFError, Exception):
            return False

    def _trigger_reboot(self, console: Console) -> bool:
        if self._reboot_fn is not None:
            return self._reboot_fn()

        base_reboot = (
            ["systemctl", "--no-ask-password", "reboot"]
            if getattr(su, "shutil", shutil).which("systemctl")
            else ["reboot"]
        )
        cmd = base_reboot if os.geteuid() == 0 else ["sudo", "-n", *base_reboot]
        console.print("  [dim]Requesting system reboot[/dim]")
        try:
            sub_run = getattr(su, "subprocess", subprocess).run
            res = sub_run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            console.print(
                "[yellow]Reboot request timed out. "
                "Please reboot manually: sudo systemctl reboot[/yellow]"
            )
            return False
        except (OSError, subprocess.SubprocessError) as exc:
            console.print(f"[red]Reboot command failed:[/red] {escape(str(exc))}")
            return False

        if res.returncode == 0:
            console.print("[green]Reboot request accepted. System will reboot now.[/green]")
            return True

        if os.geteuid() != 0 and getattr(su, "shutil", shutil).which("sudo"):
            with suppress(Exception):
                res_interactive = subprocess.run(["sudo", *base_reboot], timeout=30)
                if res_interactive.returncode == 0:
                    console.print("[green]Reboot request accepted. System will reboot now.[/green]")
                    return True

        console.print(
            f"[red]Reboot command failed (exit={res.returncode}). "
            f"Please reboot manually: sudo systemctl reboot[/red]"
        )
        return False

    def _prepare_keyring(self, console: Console, force: bool = False) -> bool:
        self._keyring_steps = 0
        self._keyring_updated = False
        if "sys.keyring" in {cid.replace(":", ".") for cid in self.config.disabled_checks}:
            return True
        if not getattr(su, "shutil", shutil).which("pacman"):
            return True
        if not force and not getattr(su, "shutil", shutil).which("checkupdates"):
            return True
        try:
            keyrings = self.config.maintenance.keyring_packages
            if not force:
                cap_fn = getattr(su, "capture", capture)
                result = cap_fn(["checkupdates"], 60)
                if result.returncode not in {0, 2}:
                    return True  # The full upgrade will report repository failures.
                available = {line.split()[0] for line in result.stdout.splitlines() if line.split()}
                keyrings = [p for p in keyrings if p in available]
            if not keyrings:
                return True
            if any(not PACKAGE_RE.fullmatch(p) for p in keyrings):
                return False
            err, _, updated = self._run_step(
                ["sudo", "pacman", "-Sy", "--needed", *keyrings],
                console,
                "Package signing key update",
            )
            if err:
                return False
            self._keyring_steps += 1
            self._keyring_updated |= updated
            err, _, updated = self._run_step(
                ["sudo", "pacman", "-Su"], console, "Complete system upgrade after key update"
            )
            if not err:
                self._keyring_steps += 1
                self._keyring_updated |= updated
            return not err
        except (OSError, subprocess.SubprocessError):
            return False

    def _offer_rebuilds(self, result: CheckResult, context: ScanContext, console: Console) -> bool:
        helper = self._aur_helper_fn()
        if helper not in {"paru", "yay"}:
            return True
        successful = True
        for package in result.details["rebuild_packages"]:
            if not PACKAGE_RE.fullmatch(package) or package.endswith("-bin"):
                continue
            if self._confirm(f"Review and rebuild {package} to check library compatibility?"):
                # Paru only consumes an optional value when joined with '=';
                # a separate 'yes' would be interpreted as a package target.
                rebuild_flags = ["--rebuild=yes"] if helper == "paru" else ["--rebuild"]
                error, _, _ = self._run_step(
                    [helper, "-S", *rebuild_flags, "--", package], console, f"Rebuild {package}"
                )
                if not error:
                    maint_cls = getattr(su, "MaintenanceChecks", MaintenanceChecks)
                    refreshed = maint_cls(self.config).run(context, frozenset({"sys.rebuild"}))
                    if (
                        not refreshed
                        or refreshed[0].details.get("verified") is False
                        or refreshed[0].severity == Severity.FAIL
                        or package in refreshed[0].details.get("rebuild_packages", [])
                    ):
                        for line in format_status_line(
                            "WARN", f"{package} still has compatibility findings"
                        ):
                            console.print(line)
                        successful = False
                else:
                    successful = False
        return successful

    def _create_pre_update_snapshot(self, console: Console) -> tuple[bool, str, str | None]:
        console_width = getattr(console, "width", 80) or 80
        tool = (
            getattr(su, "detect_snapshot_tool", self._snapshot_tool_fn)()
            if self._snapshot_tool_fn is detect_snapshot_tool
            else self._snapshot_tool_fn()
        )
        if tool == "snapper":
            cmd = ["sudo", "snapper", "create", "-d", "dotdoctor pre-sysup", "-t", "single", "-p"]
            err, _, _ = self._run_step(cmd, console, "Pre-update snapshot (snapper)")
            if err:
                return True, "fail", None
            return False, "done", "snapper"
        if tool == "timeshift":
            cmd = [
                "sudo",
                "timeshift",
                "--create",
                "--comments",
                "dotdoctor pre-sysup",
                "--tags",
                "D",
            ]
            err, _, _ = self._run_step(cmd, console, "Pre-update snapshot (timeshift)")
            if err:
                return True, "fail", None
            return False, "done", "timeshift"

        for line_text in format_status_line(
            STATUS_SKIP,
            "Pre-update snapshot",
            detail="(no snapshot tool configured)",
            width=console_width,
        ):
            console.print(line_text)
        return False, "skip", None

    def _refresh_mirrors(self, console: Console) -> tuple[bool, str]:
        console_width = getattr(console, "width", 80) or 80
        if getattr(su, "shutil", shutil).which("cachyos-rate-mirrors") is not None:
            had_error, _, _ = self._run_step(
                ["sudo", "cachyos-rate-mirrors"],
                console,
                "Mirror refresh",
            )
            return had_error, "fail" if had_error else "done"

        if getattr(su, "shutil", shutil).which("reflector") is not None:
            had_error, _, _ = self._run_step(
                [
                    "sudo",
                    "reflector",
                    "--latest",
                    "5",
                    "--protocol",
                    "https",
                    "--sort",
                    "rate",
                    "--save",
                    "/etc/pacman.d/mirrorlist",
                ],
                console,
                "Mirror refresh",
            )
            return had_error, "fail" if had_error else "done"

        for line_text in format_status_line(
            STATUS_SKIP,
            "Mirror refresh",
            detail="(no supported mirror tool installed)",
            width=console_width,
        ):
            console.print(line_text)
        return False, "skip"

    def _run_streaming_step(
        self,
        command: list[str],
        console: Console,
        title: str,
        console_width: int,
        timeout: float = 300.0,
    ) -> SimpleNamespace:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            bufsize=1,
        )

        table_cls = getattr(su, "Table", Table)
        spinner_cls = getattr(su, "Spinner", Spinner)
        live_cls = getattr(su, "Live", Live)
        time_mod = getattr(su, "time", time)

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        current_subline: list[str] = [""]
        spinner = spinner_cls("dots")
        ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

        def _read_stream(stream: Any, lines_buf: list[str], is_stdout: bool) -> None:
            try:
                with suppress(Exception):
                    for raw_line in iter(stream.readline, ""):
                        lines_buf.append(raw_line)
                        if is_stdout:
                            cleaned = ansi_re.sub("", raw_line).strip()
                            if cleaned:
                                current_subline[0] = cleaned
            finally:
                with suppress(Exception):
                    stream.close()

        t_out = threading.Thread(
            target=_read_stream, args=(proc.stdout, stdout_lines, True), daemon=True
        )
        t_err = threading.Thread(
            target=_read_stream, args=(proc.stderr, stderr_lines, False), daemon=True
        )
        t_out.start()
        t_err.start()

        def _build_grid(sub: str = "") -> Table:
            grid = table_cls.grid(expand=False)
            grid.add_column()
            grid.add_column(width=STATUS_WIDTH)
            grid.add_column()
            grid.add_column()
            grid.add_row(INDENT, spinner, GAP, title)
            if sub:
                prefix_len = 2 + STATUS_WIDTH + 2 + 2
                max_sub_len = max(10, console_width - prefix_len)
                truncated = sub if len(sub) <= max_sub_len else sub[: max_sub_len - 1] + "…"
                grid.add_row(INDENT, "", GAP, f"[dim]↳ {escape(truncated)}[/dim]")
            return grid

        deadline = time.monotonic() + timeout
        try:
            with live_cls(
                _build_grid(), console=console, transient=True, refresh_per_second=10
            ) as live:
                while proc.poll() is None:
                    if time.monotonic() > deadline:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                        raise subprocess.TimeoutExpired(command, timeout)
                    sub = current_subline[0]
                    live.update(_build_grid(sub))
                    getattr(time_mod, "sleep", time.sleep)(0.08)
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise

        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)
        return SimpleNamespace(
            returncode=proc.returncode if proc.returncode is not None else 1,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
        )

    def _run_step(
        self, command: list[str], console: Console, title: str
    ) -> tuple[bool, bool, bool]:
        if os.geteuid() == 0 and command and command[0] == "sudo":
            command = command[1:]
        console_width = getattr(console, "width", 80) or 80
        is_interactive = (
            bool(getattr(console, "is_terminal", False))
            and not os.environ.get("NO_COLOR")
            and not os.environ.get("NO_ANIMATION")
            and not os.environ.get("DOTDOCTOR_NO_ANIMATION")
        )
        needs_input = (
            any(name in command for name in {"pacman", "yay", "paru"})
            and any(flag in command for flag in {"-Sy", "-Su", "-S"})
            and "--noconfirm" not in command
        )
        sub_run = getattr(su, "subprocess", subprocess).run
        orig_run = getattr(su, "_ORIGINAL_SUBPROCESS_RUN", _ORIGINAL_SUBPROCESS_RUN)
        completed: Any
        try:
            if needs_input:
                # Pacman/AUR review prompts must remain visible and retain stdin.
                # A pipe reader can hide a prompt without a newline and deadlock.
                completed = sub_run(command, check=False, env={**os.environ, "LC_ALL": "C"})
            elif is_interactive and hasattr(console, "status") and sub_run is orig_run:
                completed = self._run_streaming_step(
                    command, console, title, console_width, timeout=300.0
                )
            else:
                completed = sub_run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
        except subprocess.TimeoutExpired:
            for line_text in format_status_line(
                STATUS_FAIL, title, detail="(timed out)", width=console_width
            ):
                console.print(line_text)
            return True, True, False
        except (OSError, subprocess.SubprocessError) as exc:
            for line_text in format_status_line(
                STATUS_FAIL, title, detail=f"(failed to start: {exc})", width=console_width
            ):
                console.print(line_text)
            return True, False, False

        stderr_output = (getattr(completed, "stderr", "") or "").strip()
        stdout_output = (getattr(completed, "stdout", "") or "").strip()
        combined_output = f"{stdout_output}\n{stderr_output}".strip()
        self._last_step_output = combined_output
        is_mirror_fn = getattr(su, "_is_mirror_failure", _is_mirror_failure)
        is_net_failure = is_mirror_fn(combined_output)

        if completed.returncode != 0:
            for line_text in format_status_line(
                STATUS_FAIL,
                title,
                detail=f"(exit={completed.returncode})",
                width=console_width,
            ):
                console.print(line_text)
            error_text = stderr_output if stderr_output else stdout_output
            if error_text:
                error_lines = [line.rstrip() for line in error_text.splitlines() if line.strip()]
                prefix = "        │ "
                avail_width = max(15, console_width - len(prefix))
                if len(error_lines) > 10:
                    omitted = len(error_lines) - 10
                    console.print(f"        [dim]│ ({omitted} lines omitted)[/dim]")
                    error_lines = error_lines[-10:]
                for err_line in error_lines:
                    wrapped_err = textwrap.wrap(err_line, width=avail_width) or [err_line]
                    for i, w in enumerate(wrapped_err):
                        p = prefix if i == 0 else "          "
                        console.print(f"[dim]{p}{escape(w)}[/dim]")
            return True, is_net_failure, False

        detect_step_fn = getattr(su, "_detect_step_updates", _detect_step_updates)
        had_updates = needs_input or detect_step_fn(command, stdout_output, stderr_output)
        for line_text in format_status_line(STATUS_DONE, title, width=console_width):
            console.print(line_text)
        return False, False, had_updates


__all__ = [
    "SystemUpgradeService",
    "detect_snapshot_tool",
]
