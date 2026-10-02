import os
import time
from pathlib import Path
from typing import Any

import typer
import typer.rich_utils
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from typer._click import exceptions as _click_exceptions

from dotdoctor.application.auto_fix import InteractiveAutoFixer
from dotdoctor.application.system_update import SystemDryRunService, SystemUpgradeService
from dotdoctor.application.use_cases import RunScanUseCase
from dotdoctor.cli.render import build_live_dashboard, render_terminal_report
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
from dotdoctor.infrastructure.checks.registry import resolve_checks
from dotdoctor.infrastructure.config_loader import ConfigError, load_config


def _custom_rich_format_error(self: Any) -> None:
    console = Console(stderr=True)
    if isinstance(self, _click_exceptions.NoSuchOption):
        opt = self.option_name
        if self.possibilities:
            possibilities_str = ", or ".join(self.possibilities)
            msg = f"unknown option {opt}. Did you mean {possibilities_str}?"
        else:
            msg = f"unknown option {opt}. Run 'dotdoctor --help' for usage."
    elif isinstance(self, _click_exceptions.BadParameter):
        msg = getattr(self, "message", None) or self.format_message()
        if msg.startswith("Invalid value: "):
            msg = msg[len("Invalid value: ") :]
    elif isinstance(self, _click_exceptions.ClickException):
        msg = self.format_message()
    else:
        msg = str(self)

    err_text = Text()
    err_text.append("error: ", style="bold red")
    err_text.append(msg)
    console.print(err_text, soft_wrap=True)


typer.rich_utils.rich_format_error = _custom_rich_format_error

app = typer.Typer(help="DotDoctor: diagnose Linux development environment issues.")

PROFILE_OPTION = typer.Option("python-dev", help="Scan profile name.")
CONFIG_OPTION = typer.Option(
    None,
    "--config",
    help="Path to dotdoctor YAML config. Defaults to dotdoctor.yml or DOTDOCTOR_CONFIG.",
)
DISABLE_CHECK_OPTION = typer.Option(
    [],
    "--disable-check",
    help="Disable a check id for this run (can be repeated).",
)
JSON_OUTPUT_OPTION = typer.Option(
    None,
    "--json-output",
    help="Optional file path for machine-readable JSON report.",
)
UI_OPTION = typer.Option(
    False,
    "--ui/--no-ui",
    help="Use fullscreen live interface during scan.",
)
FIX_OPTION = typer.Option(
    False,
    "--fix",
    help="Interactively apply safe auto-fixes for WARN/FAIL findings.",
)
ENV_OPTION = typer.Option(
    False,
    "--env",
    help="Run development environment checks.",
)
SYS_OPTION = typer.Option(
    False,
    "--sys",
    help="Run parallel dry-run system update checks (default).",
)
SYSUP_OPTION = typer.Option(
    False,
    "--sysup",
    help="Run sequential real system update commands.",
)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    env: bool = ENV_OPTION,
    fix: bool = FIX_OPTION,
    sys: bool = SYS_OPTION,
    sysup: bool = SYSUP_OPTION,
) -> None:
    if ctx.invoked_subcommand is None:
        if env and (sys or sysup):
            raise typer.BadParameter("Use either --env, --sys, or --sysup, not combined.")
        if sys and sysup:
            raise typer.BadParameter("Use either --sys or --sysup, not both.")
        if fix and sysup:
            raise typer.BadParameter("Use either --fix or --sysup, not both.")

        if env:
            _scan_impl(
                profile="python-dev",
                config=None,
                disable_check=[],
                json_output=None,
                ui=True,
                fix=fix,
            )
            return

        if sysup:
            _system_upgrade_impl()
            return

        _system_dry_run_impl(fix_mode=fix)


@app.command("version")
def version() -> None:
    """Print DotDoctor version."""
    console = Console()
    console.print("dotdoctor 0.1.0")


@app.command("scan")
def scan(
    profile: str = PROFILE_OPTION,
    config: Path | None = CONFIG_OPTION,
    disable_check: list[str] = DISABLE_CHECK_OPTION,
    json_output: Path | None = JSON_OUTPUT_OPTION,
    ui: bool = UI_OPTION,
    fix: bool = FIX_OPTION,
) -> None:
    _scan_impl(profile, config, disable_check, json_output, ui, fix)


def _scan_impl(
    profile: str,
    config: Path | None,
    disable_check: list[str],
    json_output: Path | None,
    ui: bool,
    fix: bool,
) -> None:
    console = Console()

    try:
        loaded = load_config(config)
        selected_profile = loaded.profiles.get(profile)
        if selected_profile is None:
            available = ", ".join(sorted(loaded.profiles.keys()))
            raise ValueError(f"Unknown profile '{profile}'. Available: {available}")

        context = ScanContext(
            profile=profile,
            cwd=Path.cwd(),
            home=Path.home(),
            path_value=os.environ.get("PATH", ""),
            shell=os.environ.get("SHELL"),
        )

        use_case = RunScanUseCase(resolve_checks(selected_profile, set(disable_check)))
        if fix:
            report = use_case.execute(context)
        else:
            report = _run_scan(use_case, context, console, ui=ui)

        if fix:
            fixer = InteractiveAutoFixer(console)
            report = fixer.apply(report, context)

        if json_output is not None:
            json_output.parent.mkdir(parents=True, exist_ok=True)
            json_output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"JSON report exported to: {json_output}")

        raise typer.Exit(code=report.exit_code)
    except typer.Exit:
        raise
    except ConfigError as exc:
        console.print(f"[red]DotDoctor config error:[/red] {exc}")
        raise typer.Exit(code=3) from None
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]DotDoctor runtime error:[/red] {exc}")
        raise typer.Exit(code=3) from None


def _safe_confirm(prompt: str, default: bool = True) -> bool:
    try:
        return typer.confirm(prompt, default=default)
    except (typer.Abort, Exception):
        return False


def _system_dry_run_impl(fix_mode: bool = False) -> None:
    console = Console()
    context = ScanContext(
        profile="system",
        cwd=Path.cwd(),
        home=Path.home(),
        path_value=os.environ.get("PATH", ""),
        shell=os.environ.get("SHELL"),
    )
    service = SystemDryRunService()
    tasks = service.build_tasks(context)

    states: dict[str, str] = {task.check_id: "running" for task in tasks}

    def _build_steps_table() -> Table:
        steps = Table.grid(expand=False)
        steps.add_column(justify="left")
        steps.add_column(justify="left")
        for task in tasks:
            status: str | Spinner
            if states[task.check_id] == "done":
                status = "[green]Done[/green]"
            else:
                status = Spinner("dots", text="Running")
            steps.add_row(task.label, status)
        return steps

    with Live(
        _build_steps_table(),
        console=console,
        transient=True,
        refresh_per_second=12,
    ) as live:

        def _mark_done(check_id: str) -> None:
            states[check_id] = "done"
            live.update(_build_steps_table())

        report = service.run_with_progress(context, on_task_complete=_mark_done)

    render_terminal_report(report, console)

    if fix_mode:
        fixer = InteractiveAutoFixer(console)
        report = fixer.apply(report, context)
        raise typer.Exit(code=report.exit_code)

    has_updates = any(r.severity == Severity.OUTD for r in report.results)
    has_issues = any(r.severity in {Severity.WARN, Severity.FAIL} for r in report.results)

    if has_updates:
        console.print()
        if _safe_confirm("Update everything now?", default=True):
            upgrade_service = SystemUpgradeService()
            upgrade_service.run(context, console)

    if has_issues:
        console.print()
        if _safe_confirm("Apply fixes for detected issues now?", default=True):
            fixer = InteractiveAutoFixer(console)
            report = fixer.apply(report, context)

    raise typer.Exit(code=report.exit_code)


def _system_upgrade_impl() -> None:
    console = Console()
    context = ScanContext(
        profile="system",
        cwd=Path.cwd(),
        home=Path.home(),
        path_value=os.environ.get("PATH", ""),
        shell=os.environ.get("SHELL"),
    )
    code = SystemUpgradeService().run(context, console)
    raise typer.Exit(code=code)


def _run_scan(
    use_case: RunScanUseCase,
    context: ScanContext,
    console: Console,
    ui: bool,
) -> ScanReport:
    if not ui:
        report = use_case.execute(context)
        render_terminal_report(report, console)
        return report

    results: list[CheckResult] = []
    total_checks = use_case.total_checks
    started = time.monotonic()

    with Live(
        build_live_dashboard(
            profile=context.profile,
            results=results,
            total_checks=total_checks,
            elapsed_seconds=0.0,
            active_check_id=None,
        ),
        console=console,
        screen=True,
        refresh_per_second=10,
    ) as live:
        for result in use_case.execute_iter(context):
            results.append(result)
            live.update(
                build_live_dashboard(
                    profile=context.profile,
                    results=results,
                    total_checks=total_checks,
                    elapsed_seconds=time.monotonic() - started,
                    active_check_id=result.check_id,
                )
            )

        live.update(
            build_live_dashboard(
                profile=context.profile,
                results=results,
                total_checks=total_checks,
                elapsed_seconds=time.monotonic() - started,
                active_check_id=None,
            )
        )

    check_order = {check.check_id: i for i, check in enumerate(use_case.checks)}
    results.sort(key=lambda r: check_order.get(r.check_id, 999))

    report = ScanReport(profile=context.profile, results=results)
    render_terminal_report(report, console)
    return report
