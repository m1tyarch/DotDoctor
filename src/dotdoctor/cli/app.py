import os
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
from dotdoctor.application.system_update import (
    FIX_CHECK_IDS,
    UPDATE_CHECK_IDS,
    SystemCheckTask,
    SystemDryRunService,
    SystemUpgradeService,
)
from dotdoctor.cli.render import format_check_status, render_terminal_report
from dotdoctor.cli.theme import (
    GAP,
    INDENT,
    STATUS_SKIP,
    STATUS_WIDTH,
    STYLE_SKIP,
    format_header,
)
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, ScanReport, Severity
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

app = typer.Typer(
    help="DotDoctor: Minimalist Linux system diagnostic and update utility.",
    add_completion=False,
)

SYSUP_OPTION = typer.Option(
    False,
    "--sysup",
    help="Run sequential comprehensive system update.",
)
FIX_OPTION = typer.Option(
    False,
    "--fix",
    help="Interactively apply safe auto-fixes for detected issues.",
)
VERBOSE_OPTION = typer.Option(
    False,
    "--verbose",
    "-v",
    help="Show detailed findings and package version lists.",
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
CONFIG_OPTION = typer.Option(
    None,
    "--config",
    help="Path to dotdoctor YAML config. Defaults to XDG config or dotdoctor.yml.",
)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    sysup: bool = SYSUP_OPTION,
    fix: bool = FIX_OPTION,
    verbose: bool = VERBOSE_OPTION,
    disable_check: list[str] = DISABLE_CHECK_OPTION,
    json_output: Path | None = JSON_OUTPUT_OPTION,
    config: Path | None = CONFIG_OPTION,
) -> None:
    if ctx.invoked_subcommand is None:
        if sysup and fix:
            raise typer.BadParameter("Use either --sysup or --fix, not both.")

        if sysup:
            _system_upgrade_impl(
                verbose=verbose,
                disable_check=disable_check,
                config_path=config,
            )
            return

        if fix:
            _system_fix_impl(
                verbose=verbose,
                disable_check=disable_check,
                json_output=json_output,
                config_path=config,
            )
            return

        _system_dry_run_impl(
            verbose=verbose,
            json_output=json_output,
            disable_check=disable_check,
            config_path=config,
        )


@app.command("version")
def version() -> None:
    """Print DotDoctor version."""
    console = Console()
    console.print("dotdoctor 0.1.0")


def _safe_confirm(prompt: str, default: bool = True) -> bool:
    try:
        return typer.confirm(prompt, default=default)
    except (typer.Abort, Exception):
        return False


def _run_tasks_with_progress(
    service: SystemDryRunService,
    context: ScanContext,
    tasks: list[SystemCheckTask],
    all_disabled: list[str],
    include_checks: frozenset[str] | None,
    console: Console,
) -> ScanReport:
    results: dict[str, CheckResult | None] = {}
    spinners = {task.check_id: Spinner("dots") for task in tasks}
    id_width = max((len(task.check_id) for task in tasks), default=0)

    def _build_steps_table() -> Table:
        grid = Table.grid(expand=True, padding=0)
        grid.add_column(width=len(INDENT))
        grid.add_column(width=STATUS_WIDTH, no_wrap=True)
        grid.add_column(width=len(GAP))
        grid.add_column(width=id_width, no_wrap=True, overflow="ellipsis")
        grid.add_column(width=len(GAP))
        grid.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        for task in tasks:
            st_renderable: Text | Spinner
            result = results.get(task.check_id)
            if result is not None:
                st_renderable = format_check_status(result)
                message = Text(
                    " ".join(result.message.split()),
                    style="dim" if result.severity == Severity.PASS else "",
                )
            elif task.check_id in results:
                st_renderable = Text(STATUS_SKIP, style=STYLE_SKIP)
                message = Text("no result reported", style="dim")
            else:
                st_renderable = spinners[task.check_id]
                message = Text(" ".join(task.label.split()))
            grid.add_row(INDENT, st_renderable, GAP, Text(task.check_id), GAP, message)
        return grid

    is_interactive = (
        console.is_terminal
        and not console.is_dumb_terminal
        and not os.environ.get("NO_ANIMATION")
        and not os.environ.get("DOTDOCTOR_NO_ANIMATION")
        and not os.environ.get("NO_COLOR")
    )

    if is_interactive:
        with Live(
            _build_steps_table(),
            console=console,
            transient=True,
            refresh_per_second=12.5,
        ) as live:

            def _show_result(check_id: str, result: CheckResult | None) -> None:
                results[check_id] = result
                live.update(_build_steps_table(), refresh=True)

            return service.run_with_progress(
                context,
                on_task_result=_show_result,
                disabled_checks=all_disabled,
                include_checks=include_checks,
                tasks=tasks,
            )
    else:
        return service.run_with_progress(
            context,
            disabled_checks=all_disabled,
            include_checks=include_checks,
            tasks=tasks,
        )


def _system_fix_impl(
    verbose: bool = False,
    disable_check: list[str] | None = None,
    json_output: Path | None = None,
    config_path: Path | None = None,
) -> None:
    console = Console()
    try:
        loaded_cfg = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]DotDoctor config error:[/red] {exc}")
        raise typer.Exit(code=3) from None

    all_disabled: list[str] = list(loaded_cfg.disabled_checks)
    if disable_check:
        all_disabled.extend(disable_check)

    context = ScanContext(
        profile="system",
        cwd=Path.cwd(),
        home=Path.home(),
        path_value=os.environ.get("PATH", ""),
        shell=os.environ.get("SHELL"),
    )
    console.print(format_header("fix"))
    console.print()

    loaded_cfg = loaded_cfg.model_copy(update={"disabled_checks": all_disabled})
    service = SystemDryRunService(config=loaded_cfg)
    tasks = service.build_tasks(
        context,
        disabled_checks=all_disabled,
        include_checks=FIX_CHECK_IDS,
    )
    report = _run_tasks_with_progress(
        service,
        context,
        tasks,
        all_disabled,
        include_checks=FIX_CHECK_IDS,
        console=console,
    )

    issues = [r for r in report.results if r.severity in {Severity.WARN, Severity.FAIL}]

    if not issues:
        console.print("  [dim green]PASS[/dim green]  System hygiene clean.")
        console.print("\n[dim]Nothing to fix.[/dim]")
        if json_output is not None:
            json_output.parent.mkdir(parents=True, exist_ok=True)
            json_output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"JSON report exported to: {json_output}")
        raise typer.Exit(code=0)

    # Show only actionable findings
    issues_report = ScanReport(profile="system", results=issues)
    render_terminal_report(issues_report, console, print_header=False, verbose=verbose)
    console.print()

    fixer = InteractiveAutoFixer(console, config=loaded_cfg)
    report = fixer.apply(report, context)

    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"JSON report exported to: {json_output}")

    raise typer.Exit(code=report.exit_code)


def _system_upgrade_impl(
    verbose: bool = False,
    disable_check: list[str] | None = None,
    config_path: Path | None = None,
) -> None:
    console = Console()
    try:
        loaded_cfg = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]DotDoctor config error:[/red] {exc}")
        raise typer.Exit(code=3) from None

    all_disabled: list[str] = list(loaded_cfg.disabled_checks)
    if disable_check:
        all_disabled.extend(disable_check)

    context = ScanContext(
        profile="system",
        cwd=Path.cwd(),
        home=Path.home(),
        path_value=os.environ.get("PATH", ""),
        shell=os.environ.get("SHELL"),
    )
    console.print(format_header("system update"))
    console.print()

    loaded_cfg = loaded_cfg.model_copy(update={"disabled_checks": all_disabled})
    service = SystemDryRunService(config=loaded_cfg)
    tasks = service.build_tasks(
        context,
        disabled_checks=all_disabled,
        include_checks=UPDATE_CHECK_IDS,
    )
    report = _run_tasks_with_progress(
        service,
        context,
        tasks,
        all_disabled,
        include_checks=UPDATE_CHECK_IDS,
        console=console,
    )

    has_updates = any(r.severity == Severity.OUTD for r in report.results)
    has_fails = any(r.severity == Severity.FAIL for r in report.results)

    if not has_updates and not has_fails:
        warnings = [r for r in report.results if r.severity == Severity.WARN]
        if warnings:
            render_terminal_report(
                ScanReport(profile="system", results=warnings),
                console,
                print_header=False,
                verbose=verbose,
            )
            console.print("\n[dim]No updates reported; review the findings above.[/dim]")
        else:
            console.print("  [dim green]PASS[/dim green]  No updates reported by enabled checks.")
            console.print("\n[dim]Nothing to update.[/dim]")
        raise typer.Exit(code=0)

    # Show outdated or failed checks
    non_pass_results = (
        report.results if verbose else [r for r in report.results if r.severity != Severity.PASS]
    )
    if non_pass_results:
        update_report = ScanReport(profile="system", results=non_pass_results)
        render_terminal_report(update_report, console, print_header=False, verbose=verbose)

    if has_updates:
        crit_names: list[str] = []
        for item in report.results:
            if item.severity is Severity.OUTD and item.details and item.details.get("critical"):
                crit_names.extend(item.details["critical"])
        if crit_names:
            crit_str = ", ".join(sorted(set(crit_names)))
            console.print(
                f"\n  [yellow]Note: Critical updates detected ({crit_str}) — "
                "reboot will be recommended.[/yellow]"
            )
        console.print()

    if has_fails and not has_updates:
        raise typer.Exit(code=2)

    upgrade_service = SystemUpgradeService(config=loaded_cfg)
    code = upgrade_service.run(context, console)
    raise typer.Exit(code=code)


def _system_dry_run_impl(
    verbose: bool = False,
    json_output: Path | None = None,
    disable_check: list[str] | None = None,
    config_path: Path | None = None,
) -> None:
    console = Console()
    try:
        loaded_cfg = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]DotDoctor config error:[/red] {exc}")
        raise typer.Exit(code=3) from None

    all_disabled: list[str] = list(loaded_cfg.disabled_checks)
    if disable_check:
        all_disabled.extend(disable_check)

    context = ScanContext(
        profile="system",
        cwd=Path.cwd(),
        home=Path.home(),
        path_value=os.environ.get("PATH", ""),
        shell=os.environ.get("SHELL"),
    )
    console.print(format_header(context.profile))
    console.print()

    loaded_cfg = loaded_cfg.model_copy(update={"disabled_checks": all_disabled})
    service = SystemDryRunService(config=loaded_cfg)
    tasks = service.build_tasks(context, disabled_checks=all_disabled)
    report = _run_tasks_with_progress(
        service,
        context,
        tasks,
        all_disabled,
        include_checks=None,
        console=console,
    )

    render_terminal_report(report, console, print_header=False, verbose=verbose)

    has_updates = any(r.severity == Severity.OUTD for r in report.results)
    has_issues = any(r.severity in {Severity.WARN, Severity.FAIL} for r in report.results)

    if has_updates:
        crit_names: list[str] = []
        for item in report.results:
            if item.severity is Severity.OUTD and item.details and item.details.get("critical"):
                crit_names.extend(item.details["critical"])
        if crit_names:
            crit_str = ", ".join(sorted(set(crit_names)))
            console.print(
                f"\n  [yellow]Note: Critical updates detected ({crit_str}) — "
                "reboot will be recommended.[/yellow]"
            )
        console.print()
        if _safe_confirm("Update everything now?", default=True):
            console.print()
            console.print(format_header("system update"))
            console.print()
            upgrade_service = SystemUpgradeService(config=loaded_cfg)
            upgrade_code = upgrade_service.run(context, console)
            if upgrade_code:
                if json_output is not None:
                    json_output.parent.mkdir(parents=True, exist_ok=True)
                    json_output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
                raise typer.Exit(code=upgrade_code)
            # Re-evaluate report after system update
            report = service.run(context, disabled_checks=all_disabled)
            has_issues = any(r.severity in {Severity.WARN, Severity.FAIL} for r in report.results)

    if has_issues:
        fixer = InteractiveAutoFixer(console, config=loaded_cfg)
        if any(fixer.can_fix(result) for result in report.results) and _safe_confirm(
            "Apply fixes for detected issues now?", default=True
        ):
            report = fixer.apply(report, context)

    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"JSON report exported to: {json_output}")

    raise typer.Exit(code=report.exit_code)
