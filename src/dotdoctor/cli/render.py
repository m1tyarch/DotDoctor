import os
import textwrap
import time

from rich.console import Console
from rich.layout import Layout
from rich.table import Table
from rich.text import Text

from dotdoctor.domain.models import CheckResult, ScanReport, Severity

DEFAULT_ANIMATION_DELAY = 0.025


def _sleep(seconds: float) -> None:
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass


def _status_label(severity: Severity) -> str:
    if severity == Severity.OUTD:
        return "OLD"
    return severity.value


def _status_style(severity: Severity) -> str:
    if severity == Severity.PASS:
        return "dim green"
    if severity == Severity.OUTD:
        return "bold cyan"
    if severity == Severity.WARN:
        return "bold yellow"
    if severity == Severity.FAIL:
        return "bold red"
    return "default"


def format_summary(summary: dict[str, int]) -> Text:
    pass_count = summary.get("PASS", 0)
    outd_count = summary.get("OUTD", 0)
    warn_count = summary.get("WARN", 0)
    fail_count = summary.get("FAIL", 0)
    total = pass_count + outd_count + warn_count + fail_count

    if total > 0 and pass_count == total:
        noun = "check" if total == 1 else "checks"
        return Text(f"All {total} {noun} passed")

    parts: list[tuple[str, str | None]] = []
    if pass_count > 0:
        parts.append((f"{pass_count} passed", None))
    if outd_count > 0:
        parts.append((f"{outd_count} outdated", "cyan"))
    if warn_count > 0:
        noun = "warning" if warn_count == 1 else "warnings"
        parts.append((f"{warn_count} {noun}", "yellow"))
    if fail_count > 0:
        parts.append((f"{fail_count} failed", "red"))

    if not parts:
        return Text("0 checks passed")

    summary_text = Text()
    for i, (txt, style) in enumerate(parts):
        if i > 0:
            summary_text.append(" \u00b7 ")
        summary_text.append(txt, style=style)
    return summary_text


def _wrap_text(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in text.splitlines():
        wrapped = textwrap.wrap(paragraph, width=width)
        lines.extend(wrapped if wrapped else [""])
    return lines or [""]


def render_terminal_report(
    report: ScanReport,
    console: Console,
    animate: bool | None = None,
    delay: float = DEFAULT_ANIMATION_DELAY,
) -> None:
    header = Text("DotDoctor \u00b7 ")
    header.append(report.profile, style="dim")
    console.print(header)
    console.print()

    if not report.results:
        console.print(format_summary(report.summary))
        return

    should_animate = (
        animate
        if animate is not None
        else (
            console.is_terminal
            and not console.is_dumb_terminal
            and not os.environ.get("NO_ANIMATION")
            and not os.environ.get("DOTDOCTOR_NO_ANIMATION")
        )
    )

    max_status_len = max((len(_status_label(r.severity)) for r in report.results), default=4)
    max_id_len = max((len(r.check_id) for r in report.results), default=0)

    prefix_len = 2 + max_status_len + 2 + max_id_len + 2
    indent_spaces = " " * prefix_len

    console_width = console.width if console and console.width else 80
    msg_width = max(15, console_width - prefix_len)

    for result in report.results:
        label = _status_label(result.severity)
        st_style = _status_style(result.severity)
        id_str = result.check_id.ljust(max_id_len)
        msg_style = "dim" if result.severity == Severity.PASS else None

        msg_lines = _wrap_text(result.message, msg_width)

        line1 = Text("  ")
        line1.append(label.ljust(max_status_len), style=st_style)
        line1.append("  ")
        line1.append(id_str)
        line1.append("  ")
        line1.append(msg_lines[0], style=msg_style)
        console.print(line1)
        if should_animate:
            _sleep(delay)

        for extra_line in msg_lines[1:]:
            cont_line = Text(indent_spaces)
            cont_line.append(extra_line, style=msg_style)
            console.print(cont_line)
            if should_animate:
                _sleep(delay)

        if result.severity != Severity.PASS and result.remediation:
            fix_text = f"fix: {result.remediation}"
            fix_lines = _wrap_text(fix_text, msg_width)
            for fix_line in fix_lines:
                f_line = Text(indent_spaces)
                f_line.append(fix_line, style="dim")
                console.print(f_line)
                if should_animate:
                    _sleep(delay)

    console.print()
    if should_animate:
        _sleep(delay)
    console.print(format_summary(report.summary))


def build_live_dashboard(
    profile: str,
    results: list[CheckResult],
    total_checks: int,
    elapsed_seconds: float,
    active_check_id: str | None,
) -> Layout:
    header = Text("DotDoctor \u00b7 ")
    header.append(f"{profile}  ({elapsed_seconds:.1f}s)", style="dim")

    completed = len(results)
    ratio = completed / total_checks if total_checks > 0 else 1.0
    bar_width = 24
    filled = int(ratio * bar_width)
    progress_bar = "[" + ("#" * filled) + ("-" * (bar_width - filled)) + "]"
    progress_text = Text(f"  progress {progress_bar} {completed}/{total_checks}", style="dim")

    body = Table.grid(expand=True)
    body.add_column()
    body.add_row(header)
    body.add_row(Text(""))
    body.add_row(progress_text)
    body.add_row(Text(""))

    max_status_len = max((len(_status_label(r.severity)) for r in results), default=4)
    max_id_len = max((len(r.check_id) for r in results), default=0)
    for result in results[-12:]:
        label = _status_label(result.severity)
        st_style = _status_style(result.severity)
        id_str = result.check_id.ljust(max_id_len)
        msg_style = "dim" if result.severity == Severity.PASS else None

        line = Text("  ")
        line.append(label.ljust(max_status_len), style=st_style)
        line.append("  ")
        line.append(id_str)
        line.append("  ")
        line.append(result.message, style=msg_style)
        body.add_row(line)

    layout = Layout()
    layout.update(body)
    return layout
