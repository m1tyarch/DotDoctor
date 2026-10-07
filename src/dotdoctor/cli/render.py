import textwrap
from typing import Any

from rich.console import Console
from rich.text import Text

from dotdoctor.cli.theme import (
    STATUS_FAIL,
    STATUS_OLD,
    STATUS_PASS,
    STATUS_STYLES,
    STATUS_WARN,
    STYLE_DEFAULT,
    STYLE_OLD,
    STYLE_WARN,
    format_header,
)
from dotdoctor.domain.models import CheckResult, ScanReport, Severity


def _status_label(severity: Severity) -> str:
    if severity == Severity.OUTD:
        return STATUS_OLD
    if severity == Severity.PASS:
        return STATUS_PASS
    if severity == Severity.WARN:
        return STATUS_WARN
    if severity == Severity.FAIL:
        return STATUS_FAIL
    return severity.value


def _status_style(severity: Severity) -> str:
    label = _status_label(severity)
    return STATUS_STYLES.get(label, STYLE_DEFAULT)


def format_check_status(result: CheckResult) -> Text:
    return Text(_status_label(result.severity), style=_status_style(result.severity))


def format_summary(
    summary: dict[str, int],
    is_final: bool = True,
    all_passed: bool = False,
    total_target: int | None = None,
    **kwargs: Any,
) -> Text:
    pass_count = summary.get("PASS", 0)
    outd_count = summary.get("OUTD", 0)
    warn_count = summary.get("WARN", 0)
    fail_count = summary.get("FAIL", 0)
    total = pass_count + outd_count + warn_count + fail_count

    if all_passed or (is_final and total > 0 and pass_count == total):
        ref_total = (
            total_target if total_target is not None else (total if total > 0 else pass_count)
        )
        noun = "check" if ref_total == 1 else "checks"
        return Text(f"All {pass_count} {noun} passed")

    parts: list[tuple[str, str | None]] = []
    if pass_count > 0:
        parts.append((f"{pass_count} passed", None))
    elif not is_final:
        parts.append(("0 passed", "dim"))

    if outd_count > 0:
        parts.append((f"{outd_count} outdated", STYLE_OLD))
    if warn_count > 0:
        noun = "warning" if warn_count == 1 else "warnings"
        parts.append((f"{warn_count} {noun}", STYLE_WARN))
    if fail_count > 0:
        parts.append((f"{fail_count} failed", "red"))

    if not parts:
        return Text("0 checks passed")

    summary_text = Text()
    for i, (txt, style) in enumerate(parts):
        if i > 0:
            summary_text.append(" · ")
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
    print_header: bool = True,
    verbose: bool = False,
    **kwargs: Any,
) -> None:
    if print_header:
        console.print(format_header(report.profile))
        console.print()

    if not report.results:
        console.print(format_summary(report.summary))
        return

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

        for extra_line in msg_lines[1:]:
            cont_line = Text(indent_spaces)
            cont_line.append(extra_line, style=msg_style)
            console.print(cont_line)

        packages = (
            result.details.get("items") or result.details.get("packages")
            if result.details
            else None
        )
        item_noun = "item" if result.details.get("items") else "package"
        critical = result.details.get("critical") if result.details else None
        if packages and isinstance(packages, list) and result.severity != Severity.PASS:
            to_show: list[str] = []
            if verbose:
                to_show = packages
            else:
                if critical:
                    for pkg in packages:
                        p_name = pkg.split()[0].replace("•", "").strip()
                        if p_name in critical:
                            to_show.append(pkg)
                if len(to_show) < 3:
                    for pkg in packages:
                        if pkg not in to_show:
                            to_show.append(pkg)
                        if len(to_show) >= 3:
                            break

            for pkg in to_show:
                pkg_text = f"• {pkg}"
                for p_line in _wrap_text(pkg_text, msg_width):
                    pkg_line = Text(indent_spaces)
                    pkg_line.append(p_line, style="dim")
                    console.print(pkg_line)

            if len(packages) > len(to_show) and not verbose:
                omitted = len(packages) - len(to_show)
                noun = item_noun if omitted == 1 else f"{item_noun}s"
                omit_line = Text(indent_spaces)
                omit_line.append(f"• ({omitted} more {noun}, use -v to show all)", style="dim")
                console.print(omit_line)

        if result.severity != Severity.PASS and result.remediation:
            fix_text = f"fix: {result.remediation}"
            fix_lines = _wrap_text(fix_text, msg_width)
            for fix_line in fix_lines:
                f_line = Text(indent_spaces)
                f_line.append(fix_line, style="dim")
                console.print(f_line)

    console.print()
    console.print(format_summary(report.summary))
