import math
import textwrap
from collections.abc import Sequence
from typing import Any

from rich.console import Console
from rich.text import Text

from dotdoctor.application.disk import _format_bytes
from dotdoctor.application.reboot import is_critical_reboot_package
from dotdoctor.cli.theme import (
    PREFIX_LEN,
    STATUS_FAIL,
    STATUS_OLD,
    STATUS_PASS,
    STATUS_SKIP,
    STATUS_STYLES,
    STATUS_WARN,
    STYLE_DEFAULT,
    STYLE_MUTED,
    STYLE_OLD,
    STYLE_WARN,
    format_duration_ms,
    format_header,
    format_status_line,
)
from dotdoctor.domain.models import CheckResult, ScanReport, Severity, normalize_check_id


def _status_label(severity: Severity) -> str:
    if severity == Severity.OUTD:
        return STATUS_OLD
    if severity == Severity.PASS:
        return STATUS_PASS
    if severity == Severity.WARN:
        return STATUS_WARN
    if severity == Severity.FAIL:
        return STATUS_FAIL
    if severity == Severity.SKIP:
        return STATUS_SKIP
    return severity.value


def _status_style(severity: Severity) -> str:
    label = _status_label(severity)
    return STATUS_STYLES.get(label, STYLE_DEFAULT)


def format_check_status(result: CheckResult) -> Text:
    return Text(_status_label(result.severity), style=_status_style(result.severity))


def _format_duration(duration_seconds: float | None) -> str | None:
    if (
        duration_seconds is None
        or isinstance(duration_seconds, bool)
        or not isinstance(duration_seconds, (int, float))
    ):
        return None
    dur = float(duration_seconds)
    if not math.isfinite(dur) or dur < 0:
        return None
    return f"{dur:.1f}s" if dur < 10.0 else f"{dur:.0f}s"


def _extract_clean_metrics(report: ScanReport) -> list[str]:
    metrics: list[str] = []

    disk_res = report.get_result("sys.disk")
    if disk_res is not None:
        root_free = disk_res.details.get("root_free_bytes")
        if isinstance(root_free, int) and not isinstance(root_free, bool) and root_free >= 0:
            metrics.append(f"/ {_format_bytes(root_free)} free")

    cache_res = report.get_result("sys.cache")
    if cache_res is not None:
        total_bytes = cache_res.details.get("total_bytes")
        if isinstance(total_bytes, int) and not isinstance(total_bytes, bool) and total_bytes >= 0:
            metrics.append(f"cache {_format_bytes(total_bytes)}")

    journal_res = report.get_result("sys.journal")
    if journal_res is not None:
        disk_usage = journal_res.details.get("disk_usage")
        if isinstance(disk_usage, str) and disk_usage.strip():
            metrics.append(f"journal {disk_usage.strip()}")

    return metrics


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return int(value) if value > 0 else 0


def format_upgrade_preview(
    report: ScanReport,
    extra_reboot_packages: Sequence[str] = (),
) -> str | None:
    """Summarize pending updates and likely reboot trigger packages before upgrade."""
    counts_by_id: dict[str, int] = {}
    critical_packages: set[str] = set()
    normalized_extra = [pkg.strip().lower() for pkg in extra_reboot_packages if pkg.strip()]

    for result in report.results:
        if result.severity != Severity.OUTD:
            continue
        cid = normalize_check_id(result.check_id)
        details = result.details or {}

        if cid == "sys.aur":
            updates = _non_negative_int(details.get("updates", 0))
            flagged = _non_negative_int(details.get("flagged", 0))
            pkgs = details.get("packages")
            if updates > 0 or flagged > 0:
                count = updates + flagged
            elif isinstance(pkgs, list):
                count = len(pkgs)
            else:
                count = 0
        else:
            count = _non_negative_int(details.get("updates", 0))

        if count > 0:
            counts_by_id[cid] = counts_by_id.get(cid, 0) + count

        if cid in {"sys.packages", "sys.aur"}:
            pkgs = details.get("packages")
            if isinstance(pkgs, list):
                for entry in pkgs:
                    if not isinstance(entry, str):
                        continue
                    tokens = entry.strip().split(maxsplit=1)
                    if not tokens:
                        continue
                    pkg_name = tokens[0]
                    if is_critical_reboot_package(pkg_name, extra_packages=normalized_extra):
                        critical_packages.add(pkg_name)

    ordered_labels = (
        ("sys.packages", "official"),
        ("sys.aur", "AUR"),
        ("sys.flatpak", "Flatpak"),
        ("sys.firmware", "firmware"),
        ("sys.shell-omz", "Oh-My-Zsh"),
    )
    breakdown = [
        f"{counts_by_id[cid]} {label}"
        for cid, label in ordered_labels
        if counts_by_id.get(cid, 0) > 0
    ]
    total = sum(counts_by_id.values())
    if total == 0:
        return None

    noun = "update" if total == 1 else "updates"
    preview = f"{total} {noun} ready ({', '.join(breakdown)})"

    if critical_packages:
        sorted_critical = sorted(critical_packages)
        if len(sorted_critical) > 3:
            crit_text = f"{', '.join(sorted_critical[:3])}, +{len(sorted_critical) - 3} more"
        else:
            crit_text = ", ".join(sorted_critical)
        preview = f"{preview} · reboot likely ({crit_text})"

    return preview


def format_summary(
    summary: dict[str, int],
    is_final: bool = True,
    all_passed: bool = False,
    total_target: int | None = None,
    duration_seconds: float | None = None,
    verbose: bool = False,
    **kwargs: Any,
) -> Text:
    pass_count = summary.get("PASS", 0)
    outd_count = summary.get("OUTD", 0)
    warn_count = summary.get("WARN", 0)
    fail_count = summary.get("FAIL", 0)
    skip_count = summary.get("SKIP", 0)
    total = pass_count + outd_count + warn_count + fail_count + skip_count
    dur = _format_duration(duration_seconds)

    if (all_passed and not skip_count) or (is_final and total > 0 and pass_count == total):
        ref_total = (
            total_target if total_target is not None else (total if total > 0 else pass_count)
        )
        noun = "check" if ref_total == 1 else "checks"
        summary_text = Text(f"All {pass_count} {noun} passed")
        if dur is not None:
            summary_text.append(f" in {dur}", style=STYLE_MUTED)
        return summary_text

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
    if skip_count > 0:
        skip_label = (
            f"{skip_count} skipped (use -v for details)"
            if is_final and not verbose
            else f"{skip_count} skipped"
        )
        parts.append((skip_label, "dim"))

    if not parts:
        summary_text = Text("0 checks passed")
        if dur is not None:
            summary_text.append(f" in {dur}", style=STYLE_MUTED)
        return summary_text

    summary_text = Text()
    for i, (txt, style) in enumerate(parts):
        if i > 0:
            summary_text.append(" · ")
        summary_text.append(txt, style=style)
    if dur is not None:
        summary_text.append(f" in {dur}", style=STYLE_MUTED)
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
    show_all: bool = True,
    duration_seconds: float | None = None,
    check_timings: dict[str, float] | None = None,
    **kwargs: Any,
) -> None:
    if print_header:
        console.print(format_header(report.profile))
        console.print()

    if not report.results:
        console.print(
            format_summary(report.summary, duration_seconds=duration_seconds, verbose=verbose)
        )
        return

    visible_results = (
        report.results if show_all else [r for r in report.results if r.severity != Severity.PASS]
    )

    console_width = console.width if console and console.width else 80

    if not visible_results:
        pass_count = report.summary.get("PASS", 0)
        noun = "check" if pass_count == 1 else "checks"
        dur = _format_duration(duration_seconds)
        for status_line in format_status_line(
            STATUS_PASS,
            f"All {pass_count} {noun} passed",
            detail=f"in {dur}" if dur is not None else None,
            detail_style=STYLE_MUTED,
            width=console_width,
        ):
            console.print(status_line)

        metrics = _extract_clean_metrics(report)
        if metrics:
            avail = max(15, console_width - PREFIX_LEN)
            for seg in _wrap_text(" · ".join(metrics), avail):
                metric_line = Text(" " * PREFIX_LEN)
                metric_line.append(seg, style=STYLE_MUTED)
                console.print(metric_line)
        return

    max_status_len = max((len(_status_label(r.severity)) for r in visible_results), default=4)
    max_id_len = max((len(r.check_id) for r in visible_results), default=0)

    prefix_len = 2 + max_status_len + 2 + max_id_len + 2
    indent_spaces = " " * prefix_len

    msg_width = max(15, console_width - prefix_len)

    for result in visible_results:
        label = _status_label(result.severity)
        st_style = _status_style(result.severity)
        id_str = result.check_id.ljust(max_id_len)
        msg_style = "dim" if result.severity in {Severity.PASS, Severity.SKIP} else None

        msg_lines = _wrap_text(result.message, msg_width)
        timing_suffix: str | None = None
        if verbose and check_timings:
            dur_val = check_timings.get(result.check_id)
            if dur_val is None:
                dur_val = check_timings.get(normalize_check_id(result.check_id))
            if dur_val is not None:
                timing_suffix = f" ({format_duration_ms(dur_val)})"

        line1 = Text("  ")
        line1.append(label.ljust(max_status_len), style=st_style)
        line1.append("  ")
        line1.append(id_str)
        line1.append("  ")
        line1.append(msg_lines[0], style=msg_style)
        if (
            timing_suffix
            and len(msg_lines) == 1
            and len(msg_lines[0]) + len(timing_suffix) <= msg_width
        ):
            line1.append(timing_suffix, style=STYLE_MUTED)
            timing_suffix = None
        console.print(line1)

        for idx, extra_line in enumerate(msg_lines[1:]):
            cont_line = Text(indent_spaces)
            cont_line.append(extra_line, style=msg_style)
            if (
                timing_suffix
                and idx == len(msg_lines) - 2
                and len(extra_line) + len(timing_suffix) <= msg_width
            ):
                cont_line.append(timing_suffix, style=STYLE_MUTED)
                timing_suffix = None
            console.print(cont_line)

        if timing_suffix:
            timing_line = Text(indent_spaces)
            timing_line.append(timing_suffix.lstrip(), style=STYLE_MUTED)
            console.print(timing_line)

        packages = (
            result.details.get("items") or result.details.get("packages")
            if result.details
            else None
        )
        item_noun = "item" if result.details.get("items") else "package"
        if (
            packages
            and isinstance(packages, list)
            and (result.severity not in {Severity.PASS, Severity.SKIP} or verbose)
        ):
            to_show = packages if verbose else packages[:3]

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

        if result.remediation and (
            result.severity not in {Severity.PASS, Severity.SKIP}
            or (result.severity == Severity.SKIP and verbose)
        ):
            label = "check" if result.severity == Severity.SKIP else "fix"
            fix_text = f"{label}: {result.remediation}"
            fix_lines = _wrap_text(fix_text, msg_width)
            for fix_line in fix_lines:
                f_line = Text(indent_spaces)
                f_line.append(fix_line, style="dim")
                console.print(f_line)

    console.print()
    console.print(
        format_summary(report.summary, duration_seconds=duration_seconds, verbose=verbose)
    )
