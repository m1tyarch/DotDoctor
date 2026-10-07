"""Central design system and UI palette for DotDoctor."""

from __future__ import annotations

import textwrap

from rich.text import Text

# Status Labels (4 uppercase letters)
STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_OLD = "OLD"
STATUS_DONE = "DONE"
STATUS_SKIP = "SKIP"

# Palette:
# - PASS / DONE: dim green
# - WARN: yellow
# - FAIL: bold red
# - OLD: cyan
# - SKIP, explanations in parens, auxiliary: dim
# - regular text: default
STYLE_PASS = "dim green"
STYLE_DONE = "dim green"
STYLE_WARN = "yellow"
STYLE_FAIL = "bold red"
STYLE_OLD = "cyan"
STYLE_SKIP = "dim"
STYLE_MUTED = "dim"
STYLE_DEFAULT = "default"

STATUS_STYLES: dict[str, str] = {
    STATUS_PASS: STYLE_PASS,
    STATUS_DONE: STYLE_DONE,
    STATUS_WARN: STYLE_WARN,
    STATUS_FAIL: STYLE_FAIL,
    STATUS_OLD: STYLE_OLD,
    STATUS_SKIP: STYLE_SKIP,
}

INDENT = "  "
GAP = "  "
STATUS_WIDTH = 4
PREFIX_LEN = len(INDENT) + STATUS_WIDTH + len(GAP)  # 2 + 4 + 2 = 8


def format_header(profile_or_mode: str) -> Text:
    """Format unified header: 'DotDoctor · <profile_or_mode>' (second part dim)."""
    header = Text("DotDoctor · ")
    header.append(profile_or_mode, style=STYLE_MUTED)
    return header


def format_status_line(
    status: str,
    title: str,
    detail: str | None = None,
    detail_style: str = STYLE_MUTED,
    width: int | None = None,
) -> list[Text]:
    """Format unified line with hanging indent under column 8 if wrapped."""
    status_style = STATUS_STYLES.get(status, STYLE_DEFAULT)
    detail_suffix = f" {detail}" if detail else ""
    full_text = f"{title}{detail_suffix}"

    if width is None:
        line = Text(INDENT)
        line.append(status.ljust(STATUS_WIDTH), style=status_style)
        line.append(GAP)
        line.append(title)
        if detail:
            line.append(f" {detail}", style=detail_style)
        return [line]

    avail = max(15, width - PREFIX_LEN)
    wrapped = textwrap.wrap(full_text, width=avail) or [full_text]

    lines: list[Text] = []
    for idx, seg in enumerate(wrapped):
        line = Text(INDENT if idx == 0 else " " * PREFIX_LEN)
        if idx == 0:
            line.append(status.ljust(STATUS_WIDTH), style=status_style)
            line.append(GAP)
        if detail and detail in seg:
            t_part, d_part = seg.split(detail, 1)
            line.append(t_part)
            line.append(detail, style=detail_style)
            line.append(d_part)
        else:
            line.append(seg)
        lines.append(line)
    return lines


def format_sysup_summary(done: int, failed: int = 0, skipped: int = 0) -> Text:
    """Format sysup summary in scan format with non-zero counters only.

    Successful counters are uncolored, and failed count is styled bold red.
    """
    parts: list[tuple[str, str | None]] = []
    if done > 0:
        parts.append((f"{done} done", None))
    if failed > 0:
        parts.append((f"{failed} failed", STYLE_FAIL))
    if skipped > 0:
        parts.append((f"{skipped} skipped", None))
    if not parts:
        return Text("0 steps done")

    summary_text = Text()
    for i, (txt, style) in enumerate(parts):
        if i > 0:
            summary_text.append(" · ")
        summary_text.append(txt, style=style)
    return summary_text
