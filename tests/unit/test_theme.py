"""Tests for DotDoctor central UI theme, palette, and unified layout."""

import io

from rich.console import Console

from dotdoctor.cli.theme import (
    GAP,
    INDENT,
    PREFIX_LEN,
    STATUS_DONE,
    STATUS_FAIL,
    STATUS_OLD,
    STATUS_PASS,
    STATUS_SKIP,
    STATUS_STYLES,
    STATUS_WARN,
    STATUS_WIDTH,
    STYLE_FAIL,
    STYLE_MUTED,
    STYLE_OLD,
    emit_osc_progress,
    format_duration_ms,
    format_header,
    format_relative_age,
    format_status_line,
    format_sysup_summary,
    supports_osc_progress,
)


def test_format_header() -> None:
    header = format_header("system update")
    assert header.plain == "DotDoctor · system update"
    # Second part must be dim
    assert any(span.style == "dim" for span in header.spans)
    # No italics
    assert not any(getattr(span.style, "italic", False) for span in header.spans)
    # No exclamation mark or ellipsis
    assert "!" not in header.plain and "..." not in header.plain


def test_format_header_with_detail() -> None:
    header = format_header("system", detail="last update 3d ago")
    assert header.plain == "DotDoctor · system · last update 3d ago"
    spans = {header.plain[s.start : s.end]: s.style for s in header.spans}
    assert spans.get("system") == STYLE_MUTED
    assert spans.get(" · last update 3d ago") == STYLE_MUTED

    header_none = format_header("system", detail=None)
    assert header_none.plain == "DotDoctor · system"


def test_format_relative_age() -> None:
    now = 1_700_000_000.0
    assert format_relative_age(now, now=now) == "just now"
    assert format_relative_age(now - 59, now=now) == "just now"
    assert format_relative_age(now + 30, now=now) == "just now"
    assert format_relative_age(now + 61, now=now) is None
    assert format_relative_age(-1.0, now=now) is None
    assert format_relative_age(float("nan"), now=now) is None
    assert format_relative_age(now - 60, now=now) == "1m ago"
    assert format_relative_age(now - 3599, now=now) == "59m ago"
    assert format_relative_age(now - 3600, now=now) == "1h ago"
    assert format_relative_age(now - 86399, now=now) == "23h ago"
    assert format_relative_age(now - 86400, now=now) == "1d ago"
    assert format_relative_age(now - 3 * 86400, now=now) == "3d ago"


def test_cyan_only_in_old_status() -> None:
    """Cyan must only be used for STATUS_OLD and nowhere else in theme palette."""
    assert STATUS_STYLES[STATUS_OLD] == STYLE_OLD == "cyan"
    for status, style in STATUS_STYLES.items():
        if "cyan" in style:
            assert status == STATUS_OLD, f"Status {status} unexpectedly has cyan style {style}"

    # Check format_status_line for non-OLD statuses does not include cyan
    for status in [STATUS_PASS, STATUS_DONE, STATUS_WARN, STATUS_FAIL, STATUS_SKIP]:
        lines = format_status_line(status, "Some check label", detail="(info)")
        for line in lines:
            for span in line.spans:
                style_str = str(span.style)
                assert "cyan" not in style_str


def test_layout_hanging_indent_at_80_and_60_cols() -> None:
    """Longest labels must wrap cleanly with hanging indent under column 8 without collision."""
    longest_labels = [
        ("Journal disk usage", "(archived and active journals take up 6.2G)"),
        ("Pacman cache cleanup (uninstalled packages)", "(paccache -ruk0)"),
        ("Pacman cache cleanup (keep 2 versions)", "(clean 2.4 GiB)"),
        (
            "Very long custom task label that stretches significantly across multiple rows",
            "(detail in parens)",
        ),
    ]

    for width in (80, 60):
        for title, detail in longest_labels:
            lines = format_status_line(
                STATUS_DONE,
                title,
                detail=detail,
                width=width,
            )
            assert len(lines) >= 1

            # Line 1 format: 2 spaces, 4-char status, 2 spaces, then text
            first_plain = lines[0].plain
            assert first_plain.startswith(f"{INDENT}{STATUS_DONE}{GAP}")
            assert len(first_plain) <= width, f"Line exceeded width {width}: '{first_plain}'"

            # Subsequent lines must start with 8 spaces (hanging indent under column 8)
            for continuation in lines[1:]:
                cont_plain = continuation.plain
                assert cont_plain.startswith(" " * PREFIX_LEN)
                assert len(cont_plain) <= width, (
                    f"Continuation exceeded width {width}: '{cont_plain}'"
                )


def test_status_fixed_width_and_left_aligned() -> None:
    """Status is always 4 chars, on the left, never on the right."""
    for status in [STATUS_PASS, STATUS_WARN, STATUS_FAIL, STATUS_OLD, STATUS_DONE, STATUS_SKIP]:
        lines = format_status_line(status, "Test Step Title")
        plain = lines[0].plain
        assert plain.startswith(f"  {status.ljust(STATUS_WIDTH)}  Test Step Title")


def test_sysup_summary_success() -> None:
    # Success with skip
    text = format_sysup_summary(done=6, failed=0, skipped=2)
    assert text.plain == "6 done · 2 skipped"
    assert "!" not in text.plain and "..." not in text.plain
    # Successful counters have no color style
    for span in text.spans:
        assert span.style != STYLE_FAIL and "cyan" not in str(span.style)

    # Success without skip
    text_all = format_sysup_summary(done=8, failed=0, skipped=0)
    assert text_all.plain == "8 done"
    assert len(text_all.spans) == 0


def test_sysup_summary_with_errors() -> None:
    text = format_sysup_summary(done=5, failed=1, skipped=2)
    assert text.plain == "5 done · 1 failed · 2 skipped"
    spans = {text.plain[s.start : s.end]: s.style for s in text.spans}
    assert spans.get("1 failed") == STYLE_FAIL
    # done and skipped counters are uncolored
    assert "5 done" not in spans
    assert "2 skipped" not in spans


def test_sysup_summary_only_skipped() -> None:
    text = format_sysup_summary(done=0, failed=0, skipped=3)
    assert text.plain == "3 skipped"
    assert "done" not in text.plain
    assert "failed" not in text.plain


def test_sysup_summary_zero_steps() -> None:
    text = format_sysup_summary(done=0, failed=0, skipped=0)
    assert text.plain == "0 steps done"


def test_no_ansi_when_no_color() -> None:
    output = io.StringIO()
    console = Console(file=output, width=80, no_color=True)

    header = format_header("system update")
    console.print(header)

    lines = format_status_line(STATUS_DONE, "Pacman cache cleanup (keep 2 versions)", width=80)
    for line in lines:
        console.print(line)

    summary = format_sysup_summary(done=6, failed=1, skipped=2)
    console.print(summary)

    rendered = output.getvalue()
    assert "\x1b[" not in rendered
    assert "DotDoctor · system update" in rendered
    assert "DONE  Pacman cache cleanup (keep 2 versions)" in rendered
    assert "6 done · 1 failed · 2 skipped" in rendered


def test_format_duration_ms() -> None:
    assert format_duration_ms(0.0002) == "<1ms"
    assert format_duration_ms(0.001) == "1ms"
    assert format_duration_ms(0.245) == "245ms"
    assert format_duration_ms(0.9999) == "1.0s"
    assert format_duration_ms(1.42) == "1.4s"
    assert format_duration_ms(10.0) == "10s"
    assert format_duration_ms(-1.0) == "0ms"


def test_emit_osc_progress_respects_tty_and_suppression(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("NO_ANIMATION", raising=False)
    monkeypatch.delenv("DOTDOCTOR_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")

    tty_buf = io.StringIO()
    tty_console = Console(file=tty_buf, force_terminal=True)
    assert supports_osc_progress(tty_console) is True
    emit_osc_progress(tty_console, 50, state=1)
    emit_osc_progress(tty_console, 150, state=2)
    emit_osc_progress(tty_console, None, state=0)
    assert tty_buf.getvalue() == "\x1b]9;4;1;50\x07\x1b]9;4;2;100\x07\x1b]9;4;0\x07"

    nontty_buf = io.StringIO()
    nontty_console = Console(file=nontty_buf, force_terminal=False)
    assert supports_osc_progress(nontty_console) is False
    emit_osc_progress(nontty_console, 50, state=1)
    emit_osc_progress(nontty_console, None, state=0)
    assert nontty_buf.getvalue() == ""

    monkeypatch.setenv("NO_COLOR", "1")
    no_color_buf = io.StringIO()
    no_color_console = Console(file=no_color_buf, force_terminal=True)
    assert supports_osc_progress(no_color_console) is False
    emit_osc_progress(no_color_console, 50, state=1)
    assert no_color_buf.getvalue() == ""
