"""Live results must appear before slower checks finish, without changing row order."""

import io
import threading

import pytest
from rich.console import Console

from dotdoctor.application.system_update import SystemCheckTask, SystemDryRunService
from dotdoctor.cli.app import _run_tasks_with_progress
from dotdoctor.cli.render import format_check_status
from dotdoctor.domain.context import ScanContext
from dotdoctor.domain.models import CheckResult, Severity


@pytest.fixture
def context(tmp_path):
    return ScanContext("system", tmp_path, tmp_path, "/bin", "/bin/bash")


@pytest.mark.parametrize("width", [40, 80])
@pytest.mark.parametrize(
    "outcome,status",
    [
        (Severity.PASS, "PASS"),
        (Severity.OUTD, "OLD"),
        (Severity.WARN, "WARN"),
        (Severity.FAIL, "FAIL"),
        (OSError("reader unavailable"), "WARN"),
        (None, "SKIP"),
    ],
)
def test_live_result_arrives_while_another_check_is_pending(
    monkeypatch, context, outcome, status, width
):
    monkeypatch.setenv("TERM", "xterm-256color")
    for name in ("NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)
    release_slow = threading.Event()
    slow_finished = threading.Event()
    snapshots = []

    def snapshot(grid):
        output = io.StringIO()
        Console(file=output, width=width, color_system=None).print(grid)
        rows = output.getvalue().splitlines()
        assert len(rows) == 2
        assert "sys.slow" in rows[0]
        assert "sys.fast" in rows[1]
        snapshots.append(rows)
        return rows

    class Live:
        def __init__(self, grid, **kwargs):
            assert kwargs["transient"] is True
            snapshot(grid)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            release_slow.set()

        def update(self, grid, *, refresh):
            assert refresh is True
            rows = snapshot(grid)
            if not release_slow.is_set():
                assert not slow_finished.is_set()
                assert rows[1].startswith(f"  {status:<4}  sys.fast  ")
                assert "DONE" not in rows[1]
                if isinstance(outcome, Severity):
                    assert "finding" in rows[1]
                elif isinstance(outcome, OSError):
                    assert "check could" in rows[1]
                else:
                    assert "no result" in rows[1]
                release_slow.set()

    monkeypatch.setattr("dotdoctor.cli.app.Live", Live)

    def slow():
        assert release_slow.wait(2), "No live result before the slow check finished"
        slow_finished.set()
        return CheckResult(check_id="sys.slow", severity=Severity.PASS, message="ok")

    def fast():
        if isinstance(outcome, OSError):
            raise outcome
        if outcome is None:
            return None
        return CheckResult(
            check_id="sys.fast",
            severity=outcome,
            message="finding [red]literal[/red]\n" + "long details " * 20,
        )

    tasks = [
        SystemCheckTask("sys.slow", "Slow check", slow),
        SystemCheckTask("sys.fast", "Fast check", fast),
    ]
    report = _run_tasks_with_progress(
        SystemDryRunService(),
        context,
        tasks,
        [],
        None,
        Console(file=io.StringIO(), width=width, force_terminal=True),
    )
    assert len(snapshots) == 3
    assert snapshots[-1][0].startswith("  PASS  sys.slow  ok")
    assert [result.check_id for result in report.results] == (
        ["sys.slow"] if outcome is None else ["sys.slow", "sys.fast"]
    )
    if isinstance(outcome, Severity) and width == 80:
        assert "[red]literal[/red]" in snapshots[1][1]
        assert "…" in snapshots[1][1]


@pytest.mark.parametrize(
    "severity,label,style",
    [
        (Severity.PASS, "PASS", "dim green"),
        (Severity.OUTD, "OLD", "cyan"),
        (Severity.WARN, "WARN", "yellow"),
        (Severity.FAIL, "FAIL", "bold red"),
    ],
)
def test_live_status_uses_the_report_palette(severity, label, style):
    status = format_check_status(CheckResult(check_id="test", severity=severity, message="ok"))
    assert status.plain == label
    assert status.style == style


def test_result_callback_keeps_the_completion_callback_compatible(context):
    result = CheckResult(check_id="test", severity=Severity.FAIL, message="problem")
    complete = []
    findings = []
    report = SystemDryRunService().run_with_progress(
        context,
        tasks=[SystemCheckTask("test", "Test", lambda: result)],
        on_task_complete=complete.append,
        on_task_result=lambda cid, finding: findings.append((cid, finding)),
    )
    assert complete == ["test"]
    assert findings == [("test", result)]
    assert report.results == [result]


@pytest.mark.parametrize("setting", ["pipe", "NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR"])
def test_nonanimated_output_never_starts_a_live_display(monkeypatch, context, setting):
    monkeypatch.setenv("TERM", "xterm-256color")
    for name in ("NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)
    if setting != "pipe":
        monkeypatch.setenv(setting, "1")

    def forbidden(*args, **kwargs):
        raise AssertionError("Animations are disabled")

    monkeypatch.setattr("dotdoctor.cli.app.Live", forbidden)
    result = CheckResult(check_id="test", severity=Severity.WARN, message="finding")
    report = _run_tasks_with_progress(
        SystemDryRunService(),
        context,
        [SystemCheckTask("test", "Test", lambda: result)],
        [],
        None,
        Console(file=io.StringIO(), force_terminal=setting != "pipe"),
    )
    assert report.results == [result]


@pytest.mark.parametrize("cancel", [False, True])
def test_real_live_display_restores_cursor_after_completion_or_cancellation(
    monkeypatch, context, cancel
):
    monkeypatch.setenv("TERM", "xterm-256color")
    for name in ("NO_ANIMATION", "DOTDOCTOR_NO_ANIMATION", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)
    output = io.StringIO()

    def check():
        if cancel:
            raise KeyboardInterrupt
        return CheckResult(check_id="test", severity=Severity.WARN, message="finding")

    def run():
        return _run_tasks_with_progress(
            SystemDryRunService(),
            context,
            [SystemCheckTask("test", "Test", check)],
            [],
            None,
            Console(file=output, force_terminal=True),
        )

    if cancel:
        with pytest.raises(KeyboardInterrupt):
            run()
    else:
        assert run().results[0].severity == Severity.WARN
        assert "WARN" in output.getvalue()
        assert "finding" in output.getvalue()
    rendered = output.getvalue()
    assert "\x1b[?25l" in rendered
    assert "\x1b[?25h" in rendered
    assert "\x1b[?1049h" not in rendered
