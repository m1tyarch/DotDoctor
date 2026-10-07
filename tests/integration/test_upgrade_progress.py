"""Upgrade progress uses mocked processes; no package transactions are started."""

import io
from types import SimpleNamespace

import pytest
from rich.console import Console

from dotdoctor.application import system_update as s


@pytest.mark.parametrize("output", ["", "Retrieving packages...\n"])
def test_upgrade_spinner_advances_even_without_new_command_output(monkeypatch, output):
    now = [0.0]
    frames = []
    polls = []

    def poll():
        polls.append(True)
        return 0 if len(polls) > 6 else None

    process = SimpleNamespace(
        stdout=io.StringIO(output), stderr=io.StringIO(""), poll=poll, returncode=0
    )
    monkeypatch.setattr(s.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(s.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))

    def capture_frame(grid):
        # Render the actual status cell at each simulated refresh time. Recreating
        # a Spinner resets its start time and would produce only the first frame.
        status = grid.columns[1]._cells[0]
        frames.append(status.render(now[0]).plain)

    class Live:
        def __init__(self, grid, **kwargs):
            assert kwargs["transient"] is True
            capture_frame(grid)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def update(self, grid):
            capture_frame(grid)

    monkeypatch.setattr(s, "Live", Live)
    result = s.SystemUpgradeService()._run_streaming_step(
        ["mock-upgrade"], Console(file=io.StringIO()), "Update", 80
    )
    assert len(frames) == 7
    assert len(set(frames)) >= 3
    assert frames[2] != frames[0]
    assert result.returncode == 0
    assert result.stdout == output
