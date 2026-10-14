"""Exercise the isolated worker with fake HTTPS readers and harmless processes."""

import json
import subprocess
import sys
import time

import pytest

from dotdoctor.application import system_update as updates
from dotdoctor.infrastructure import audit_processes as processes


@pytest.mark.parametrize("reachable", [True, False])
def test_worker_entrypoint_reports_mocked_https_result(reachable):
    script = """
import runpy
import sys
import urllib.request
from contextlib import nullcontext
from types import SimpleNamespace
reachable = sys.argv[1]
def fake_open(request, timeout):
    assert request.get_method() == 'HEAD'
    assert request.full_url.startswith('https://')
    if reachable != 'True':
        raise OSError('network unreachable')
    return nullcontext(SimpleNamespace(geturl=lambda: request.full_url))
urllib.request.urlopen = fake_open
sys.argv = ['network_worker', '["https://archlinux.org/", "https://aur.archlinux.org/"]', '0.5']
runpy.run_module('dotdoctor.infrastructure.network_worker', run_name='__main__')
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(reachable)],
        capture_output=True,
        text=True,
        check=True,
        timeout=3,
    )
    assert json.loads(result.stdout) is reachable
    assert result.stderr == ""


def test_parent_deadline_kills_stalled_worker(monkeypatch):
    def capture(command, timeout):
        assert command[1:3] == ["-m", "dotdoctor.infrastructure.network_worker"]
        return processes.capture([sys.executable, "-c", "import time; time.sleep(30)"], timeout)

    monkeypatch.setattr(updates, "capture_command", capture)
    started = time.monotonic()
    assert not updates.is_online(timeout=0.05)
    assert time.monotonic() - started < 3
