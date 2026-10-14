"""HTTPS connectivity tests use mocked readers, never remote requests."""

import subprocess
import threading
import time
import urllib.error
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from dotdoctor.application import system_update as updates
from dotdoctor.infrastructure import network_worker as network


def test_https_reachability_uses_head_and_never_probes_dns_ports(monkeypatch):
    calls = []
    ready = threading.Barrier(len(network.HTTPS_TARGETS))

    def open_url(request, timeout):
        calls.append((request.full_url, request.get_method(), timeout))
        ready.wait(0.5)
        return nullcontext(SimpleNamespace(geturl=lambda: request.full_url))

    def forbidden(*args, **kwargs):
        raise AssertionError("Connectivity must not depend on public DNS ports")

    monkeypatch.setattr(network.urllib.request, "urlopen", open_url)
    monkeypatch.setattr("socket.create_connection", forbidden)
    assert network.probe(network.HTTPS_TARGETS, 0.5)
    assert calls
    assert all(url.startswith("https://") and method == "HEAD" for url, method, _ in calls)


@pytest.mark.parametrize("status", [403, 405, 503])
def test_https_application_errors_still_establish_connectivity(monkeypatch, status):
    error = urllib.error.HTTPError("https://archlinux.org/", status, "error", None, None)
    closed = []
    monkeypatch.setattr(error, "close", lambda: closed.append(True))

    def open_url(*args, **kwargs):
        raise error

    monkeypatch.setattr(network.urllib.request, "urlopen", open_url)
    assert network._reachable("https://archlinux.org/", 0.5)
    assert closed == [True]


def test_http_redirect_does_not_establish_https_connectivity(monkeypatch):
    monkeypatch.setattr(
        network.urllib.request,
        "urlopen",
        lambda *a, **kw: nullcontext(SimpleNamespace(geturl=lambda: "http://login.local/")),
    )
    assert not network._reachable("https://archlinux.org/", 0.5)


def test_reachable_site_returns_without_waiting_for_stalled_sites(monkeypatch):
    release = threading.Event()
    stalled = [threading.Event(), threading.Event()]

    def reachable(url, timeout):
        if url == "https://working/":
            assert all(started.wait(0.5) for started in stalled)
            return True
        stalled[int(url[-2])].set()
        release.wait(1)
        return False

    monkeypatch.setattr(network, "_reachable", reachable)
    started = time.monotonic()
    try:
        assert network.probe(("https://stalled0/", "https://stalled1/", "https://working/"), 0.5)
        assert time.monotonic() - started < 0.5
    finally:
        release.set()


def test_dns_stall_is_bounded_by_shared_deadline(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(network, "_reachable", lambda *args: release.wait(1))
    started = time.monotonic()
    try:
        assert not network.probe(network.HTTPS_TARGETS, 0.05)
        assert time.monotonic() - started < 0.5
    finally:
        release.set()


def test_all_sites_unreachable(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(network.urllib.request, "urlopen", unavailable)
    assert not network.probe(network.HTTPS_TARGETS, 0.5)


@pytest.mark.parametrize(
    ("payload", "code"), [("false", 0), ("true", 1), ("broken", 0), ("1", 0), ('"true"', 0)]
)
def test_probe_failure_or_invalid_output_is_never_online(monkeypatch, payload, code):
    monkeypatch.setattr(
        updates,
        "capture_command",
        lambda *a, **kw: SimpleNamespace(returncode=code, stdout=payload),
    )
    assert not updates.is_online()


def test_worker_timeout_is_global_and_cancellation_is_not_swallowed(monkeypatch):
    from dotdoctor.infrastructure.audit_processes import AuditCancelled

    calls = []

    def capture(command, timeout):
        calls.append((command, timeout))
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(updates, "capture_command", capture)
    assert not updates.is_online(timeout=0.5)
    assert calls[0][1] == 1.5
    assert calls[0][0][1:3] == ["-m", "dotdoctor.infrastructure.network_worker"]

    def cancelled(*args, **kwargs):
        raise AuditCancelled()

    monkeypatch.setattr(updates, "capture_command", cancelled)
    with pytest.raises(AuditCancelled):
        updates.is_online()
