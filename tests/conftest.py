"""Keep legacy command-mocking suites independent of host network and new checks.

Maintenance integration is exercised separately in test_maintenance and
test_maintenance_flows, with explicit command readers and pre/post-flight fixtures.
"""

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from dotdoctor.application.maintenance import MaintenanceChecks
from dotdoctor.application.system_update import SystemDryRunService, SystemUpgradeService
from dotdoctor.infrastructure.audit_processes import AuditSession

_REAL_RUN = subprocess.run


@pytest.fixture(autouse=True)
def isolate_legacy_system_tests(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    if request.path.name not in {"test_system_update.py", "test_cli.py"}:
        return
    monkeypatch.setattr(MaintenanceChecks, "registrations", lambda self, context: [])

    def mocked_capture(self, command, timeout, input_str=None, env=None):
        assert subprocess.run is not _REAL_RUN, "Legacy command tests must mock subprocess.run"
        return subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=timeout, input=input_str
        )

    monkeypatch.setattr(AuditSession, "capture", mocked_capture)

    def offline_independent(original: Callable[..., None]) -> Callable[..., None]:
        def initialize(self: Any, *args: Any, **kwargs: Any) -> None:
            if not args:
                kwargs.setdefault("is_online_fn", lambda: True)
            original(self, *args, **kwargs)

        return initialize

    for cls in (SystemDryRunService, SystemUpgradeService):
        monkeypatch.setattr(cls, "__init__", offline_independent(cls.__init__))
