import re
from pathlib import Path

import pytest

from dotdoctor.application.maintenance import (
    MAINTENANCE_CHECK_IDS,
    MaintenanceChecks,
)
from dotdoctor.application.system_update import (
    ALL_CHECK_IDS,
    FIX_CHECK_IDS,
    UPDATE_CHECK_IDS,
    SystemDryRunService,
)
from dotdoctor.domain.config import DotDoctorConfig
from dotdoctor.domain.context import ScanContext


def test_example_config_check_ids_match_registry() -> None:
    example_path = Path(__file__).resolve().parents[2] / "dotdoctor.example.yml"
    assert example_path.is_file(), f"Cannot find {example_path}"

    content = example_path.read_text(encoding="utf-8")
    parsed_ids = set(re.findall(r"^#\s+(sys\.[a-z0-9\-]+)\s+-", content, flags=re.MULTILINE))

    assert parsed_ids == set(ALL_CHECK_IDS)
    assert len(ALL_CHECK_IDS) == 26


def test_all_check_ids_is_derived_from_actual_mode_registries() -> None:
    expected = frozenset(UPDATE_CHECK_IDS | FIX_CHECK_IDS | {"sys.network"})
    assert expected == ALL_CHECK_IDS
    assert MAINTENANCE_CHECK_IDS.issubset(ALL_CHECK_IDS)


def test_unregistered_check_id_raises_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = ScanContext(
        profile="system",
        cwd=tmp_path,
        home=tmp_path,
        path_value="/bin",
        shell="/bin/bash",
    )
    service = SystemDryRunService(config=DotDoctorConfig())
    monkeypatch.setattr(
        "dotdoctor.application.system_update.MaintenanceChecks.registrations",
        lambda self, ctx: [("sys.fake-unregistered", "Fake", lambda: None)],
    )
    with pytest.raises(ValueError, match="Unregistered check_id"):
        service.build_tasks(context)


def test_maintenance_registrations_validates_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = ScanContext(
        profile="system",
        cwd=tmp_path,
        home=tmp_path,
        path_value="/bin",
        shell="/bin/bash",
    )
    checks = MaintenanceChecks()
    monkeypatch.setattr(
        "dotdoctor.application.maintenance.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    registered_ids = {cid for cid, _, _ in checks.registrations(context)}
    assert registered_ids.issubset(ALL_CHECK_IDS)
