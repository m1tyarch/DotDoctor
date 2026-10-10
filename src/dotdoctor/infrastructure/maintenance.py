"""Bounded, non-interactive readers used by maintenance checks."""

import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from dotdoctor.infrastructure.audit_processes import capture as capture_command
from dotdoctor.infrastructure.audit_processes import current_session

NEWS_URL = "https://archlinux.org/feeds/news/"

# Stable systemd MESSAGE_IDs: completion, failure, skipped job and new start.
# Query all outcomes so an older success cannot hide a later unsuccessful run.
UNIT_SUCCESS = "7ad2d189f7e94e70a38c781354912448"
UNIT_FAILURES = {"d9b373ed55a64feb8242e02dbe79a49c", "be02cf6855d2428ba40df7e9d022f03d"}
UNIT_OUTCOMES = (
    UNIT_SUCCESS,
    "d9b373ed55a64feb8242e02dbe79a49c",  # UNIT_FAILURE_RESULT
    "be02cf6855d2428ba40df7e9d022f03d",  # UNIT_FAILED
    "0e4284a0caca4bfc81c0bb6786972673",  # UNIT_SKIPPED
    "7d4958e842da4a758f6c1cdc7b36dcc5",  # UNIT_STARTING
)


class ServiceJobFailed(ValueError):
    """The latest relevant manager event records a failed service job."""


def capture(command: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return capture_command(command, timeout, env={**os.environ, "LC_ALL": "C"})


def read_json(command: list[str], timeout: int = 15) -> Any:
    result = capture(command, timeout)
    if result.returncode:
        raise ValueError(result.stderr.strip() or f"command exited with {result.returncode}")
    return json.loads(result.stdout)


def properties(unit: str, scope: str = "system", timer: bool = False) -> dict[str, str]:
    names = [
        "LoadState",
        "ActiveState",
        "Result",
        "ExecMainStatus",
        "ExecMainExitTimestamp",
        "ConditionResult",
        "AssertResult",
        "ConditionTimestamp",
        "AssertTimestamp",
    ]
    if timer:
        names += ["LastTriggerUSec", "NextElapseUSecRealtime", "Triggers", "UnitFileState"]
    args = ["systemctl"] + (["--user"] if scope == "user" else [])
    result = capture([*args, "show", unit, *[f"--property={name}" for name in names]])
    if result.returncode:
        raise ValueError(result.stderr.strip() or "systemd properties unavailable")
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if values.get("LoadState") != "loaded":
        raise ValueError(f"{unit} is not loaded")
    return values


def service_completion_timestamp(unit: str, scope: str = "system") -> float | None:
    """Recover a completed execution after systemd unloads an inactive service.

    Only a manager's successful deactivation counts, never a start/trigger event.
    No sudo is requested; missing or unreadable history stays unverified.
    """
    field = "USER_UNIT" if scope == "user" else "UNIT"
    owner = f"_UID={os.getuid()}" if scope == "user" else "_PID=1"
    result = capture(
        [
            "journalctl",
            "--no-pager",
            "--output=json",
            "--lines=1",
            f"{field}={unit}",
            owner,
            "SYSLOG_IDENTIFIER=systemd",
            *[f"MESSAGE_ID={value}" for value in UNIT_OUTCOMES],
        ]
    )
    if result.returncode:
        raise ValueError("service completion journal is unavailable")
    if not result.stdout.strip():
        return None
    record = json.loads(result.stdout)
    if not isinstance(record, dict):
        raise ValueError("invalid service completion journal")
    if record.get(field) != unit or record.get("MESSAGE_ID") not in {UNIT_SUCCESS, *UNIT_FAILURES}:
        return None
    if (
        record.get("SYSLOG_IDENTIFIER") != "systemd"
        or record.get(owner.split("=")[0]) != owner.split("=")[1]
    ):
        raise ValueError("invalid service completion journal source")
    value = record.get("__REALTIME_TIMESTAMP", "")
    if not isinstance(value, str) or not value.isdigit():
        raise ValueError("invalid service completion journal timestamp")
    if record["MESSAGE_ID"] in UNIT_FAILURES:
        raise ServiceJobFailed("last recorded service job failed")
    return int(value) / 1_000_000


def fetch_news() -> list[dict[str, str]]:
    if current_session() is not None:
        result = capture([sys.executable, "-m", "dotdoctor.infrastructure.news_worker"], 15)
        if result.returncode:
            raise ValueError("Arch news could not be fetched")
        data = json.loads(result.stdout)
        if not isinstance(data, list) or not data:
            raise ValueError("invalid Arch news response")
        return data
    request = urllib.request.Request(NEWS_URL, headers={"User-Agent": "DotDoctor/0.1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = response.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise ValueError("news feed exceeds size limit")
    root = ElementTree.fromstring(payload)
    if root.tag != "rss" or root.find("channel") is None:
        raise ValueError("invalid Arch news feed")
    items = []
    for item in root.findall("./channel/item"):
        title = item.findtext("title", "").strip()
        link = item.findtext("link", "").strip()
        if title and link.startswith("https://archlinux.org/news/"):
            items.append({"title": title, "url": link})
    if not items:
        raise ValueError("news feed contains no valid items")
    return items


class MaintenanceState:
    def __init__(self, path: Path | None = None) -> None:
        base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
        self.path = path or base / "dotdoctor" / "maintenance.json"

    def read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("news", []), list):
            raise ValueError("invalid maintenance state")
        return data

    def acknowledge_news(self, urls: list[str]) -> None:
        data = self.read()
        data["news"] = list(dict.fromkeys([*data.get("news", []), *urls]))[-200:]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix=".maintenance-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream)
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
