"""Parsing utilities for package updates, step detection and error patterns."""

import re

_NETWORK_FAILURE_PATTERNS: frozenset[str] = frozenset(
    {
        "failed to retrieve",
        "failed to synchronize",
        "couldn't connect to server",
        "connection timed out",
        "download library error",
        "error: failed to update",
        "failed to download",
        "curl error",
        "resolving timed out",
        "failed to get",
        "could not connect",
    }
)

_AUR_FLAGGED_RE = re.compile(
    r"\[(?:out[- ]of[- ]date|flagged[- ]out[- ]of[- ]date)\b",
    re.IGNORECASE,
)


def parse_package_update_line(line: str) -> tuple[str, str, str] | None:
    """Parse 'pkgname old_version -> new_version' from package managers."""
    parts = line.split()
    if len(parts) >= 4 and parts[2] in {"->", "→"}:
        return parts[0], parts[1], parts[3]
    if len(parts) == 3 and parts[0] not in {"->", "→"}:
        return parts[0], parts[1], parts[2]
    return None


def _is_mirror_failure(output: str) -> bool:
    lowered = output.lower()
    return any(pattern in lowered for pattern in _NETWORK_FAILURE_PATTERNS)


def _detect_step_updates(command: list[str], stdout: str, stderr: str) -> bool:
    """Detect whether a maintenance step actually applied updates or changes."""
    cmd_str = " ".join(command).lower()
    combined = f"{stdout}\n{stderr}".lower()

    if any(helper in cmd_str for helper in ("yay", "paru", "pacman")) and any(
        arg in cmd_str for arg in ("-syu", "-u")
    ):
        if "there is nothing to do" in combined or "nothing to do" in combined:
            return False
        if any(
            marker in combined
            for marker in ("total installed size", "upgraded", "packages (", "installing")
        ):
            return True
        return "there is nothing to do" not in combined and len(stdout.strip()) > 0

    if "flatpak" in cmd_str and "update" in cmd_str:
        if any(
            marker in combined
            for marker in ("nothing to do", "nothing to update", "nothing to install")
        ):
            return False
        if any(marker in combined for marker in ("updating", "installing", "changes:")):
            return True

    if "flatpak" in cmd_str and "unused" in cmd_str:
        if "nothing unused to uninstall" in combined:
            return False
        return "uninstalling" in combined

    if "paccache" in cmd_str:
        if "no candidate packages" in combined or "0 packages removed" in combined:
            return False
        match = re.search(r"(\d+)\s+packages removed", combined)
        return bool(match and int(match.group(1)) > 0)

    if "upgrade.sh" in cmd_str:
        if "already at the latest version" in combined:
            return False
        return "updating oh my zsh" in combined or "upgraded" in combined

    if "fwupdmgr" in cmd_str and "update" in cmd_str:
        no_update_markers = (
            "no updates available",
            "devices with no available firmware updates",
            "no updatable devices",
            "nothing to do",
            "devices with the latest available firmware version",
        )
        if any(marker in combined for marker in no_update_markers) and not any(
            marker in combined for marker in ("successfully installed", "updating")
        ):
            return False
        return "successfully installed" in combined or "updating" in combined

    return False


def _parse_fwupdmgr_updates(output: str) -> int:
    """Count firmware updates only when there are explicit update indicators."""
    lines = [line.rstrip() for line in output.splitlines()]
    normalized = "\n".join(line.lower() for line in lines)

    no_update_markers = (
        "no updates available",
        "no updatable devices",
        "devices with the latest available firmware version",
        "devices with no available firmware updates",
    )
    if any(marker in normalized for marker in no_update_markers):
        pass

    version_transition_pattern = re.compile(r"\b\d[\w.-]*\s*(?:->|→)\s*\d[\w.-]*\b")
    explicit_update_pattern = re.compile(
        r"\b(update available for|updates available for|upgrade available for)\b",
    )

    updates = 0
    in_no_update_section = False
    for raw_line in lines:
        line = raw_line.strip()
        lowered = line.lower()
        if not line:
            in_no_update_section = False
            continue

        if lowered.startswith("devices with the latest available firmware version"):
            in_no_update_section = True
            continue

        if lowered.startswith("devices with no available firmware updates"):
            in_no_update_section = True
            continue

        if in_no_update_section:
            continue

        if version_transition_pattern.search(line):
            updates += 1
            continue

        if explicit_update_pattern.search(lowered):
            updates += 1

    return updates


__all__ = [
    "_AUR_FLAGGED_RE",
    "_NETWORK_FAILURE_PATTERNS",
    "_detect_step_updates",
    "_is_mirror_failure",
    "_parse_fwupdmgr_updates",
    "parse_package_update_line",
]
