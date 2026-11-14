"""Tests for packaging, versioning, and distribution integrity."""

import os
import re
import subprocess
import sys
from pathlib import Path

from dotdoctor import __version__


def test_main_module_execution() -> None:
    """Verify that python -m dotdoctor executes successfully."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    src_dir = repo_root / "src"

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{src_dir}{os.pathsep}{env.get('PYTHONPATH', '')}"

    result = subprocess.run(
        [sys.executable, "-m", "dotdoctor", "--version"],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert result.returncode == 0
    assert f"dotdoctor {__version__}" in result.stdout


def test_pyproject_metadata() -> None:
    """Verify pyproject.toml PEP 621 metadata and dynamic versioning."""
    import tomllib

    repo_root = Path(__file__).resolve().parent.parent.parent
    pyproject_path = repo_root / "pyproject.toml"

    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)

    project = data.get("project", {})
    assert "version" in project.get("dynamic", [])
    assert project.get("license") == "MIT"
    assert "classifiers" in project
    assert len(project["classifiers"]) > 0
    assert "urls" in project
    assert "Homepage" in project["urls"]
    assert "Repository" in project["urls"]
    assert "Issues" in project["urls"]

    # Verify hatchling version config
    hatch_version = data.get("tool", {}).get("hatch", {}).get("version", {})
    assert hatch_version.get("path") == "src/dotdoctor/__init__.py"


def test_pkgbuild_integrity() -> None:
    """Verify PKGBUILD dependencies don't have rolling release breaking upper limits."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    pkgbuild_path = repo_root / "packaging" / "aur" / "dotdoctor-git" / "PKGBUILD"

    content = pkgbuild_path.read_text(encoding="utf-8")

    # Depends block should not have < version upper limits
    depends_match = re.search(r"depends=\((.*?)\)", content, re.DOTALL)
    assert depends_match is not None
    depends_block = depends_match.group(1)

    for line in depends_block.splitlines():
        line = line.strip().strip("'\"")
        if not line or line.startswith("#"):
            continue
        # Verify no rolling-release-breaking upper limits in depends
        assert "<" not in line, f"Upper version bound found in PKGBUILD depends: {line}"

    init_text = (repo_root / "src" / "dotdoctor" / "__init__.py").read_text()
    version_match = re.search(
        r"^__version__\s*=\s*['\"]([^'\"]+)['\"]",
        init_text,
        re.M,
    )
    assert version_match is not None
    assert version_match.group(1) == __version__
