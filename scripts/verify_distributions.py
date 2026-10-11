"""Install each release artifact in a fresh venv and exercise read-only entrypoints."""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import venv
from pathlib import Path


def verify(artifact: Path, expected: str) -> None:
    with tempfile.TemporaryDirectory(prefix="dotdoctor-package-check-") as directory:
        root = Path(directory)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / "bin/python"
        entrypoint = environment / "bin/dotdoctor"
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        env.update({"TERM": "dumb", "NO_COLOR": "1", "COLUMNS": "120"})

        def run(*args: str) -> str:
            completed = subprocess.run(
                args, cwd=root, env=env, check=True, capture_output=True, text=True
            )
            # CI may force ANSI styles even when stdout is captured.
            return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", completed.stdout).strip()

        run(str(python), "-m", "pip", "install", "--disable-pip-version-check", str(artifact))
        run(str(python), "-m", "pip", "check")
        imports = """
import importlib
import importlib.metadata
import pkgutil
import sys
from pathlib import Path
import dotdoctor
assert dotdoctor.__version__ == importlib.metadata.version('dotdoctor') == sys.argv[1]
assert Path(dotdoctor.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
for module in pkgutil.walk_packages(dotdoctor.__path__, prefix='dotdoctor.'):
    importlib.import_module(module.name)
"""
        run(str(python), "-c", imports, expected)
        assert run(str(entrypoint), "version") == f"dotdoctor {expected}"
        help_text = run(str(entrypoint), "--help")
        for option in ("--sysup", "--fix", "--json-output", "--config"):
            assert option in help_text, f"Missing documented option: {option}\n{help_text}"
        for removed in ("--env", "--sys ", "--profile", "--no-ui"):
            assert removed not in help_text, f"Removed option still advertised: {removed}"
        print(f"PASS {artifact.name}: clean install, dependencies, imports, help, version")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1] / "pyproject.toml"
    expected = tomllib.loads(project.read_text())["project"]["version"]
    for artifact in args.artifacts:
        verify(artifact.resolve(strict=True), expected)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stdout or "", file=sys.stderr)
        print(exc.stderr or "", file=sys.stderr)
        raise
