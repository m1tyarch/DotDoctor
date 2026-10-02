DotDoctor
=========

DotDoctor is a Linux CLI utility for diagnosing development environment issues and checking available system updates.

Key Features
------------

- System dry-run update audit by default (`dotdoctor` or `--sys`) for Arch packages, AUR, Flatpak, firmware, and Oh-My-Zsh
- Development environment checks (`--env` or `scan`) (binary availability, version checks, PATH integrity, shell config sanity, directory permissions)
- Live terminal dashboard and plain report mode
- Optional interactive auto-fix flow for actionable findings (`--fix`)
- System upgrade flow (`--sysup`) with strict failure handling

System Update Safety Model
--------------------------

- AUR parsing recognizes flagged packages, including out-of-date markers from AUR helper output
- Exit codes from update commands are handled strictly (`pacman`/`yay`, `flatpak`, `fwupdmgr`)
- Fatal network and mirror failures are treated as hard failures
- Mirror fallback is attempted when package sync fails with mirror/network symptoms
- Fatal update failures terminate with exit code `1`

Requirements
------------

- Python `>=3.11`
- Linux environment
- Optional system tools for extended checks and updates:
	- `checkupdates`
	- `yay`
	- `flatpak`
	- `fwupdmgr`
	- `cachyos-rate-mirrors` or `reflector`

Installation
------------

Using local repository:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Install dev dependencies:

```bash
pip install -e .[dev]
```

Usage
-----

Run default system dry-run update checks:

```bash
dotdoctor
```

Run development environment scan:

```bash
dotdoctor --env
```

Run development environment scan with auto-fix:

```bash
dotdoctor --env --fix
```

Run profile explicitly:

```bash
dotdoctor scan --profile python-dev
```

Run without fullscreen UI:

```bash
dotdoctor scan --no-ui
```

Export JSON report:

```bash
dotdoctor scan --json-output artifacts/report.json
```

Run system upgrades:

```bash
dotdoctor --sysup
```

Configuration
-------------

DotDoctor supports YAML-based configuration and profiles.

- Default file: `dotdoctor.yml`
- Example file: `dotdoctor.example.yml`
- Override path: `--config /path/to/config.yml`

Testing
-------

Run tests:

```bash
.venv/bin/pytest --tb=short
```

Project Layout
--------------

- `src/dotdoctor/domain`: entities, models, config schemas, ports
- `src/dotdoctor/application`: use-cases and system update flows
- `src/dotdoctor/infrastructure`: check implementations and config loading
- `src/dotdoctor/cli`: Typer commands and terminal rendering
- `tests/`: unit and integration test suites

