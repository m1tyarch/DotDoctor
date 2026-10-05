DotDoctor
=========

DotDoctor is a fast, minimalist Linux CLI utility for system diagnostics, hygiene audits, and comprehensive system updates.

Key Features
------------

- **Parallel System Diagnostics & Dry-Run** (`dotdoctor`): Fast parallel audit of Arch/AUR packages, Flatpaks, firmware, Oh-My-Zsh, orphan packages, pacman cache, `.pacnew` files, disk space, and failed systemd units.
- **Sequential System Upgrade** (`dotdoctor --sysup`): Complete, safe update flow with pre-update snapshot (Snapper / Timeshift), mirror refresh, package/AUR updates, Flatpak updates, unused runtime pruning, cache cleanup, Oh-My-Zsh, and firmware checks.
- **Interactive Auto-Fix** (`dotdoctor --fix`): Clean up detected system hygiene findings (orphan packages, pacman cache, unused Flatpak runtimes) safely with interactive confirmation.
- **Zero Visual Noise**: Minimalist 2-space terminal design, clear status tokens (`PASS`, `WARN`, `FAIL`, `OLD`, `DONE`, `SKIP`), and honest reporting.

System Update Safety Model
--------------------------

- Pre-update system snapshot creation when Snapper or Timeshift is available.
- Strict subprocess exit code handling (`pacman`, `yay`/`paru`, `flatpak`, `fwupdmgr`).
- Distinguishes AUR out-of-date flagged packages from installable updates.
- Mirror fallback is attempted when package sync fails with mirror/network symptoms.
- Fatal update failures terminate cleanly with exit code `1`.

Requirements
------------

- Python `>=3.11`
- Linux environment (primarily Arch Linux / CachyOS)
- System tools (used dynamically when available):
	- `checkupdates`
	- `paru` or `yay`
	- `pacman-contrib` (`paccache`, `pacdiff`)
	- `flatpak`
	- `fwupdmgr`
	- `cachyos-rate-mirrors` or `reflector`
	- `snapper` or `timeshift`

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

### 1. Diagnostic / Dry-Run Scan (Default)

Run parallel system diagnostic checks:

```bash
dotdoctor
```

Show expanded details (e.g. all available update package versions):

```bash
dotdoctor -v
```

Export report to JSON:

```bash
dotdoctor --json-output report.json
```

Disable specific checks:

```bash
dotdoctor --disable-check sys.firmware --disable-check sys.omz
```

### 2. Comprehensive System Upgrade

Run full sequential system upgrade flow:

```bash
dotdoctor --sysup
```

### 3. Interactive Auto-Fix

Interactively resolve detected system hygiene issues:

```bash
dotdoctor --fix
```

Configuration
-------------

DotDoctor supports YAML-based configuration for disabling checks.

- Example file: `dotdoctor.example.yml`
- Default resolution: `$XDG_CONFIG_HOME/dotdoctor/config.yml` or `~/.config/dotdoctor/config.yml`
- Override path: `--config /path/to/config.yml`
- Environment variable: `DOTDOCTOR_DISABLE_CHECKS=sys.firmware,sys.omz`

Example configuration:

```yaml
disabled_checks:
  - sys.firmware
  - sys.omz
```

Testing
-------

Run tests:

```bash
.venv/bin/pytest -v
```

Project Layout
--------------

- `src/dotdoctor/domain`: Models, context, configuration schema
- `src/dotdoctor/application`: System upgrade and dry-run orchestrators, interactive auto-fixer
- `src/dotdoctor/infrastructure`: Configuration loader with XDG precedence
- `src/dotdoctor/cli`: Typer application, theme design tokens, terminal renderer
- `tests/`: Unit and integration test suites
