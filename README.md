<div align="center">

<h1>DotDoctor</h1>
<p>Keep your Arch system in check.</p>
<p><sub>Arch Linux / CachyOS &nbsp;·&nbsp; Python 3.11+ &nbsp;·&nbsp; MIT</sub></p>

<p>
  <a href="#install">Install</a> &nbsp;·&nbsp;
  <a href="#use">Use</a> &nbsp;·&nbsp;
  <a href="#configure">Configure</a> &nbsp;·&nbsp;
  <a href="docs/reference.md">Reference</a>
</p>

</div>

Get a clear view of what needs attention before making any changes.
DotDoctor provides parallel diagnostic audits, guarded updates, and interactive hygiene for Arch Linux systems in a lightweight CLI.

DotDoctor defines up to **26 modular system checks** across five categories (executed concurrently depending on installed tools):
* **Updates:** Official packages (`pacman` / `checkupdates`), AUR (`paru` / `yay`), Flatpaks, firmware (`fwupd`), and Oh-My-Zsh.
* **Integrity & Security:** Package database consistency (`pacman -Dk`), package signing keys (`archlinux-keyring`), modified package files, unread Arch news notices, known vulnerabilities (`arch-audit`), and foreign library ABI rebuilds (`rebuild-detector`).
* **System Hygiene:** Orphan packages, package cache size (`paccache`), unused Flatpak runtimes, `.pacnew` files, and `systemd-journald` disk usage.
* **Hardware & Storage:** Storage device health (S.M.A.R.T. via `smartctl`), SSD discard/TRIM timers, Btrfs filesystem errors and scrubs, and filesystem mount capacities.
* **Services & Runtime State:** Failed systemd units, scheduled maintenance timers, pending reboot detection (kernel/driver mismatch), and backup freshness.

https://github.com/user-attachments/assets/8a176002-5070-47a3-a2e8-a789da28a998

<sub>Illustrative report. Checks depend on your installed tools and configuration.</sub>

## Install

Requires an **Arch-based Linux distribution** (such as Arch Linux or CachyOS) with `pacman`, `systemd`, and **Python 3.11 or newer**.

Check the [Releases](https://github.com/m1tyarch/DotDoctor/releases) page for release notes and tagged versions.

### Option A: Native Arch Linux Package (Recommended)

Builds the latest package directly from the repository's `main` branch and registers it with `pacman` (see [Arch packaging](packaging/aur/README.md)):

```bash
git clone https://github.com/m1tyarch/DotDoctor.git
cd DotDoctor/packaging/aur/dotdoctor-git
makepkg -si
```

This installs `dotdoctor` to `/usr/bin/dotdoctor`, installs shell completions for Bash, Zsh, and Fish, and tracks dependencies natively via `pacman`.

### Option B: Isolated Installation via pipx or virtualenv

Because Arch Linux marks the system Python environment as externally managed (PEP 668), standalone Python CLIs should be installed into an isolated environment.

Using [pipx](https://github.com/pypa/pipx):

```bash
pipx install git+https://github.com/m1tyarch/DotDoctor.git
```

Or using a standard virtual environment:

```bash
git clone https://github.com/m1tyarch/DotDoctor.git
cd DotDoctor
python -m venv .venv
.venv/bin/pip install .
.venv/bin/dotdoctor
```

For subsequent runs, execute `.venv/bin/dotdoctor` or activate the environment (`source .venv/bin/activate`). For development and testing with editable installs (`pip install -e .`), see [Contributing](CONTRIBUTING.md).

## Use

Start with `dotdoctor` whenever you want to see what needs attention.
Choose an explicit mode when you already know the next step:

| Mode | Action | Privileges |
| :--- | :--- | :--- |
| `dotdoctor` | Parallel diagnostic scan across all checks; offers updates or fixes if findings are detected. | Regular user (read-only) |
| `dotdoctor --sysup` | Guarded system upgrade: pre-update snapshot, mirror refresh, `pacman -Syu`, AUR, Flatpaks. | Root / `sudo` (prompts up front) |
| `dotdoctor --fix` | Interactive maintenance: clean pacman cache, remove orphans, clean Flatpaks, reset failed units. | Regular user (`sudo` per action) |

> [!IMPORTANT]
> **Prompt defaults:** Interactive prompts (such as `"Update everything now? [Y/n]"` and auto-fix actions) default to **Yes** (`[Y/n]`). Pressing **Enter** immediately proceeds with the action. Enter `n` or press `Ctrl+C` to decline or keep the execution diagnostic-only.

### Common Options

* `-a`, `--all`: Display all checks, including passed (`PASS`) ones.
* `-v`, `--verbose`: Show detailed findings, command outputs, and package version upgrade lists.
* `-d`, `--disable-check <id>`: Exclude specific check IDs for this run (can be repeated, e.g. `-d sys.firmware`).
* `-c`, `--config <path>`: Load a custom YAML configuration file.
* `-V`, `--version`: Print DotDoctor version and exit (or run `dotdoctor version`).
* `-h`, `--help`: Show full command-line help and usage examples.

During an audit, **Ctrl+C** cleanly stops running background diagnostic processes and restores terminal state.

### Upgrade Workflow (`--sysup`)

When running `dotdoctor --sysup`:
1. **Pre-flight verification:** Caches `sudo` credentials, checks HTTPS connectivity, and verifies disk space on `/` and `/boot`. If network or disk checks fail, updates abort before changes occur.
2. **Pre-update snapshot:** Detects `snapper` or `timeshift`. If configured, a snapshot is created. If snapshot creation fails, the update halts immediately (code 2). If no snapshot tool is found, this step is marked `SKIP` and updates proceed.
3. **Sequential transactions:** Refreshes mirrors (`cachyos-rate-mirrors` or `reflector`), verifies keyring packages, runs `pacman -Syu`, updates AUR packages (`paru` or `yay`), updates Flatpaks, cleans package caches (`paccache`), and checks firmware updates (`fwupd`).
4. **Failure handling:** If a transaction fails, subsequent mutations abort, failure counts are reported, and rollback instructions are displayed (`sudo snapper rollback` or `sudo timeshift --restore`).
5. **Post-flight checks and `.pacnew`:** Scans `/etc` for new `.pacnew` files and prints review reminders (`pacdiff`). Verifies systemd unit statuses and checks whether a kernel update requires a reboot.

### Machine-Readable Output (JSON)

DotDoctor provides machine-readable output for automation, monitoring, and scripting:

```bash
dotdoctor --json                     # Output structured JSON report directly to stdout
dotdoctor --json-output report.json  # Save structured JSON report to a file
```

The output contains metadata (`dotdoctor_version`, `schema_version`), an execution `summary` (`total`, `passed`, `warnings`, `failures`, `outdated`, `skipped`), the overall `exit_code`, and an array of individual `results`.

### Exit Codes

DotDoctor uses standard exit codes suitable for CI/CD and shell scripting:

| Code | Meaning | Typical Causes |
| :---: | :--- | :--- |
| `0` | Success / Clean | All checks passed (`PASS` / `SKIP`); or update completed with zero errors. |
| `1` | Warnings or Outdated | One or more checks returned `WARN` or `OUTD`; or pre-flight network/disk check failed. |
| `2` | Critical Issue / Failure | One or more checks returned `FAIL`; or pre-update snapshot or package transaction failed. |
| `3` | Configuration or Auth Error | Configuration file not found / invalid syntax; or `sudo` authentication timed out. |

## Configure

DotDoctor discovers available system tools automatically and works out of the box with built-in defaults.

To customize check intervals, set disk thresholds, or configure backups, copy [dotdoctor.example.yml](dotdoctor.example.yml) to your configuration path:

```bash
mkdir -p ~/.config/dotdoctor
cp dotdoctor.example.yml ~/.config/dotdoctor/config.yml
```

### Configuration Search Precedence

DotDoctor looks for configuration in the following order:
1. Explicit CLI argument: `--config <path>` or `-c <path>`.
2. Environment variable: `DOTDOCTOR_CONFIG=/path/to/config.yml`.
3. User XDG configuration: `~/.config/dotdoctor/config.yml` (or `config.yaml`).
4. System-wide configuration: `/etc/dotdoctor/config.yml` (or `config.yaml`).
5. Built-in defaults (used if no configuration file is found).

### Notable Configuration Settings

* **Backups:** Backup monitoring is opt-in (`sys.backup`): without a configured adapter command, `sys.backup` is omitted. Backups are not created automatically; snapshots do not replace external backups.
* **Optional Tools:** Utilities like `arch-audit`, `smartctl`, `btrfs-progs`, or `snapper` expand check coverage when installed.
* **Check Statuses:** `WARN` and `FAIL` indicate actionable issues. An active systemd timer without previous run history displays a neutral `SKIP` (details visible via `-v` or `--json`) and is tracked separately from passed checks.

See [Configuration reference](docs/reference.md#configuration) for complete schema documentation and backup adapter examples.

## Project

[Reference](docs/reference.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [MIT License](LICENSE)
