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

| Command | What happens |
| :--- | :--- |
| `dotdoctor` | Audit the system in parallel, then offer updates or supported fixes when relevant. |
| `dotdoctor --sysup` | Check update-related findings, then run the sequential update workflow when needed. |
| `dotdoctor --fix` | Check system hygiene and prompt for confirmation before each supported action. |

The audit does not install packages or start repairs. Follow-up update/fix
prompts default to **yes**; enter `n` to keep the run diagnostic-only. `--sysup` runs
noninteractive package transactions after its checks. A configured snapshot is
created before updating; if snapshot creation fails, the update stops. Missing
snapshot tooling is reported as `SKIP`.

Use `-a` / `--all` to show all checks including passed ones, `-v` to expand findings, `--help` for options, and `dotdoctor version` for the
installed version. During an audit, **Ctrl+C** cleanly stops running diagnostic processes
and restores your terminal.

<details>
<summary>Export a report or exclude a check</summary>

```bash
dotdoctor --json-output report.json
dotdoctor --disable-check sys.firmware
```

JSON export is available for the default and fix modes. JSON uses `OUTD` for
terminal `OLD` and `SKIP` for neutral, unverified results.
Disabling a package-manager check excludes its audit, not its
update transaction. See [reporting and exit codes](docs/reference.md#exit-codes)
for automation: warnings alone do not produce a nonzero exit code.

</details>

## Configure

DotDoctor discovers available system tools and uses built-in defaults.
To adjust checks or connect an existing maintenance job, start with
[dotdoctor.example.yml](dotdoctor.example.yml) and specify your configuration:

```bash
dotdoctor --config /path/to/config.yml
```

* **Backups:** Backup monitoring is opt-in: without a configured adapter, `sys.backup` is omitted. Backups are not created automatically; snapshots do not replace a verified backup.
* **Optional Tools:** Utilities like `arch-audit` or `smartctl` expand check coverage when installed. A clean report reflects the checks performed, not every conceivable system failure.
* **Statuses:** `WARN` and `FAIL` indicate issues requiring attention. An active timer without completion history displays a neutral `SKIP` (details visible via `-v` or JSON) and is counted separately from passed checks.

See [Configuration and maintenance](docs/reference.md#configuration) for details on
file precedence, check intervals, timers, and the backup adapter.

## Project

[Reference](docs/reference.md) · [Contributing](CONTRIBUTING.md) ·
[Changelog](CHANGELOG.md) · [Release checklist](RELEASE_CHECKLIST.md) · [MIT license](LICENSE)
