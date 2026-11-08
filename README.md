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
DotDoctor brings system health checks, safe updates, and routine maintenance into a single, lightweight Linux CLI.
Checks run in parallel, and results appear in your terminal the moment they are ready.

https://github.com/user-attachments/assets/8c189cbe-6875-4bc1-9f10-de9176c14795

<sub>Illustrative report. Checks depend on your installed tools and configuration.</sub>

## Install

Requires Linux and Python **3.11 or newer**.

The latest pre-release is [v0.2.0-beta.1](https://github.com/m1tyarch/DotDoctor/releases/tag/v0.2.0-beta.1) (identified as `0.2.0b1` by Python packaging).

### Option A: Local Arch Package (Recommended)

Build and install natively via `makepkg` (see [Arch packaging](packaging/aur/README.md); AUR publication coming soon):

```bash
git clone https://github.com/m1tyarch/DotDoctor.git
cd DotDoctor/packaging/aur/dotdoctor-git
makepkg -si
```

### Option B: Install from source in a virtualenv

```bash
git clone --branch v0.2.0-beta.1 --depth 1 https://github.com/m1tyarch/DotDoctor.git
cd DotDoctor
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
dotdoctor
```

For subsequent runs, activate the virtual environment or run `.venv/bin/dotdoctor`. To contribute or work on the development version, clone the `main` branch instead; see [Contributing](CONTRIBUTING.md).

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
