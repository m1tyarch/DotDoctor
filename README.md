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

A clear view of what needs attention, before you change anything.
DotDoctor brings system checks, updates, and maintenance into one small Linux CLI.
Checks run in parallel. In an interactive terminal, each result appears as soon
as it is ready.

```text
DotDoctor · system

  PASS  sys.packages  up to date
  PASS  sys.cache     100.0 MiB in pacman cache (clean)
  WARN  sys.backup    backup is not configured; recovery is not verified

2 passed · 1 warning
```

<sub>Illustrative report. Checks depend on your installed tools and configuration.</sub>

## Install

Requires Linux and Python **3.11 or newer**. Install the current development
branch from source:

```bash
git clone --branch refactor/system-update-strict-errors \
  https://github.com/m1tyarch/DotDoctor.git
cd DotDoctor
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
dotdoctor
```

For later runs, activate the same environment or use `.venv/bin/dotdoctor` from
the checkout. A plain clone of the default branch may contain older behavior.

## Use

Start with `dotdoctor` whenever you want to see what needs attention.
Choose an explicit mode when you already know the next step.

| Command | What happens |
| :--- | :--- |
| `dotdoctor` | Audit the system, then offer updates or supported fixes when relevant. |
| `dotdoctor --sysup` | Check update-related findings, then run the sequential update workflow when needed. |
| `dotdoctor --fix` | Check system hygiene and ask before each supported action. |

The audit does not install packages or start repairs. Its follow-up update/fix
prompts default to **yes**; enter `n` to keep the run diagnostic. `--sysup` uses
noninteractive package transactions after its checks. A configured snapshot is
created before updating; if snapshot creation fails, the update stops. Missing
snapshot tooling is reported as `SKIP`.

Use `-v` to expand findings, `--help` for options, and `dotdoctor version` for the
installed version. During an audit, **Ctrl+C** stops the diagnostic processes
and restores your terminal.

<details>
<summary>Export a report or exclude a check</summary>

```bash
dotdoctor --json-output report.json
dotdoctor --disable-check sys.firmware
```

JSON export is available for the default and fix modes. JSON uses `OUTD` for
terminal `OLD`. Disabling a package-manager check excludes its audit, not its
update transaction. See [reporting and exit codes](docs/reference.md#exit-codes)
for automation: warnings alone do not produce a nonzero scan exit code.

</details>

## Configure

DotDoctor discovers available system tools and uses built-in defaults.
To adjust checks or connect an existing maintenance job, start with
[dotdoctor.example.yml](dotdoctor.example.yml) and select your configuration:

```bash
dotdoctor --config /path/to/config.yml
```

Backups are not created automatically. An unconfigured backup is reported as
`WARN`; snapshots do not replace a verified backup. Optional tools such as
`arch-audit` or `smartctl` add coverage when installed. A clean report describes
the checks performed, not every possible system failure.

[Configuration and maintenance](docs/reference.md#configuration) covers file
precedence, intervals, timers, and the backup adapter.

## Project

[Reference](docs/reference.md) · [Contributing](CONTRIBUTING.md) ·
[Changelog](CHANGELOG.md) · [Release checklist](RELEASE_CHECKLIST.md) · [MIT license](LICENSE)

The CLI has three system modes and a `version` subcommand. Earlier dev profiles
and the `scan` command are no longer supported.
