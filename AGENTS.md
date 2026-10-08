# AI Agent Guidelines for DotDoctor

This file serves as the definitive reference and set of instructions for AI coding assistants working in the **DotDoctor** repository.

---

## 1. Project Overview & Philosophy

**DotDoctor** is a fast, minimalist CLI diagnostic and maintenance tool for Linux,
primarily Arch Linux / CachyOS. Its three modes are the default system audit,
`--sysup`, and `--fix`. Dev-environment profiles and the `scan` command were removed.
Kernel version comparison remains part of reboot detection; kernel journal
scanning (`sys.kernel-errors`) was removed.

### Core Principles

- **Minimalism & Restraint**: Zero visual noise. No emojis, no ASCII borders or box drawings, no gratuitous color highlights.
- **Calm by Default**: Normal states (`PASS`, `DONE`) are muted/dim green. Warnings (`WARN`) are yellow. Failures (`FAIL`) are bold red. Outdated items (`OLD`) are cyan.
- **Predictability & Speed**: Parallel checks during scan, honest status reporting when utilities are missing, no alternate-screen blinking (`screen=False`, transient live displays only).
- **Clean Actionability**: Any suggested `remediation` string must be directly executable in bash without extra prefixes like `"run "`.

---

## 2. Architecture & Code Structure

The project groups code into domain, application, infrastructure, and CLI layers.
Domain models have no external I/O. Application services currently also use CLI
status helpers and Rich for upgrade/fix output; do not describe presentation as
fully isolated from application code.

```
src/dotdoctor/
├── domain/             # Models, context and configuration (ZERO external I/O)
│   ├── models.py       # Severity (PASS, OUTD, WARN, FAIL), CheckResult, ScanReport
│   ├── context.py      # ScanContext (paths, environment, shell)
│   └── config.py       # DotDoctorConfig model
├── application/        # Application services & orchestrators
│   ├── system_update.py # SystemDryRunService (scan) & SystemUpgradeService (sysup)
│   ├── auto_fix.py     # InteractiveAutoFixer (confirmed actions and rechecks)
│   └── maintenance.py  # Maintenance readers, registrations, pre/postflight IDs
├── infrastructure/     # External integrations & I/O
│   ├── config_loader.py  # YAML selection and environment overrides
│   ├── audit_processes.py # Scoped readers and cancellation of process groups
│   ├── maintenance.py    # Command/JSON readers, news fetching, persisted state
│   └── news_worker.py    # Isolated HTTP/DNS worker used during audits
├── cli/                # Presentation layer (Typer + Rich)
│   ├── app.py          # CLI commands (dotdoctor, --sysup, --fix) & flags
│   ├── theme.py        # Design tokens, palette, and status line formatters
│   └── render.py       # Terminal report rendering & summary text
└── main.py             # Top-level entrypoint with SIGINT (exit code 130) handling
```

---

## 3. Strict Design System & Output Conventions

When modifying, adding, or refactoring CLI outputs or checks, **strictly adhere to these rules**:

### Line Layout

- **Indent**: Exactly 2 spaces at the beginning of each line (`INDENT = "  "`).
- **Status column**: Fixed 4-character uppercase label (`STATUS_WIDTH = 4`), aligned left.
- **Gap**: Exactly 2 spaces between status and text (`GAP = "  "`).
- **Hanging indent**: Multi-line messages and continuation rows must align with the text column.

### Status Tokens & Palette

| Context | Token | Style | Meaning |
|---|---|---|---|
| Scan / Checks | `PASS` | `dim green` | Check passed cleanly |
| Scan / Checks | `WARN` | `yellow` | Non-critical finding or missing checker tool |
| Scan / Checks | `FAIL` | `bold red` | Critical error, failure, or security issue |
| Scan / Checks | `OLD` | `cyan` | Updates available (mapped from internal `OUTD`) |
| Steps / Sysup | `DONE` | `dim green` | Step finished successfully |
| Steps / Sysup | `SKIP` | `dim` | Step skipped (tool not installed, etc.) |
| Steps / Sysup | `FAIL` | `bold red` | Step failed during execution |

> **Cyan Rule**: Cyan (`cyan`) is reserved **EXCLUSIVELY** for the `OLD` status token. Never use cyan for package names, versions, flags, or inline highlights.

### Header & Progress

- Header format: `DotDoctor · <profile or mode>` (the second part is `dim`). Printed **once** at start, followed by an empty line.
- Live progress must be **transient** (`Live(..., transient=True)`) and inline. **Never** use `screen=True` (no alternate screen flickering).
- While checks/steps are running: show a dot spinner (`Spinner("dots")`) in the status column. Do **not** print text like "Running".
- On check completion, replace its spinner with PASS/WARN/FAIL/OLD and a short
  result in the same row. Keep row order, truncate live messages to one line, and
  preserve parallel execution without artificial delays. A task returning no
  result uses SKIP, never an invented PASS. DONE belongs to successful action steps.
- Reuse spinner instances during a scan. Honor `NO_ANIMATION`,
  `DOTDOCTOR_NO_ANIMATION`, `NO_COLOR`, and static audit output on noninteractive
  or dumb terminals. Restore the cursor when the audit exits or is cancelled.
- During long sysup subprocesses: stream the active sub-line as `  [dim]↳ <truncated-output>[/dim]` beneath the step.
- Keep reboot authentication outside live displays so password prompts remain
  visible. Request reboot after other fixes, bound command waits, and never infer
  reboot completion from successful submission of the request.

### Remediation Text

- All `remediation` fields must contain raw, copy-pasteable commands or concise instructions:
  - Good: `sudo paccache -rk2`, `pacdiff -s`, `systemctl reboot`, `dotdoctor --sysup`
  - Forbidden: `run sudo paccache -rk2`, `Run pacdiff to merge`

---

## 4. Safety & System Command Constraints

1. **NEVER execute real system-modifying commands** during development, testing, or demonstrations:
   - Forbidden to run for real: `dotdoctor --sysup`, `pacman`, `yay`, `paru`, `flatpak update/uninstall`, `fwupdmgr`, `paccache`.
2. **Safe testing commands**:
   - Always run commands with mocks or non-destructive test harnesses.
   - Safe to run directly: `.venv/bin/dotdoctor --help`,
     `.venv/bin/dotdoctor version`, and read-only git/python commands.
   - Exercise audits with mocked command readers. The default command can offer
     real updates and fixes after its audit; do not treat it as an unconditional
     read-only demonstration. Test upgrade/fix paths only with mocks or a
     non-destructive harness.

---

## 5. Quality Gates (Must Pass Before Finishing Any Task)

Every task is considered complete **only** when all of the following pass without warnings or errors:

```bash
# 1. Run all unit and integration tests
.venv/bin/pytest -v

# 2. Check code style and linting
.venv/bin/ruff check .

# 3. Check code formatting
.venv/bin/black --check .

# 4. Static type checking
.venv/bin/mypy src
```

---

## 6. Common CLI Modes & Flags

- **`dotdoctor`** (default): Runs parallel dry-run system checks (`SystemDryRunService`).
- **`dotdoctor --sysup`**: Runs sequential system upgrade flow (`SystemUpgradeService`).
- **`dotdoctor --fix`**: Runs interactive auto-fixes for detected `WARN`/`FAIL` issues (`InteractiveAutoFixer`).
- **`--disable-check <id>`**: Excludes specific checks (also reads `DOTDOCTOR_DISABLE_CHECKS` env var).
- **`--json-output <path>`**: Exports report to machine-readable JSON.
- **`-v`, `--verbose`**: Shows expanded details (e.g. all available update package versions).
- **`--config <path>`**: Explicit path to YAML config file.
- **`dotdoctor version`**: Prints version information.

Configuration precedence: `--config`, then `DOTDOCTOR_CONFIG`, then the first
existing `./dotdoctor.yml`, `./dotdoctor.yaml`, XDG `config.yml`, or XDG `config.yaml`.
YAML/environment/CLI disabled checks are additive. See [README.md](README.md)
and [dotdoctor.example.yml](dotdoctor.example.yml) for maintenance settings.

Audit results use `on_task_result` for live statuses; retain the existing
`on_task_complete` callback for compatibility. Pass the prepared tasks to execution
instead of building another plan. Optional absent tools may omit checks entirely;
never describe an omitted check as verified coverage.

Scan/fix exit codes are 0 without FAIL (including WARN/OUTD) and 2 with FAIL.
Handled YAML configuration errors return 3. Upgrade failures use 1/2/3 depending
on the failing stage; Ctrl+C returns 130. JSON export is implemented for default
and fix modes, not sysup. Follow the [reference](docs/reference.md#exit-codes)
for the full exit table; the [README](README.md) provides installation and everyday use.
