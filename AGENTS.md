# AI Agent Guidelines for DotDoctor

This file serves as the definitive reference and set of instructions for AI coding assistants working in the **DotDoctor** repository.

---

## 1. Project Overview & Philosophy

**DotDoctor** is a fast, minimalist CLI/TUI diagnostic and maintenance tool for Linux (primarily Arch Linux, with extensible checks for package managers, Flatpak, firmware, kernels, and dev environments).

### Core Principles
- **Minimalism & Restraint**: Zero visual noise. No emojis, no ASCII borders or box drawings, no gratuitous color highlights.
- **Calm by Default**: Normal states (`PASS`, `DONE`) are muted/dim green. Warnings (`WARN`) are yellow. Failures (`FAIL`) are bold red. Outdated items (`OLD`) are cyan.
- **Predictability & Speed**: Parallel checks during scan, honest status reporting when utilities are missing, no alternate-screen blinking (`screen=False`, transient live displays only).
- **Clean Actionability**: Any suggested `remediation` string must be directly executable in bash without extra prefixes like `"run "`.

---

## 2. Architecture & Code Structure

The project follows clean architecture principles with strict layer boundaries:

```
src/dotdoctor/
├── domain/             # Pure models & protocols (ZERO external I/O)
│   ├── models.py       # Severity (PASS, OUTD, WARN, FAIL), CheckResult, ScanReport
│   ├── context.py      # ScanContext (paths, environment, shell)
│   ├── config.py       # Pydantic configuration models
│   └── ports.py        # EnvironmentCheck protocol
├── application/        # Application services & orchestrators
│   ├── system_update.py # SystemDryRunService (scan) & SystemUpgradeService (sysup)
│   ├── auto_fix.py     # InteractiveAutoFixer (safe remediation execution)
│   └── use_cases.py    # RunScanUseCase (profile check execution)
├── infrastructure/     # External integrations & I/O
│   ├── checks/         # Check implementations (core dev binaries, PATH, etc.)
│   └── config_loader.py# XDG-compliant configuration loader with precedence
├── cli/                # Presentation layer (Typer + Rich)
│   ├── app.py          # CLI commands (root, scan, version) & flags
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
- During long sysup subprocesses: stream the active sub-line as `  [dim]↳ <truncated-output>[/dim]` beneath the step.

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
   - Safe to run directly: `.venv/bin/dotdoctor --help`, `dotdoctor --env` (read-only dev checks), read-only git/python commands.

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
- **`dotdoctor --sysup`**: Runs sequential system upgrade (`SystemUpgradeService`).
- **`dotdoctor --fix`**: Runs interactive auto-fixes for detected `WARN`/`FAIL` issues.
- **`dotdoctor --env`**: Runs development environment checks for profile `python-dev`.
- **`dotdoctor scan --profile <name>`**: Runs checks for a specific profile (supports `--profile system`).
- **`--disable-check <id>`**: Excludes specific checks (also reads `DOTDOCTOR_DISABLE_CHECKS` env var).
- **`--json-output <path>`**: Exports report to machine-readable JSON.
- **`-v`, `--verbose`**: Shows expanded details (e.g. all available update package versions).
