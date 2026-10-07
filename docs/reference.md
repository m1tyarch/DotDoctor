# Reference

[Back to DotDoctor](../README.md)

Detailed behavior for the current system-maintenance CLI. Start with the
[README](../README.md) for installation and the three everyday commands.

[Commands and reports](#commands-and-reports) · [Configuration](#configuration) ·
[Updates and fixes](#updates-and-fixes) · [Tools](#tools) · [Development](#development)

## Commands and reports

### 1. Diagnostic / Dry-Run Scan (Default)

Run parallel system diagnostic checks:

```bash
dotdoctor
```

The audit starts without changing packages or starting repairs. After reporting,
the default command can offer an update and supported fixes; these start only
after confirmation. The initial update/fix prompts default to yes, so read them
before pressing Enter. EOF declines these prompts; redirected input can still
accept actions if it supplies an affirmative answer.

The current CLI has three modes and the `version` subcommand. The former `scan`,
`--env`, `--profile`, `python-dev`, and `cpp-dev` interfaces are no longer supported.

Show expanded details (e.g. all available update package versions):

```bash
dotdoctor -v
```

Export report to JSON:

```bash
dotdoctor --json-output report.json
```

JSON export is implemented for the default command and `--fix`, and contains the
latest scan/fix report. Successful accepted updates are followed by a new scan;
if an accepted update fails, the default command exports its pre-update report
and returns the update failure code. `--sysup` does not export a JSON report.
JSON uses `profile: system` and `results` with `check_id`, `severity`, `message`,
`remediation`, and `details`; the terminal token `OLD` is serialized as `OUTD`.
See the illustrative [example report](../artifacts/example-report.json).

Disable specific checks:

```bash
dotdoctor --disable-check sys.firmware --disable-check sys.shell-omz
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

## Configuration

DotDoctor supports YAML-based configuration for disabling checks.

- Example file: [dotdoctor.example.yml](../dotdoctor.example.yml)
- Configuration selection, in order: explicit `--config`, `DOTDOCTOR_CONFIG`,
  then the first existing file from `./dotdoctor.yml`, `./dotdoctor.yaml`,
  `$XDG_CONFIG_HOME/dotdoctor/config.yml`, and `config.yaml` in that directory.
  When `XDG_CONFIG_HOME` is unset, the directory is `~/.config/dotdoctor`.
- With no configuration file, built-in defaults apply. A selected nonexistent
  path also currently falls back to defaults.
- `DOTDOCTOR_DISABLE_CHECKS=sys.firmware,sys.shell-omz` adds to YAML exclusions;
  repeated `--disable-check` options add exclusions for the current invocation.
- YAML also configures maintenance intervals, expected timers, and an existing
  backup adapter.

Example configuration:

```yaml
disabled_checks:
  - sys.firmware
  - sys.shell-omz
```

### Regular maintenance configuration

[dotdoctor.example.yml](../dotdoctor.example.yml) documents the `maintenance`
section. Existing configurations with only `disabled_checks` continue to work.
The three CLI modes are unchanged.

The default audit includes `sys.keyring`, `sys.news`, `sys.backup`, `sys.timers`,
`sys.trim`, `sys.smart`, `sys.btrfs`, `sys.mounts`, `sys.security`,
`sys.package-db`, `sys.integrity`, and `sys.rebuild` checks when applicable.
Checks are registered according to available tools. For example, `sys.security`
is included only when pacman and arch-audit are installed; `sys.smart` requires
lsblk and smartctl. An omitted check provides no health or security coverage.
An included check that cannot read or verify its data reports WARN or FAIL.
Disabling a maintenance check also removes it from pre/postflight checks; this is
an explicit coverage override. Separate upgrade guards for connectivity and
root/boot disk space still run. Disabling a package-manager audit does not omit
that package manager's update transaction.

Reboot detection (`sys.reboot`) compares the running kernel version with installed
module directories without sudo. Kernel journal scanning has been removed from
audits and upgrade preflight checks.

Backups are **not configured automatically**. Without a configured backup, DotDoctor
reports WARN and does not offer a nonexistent backup fix. To connect an existing job:

```yaml
maintenance:
  backup:
    service: backup.service
    scope: user
    max_age_days: 7
    required_before_upgrade: true
    status_command: [/home/you/bin/backup-status]
```

The read-only status command is an argument array, executed without a shell or stdin.
It must query the backup destination using your existing tool and emit JSON such as:

```json
{"completed_at": "2026-10-05T12:00:00+02:00", "verified": true}
```

`completed_at` is an ISO timestamp with a timezone or a Unix timestamp. `verified`
must be the boolean `true` for a completed, verified copy. A recent service execution
alone is insufficient. With `required_before_upgrade: true`, unavailable, unverified,
failed, or stale backups block upgrades. DotDoctor does not assume a backup service
name, choose a destination, or invent a successful copy.

Additional expected timers can be configured with `unit`, `scope`, and `max_age_days`.
The built-in `systemd-tmpfiles-clean.timer` has a two-day freshness limit;
`archlinux-keyring-wkd-sync.timer` has an eight-day limit and is expected when
pacman is available and archlinux-keyring is configured. Their triggered services
are checked too. Other timers are checked only when listed in the configuration.

`--fix` asks separately before enabling expected timers, starting the existing TRIM
service, running a configured backup, scrubbing an overdue Btrfs filesystem, or
reinstalling selected official packages through a full upgrade. These new actions
default to **no** and are rechecked before receiving PASS. Failed services require
manual diagnosis; resetting the failure marker is not treated as a repair.
Timer auto-fixes currently enable inactive expected timers; they do not rerun a
failed or unverified triggered service. A generic "has not succeeded" finding
can also reflect missing completion state, so inspect the service and its journal
before assuming the job failed.

### Frequency and limits

- TRIM is due after seven days; an applicable continuous discard configuration also
  satisfies the check. Encryption/discard policy is never changed automatically.
- Btrfs scrub is due after 30 days by default. Scans read saved scrub status and device
  counters; they never start scrub or SMART self-tests. Scrub targets are deduplicated
  by filesystem identity. Device error history requires review; uncorrectable scrub
  errors and current SMART failures block upgrades rather than trigger repair.
- Package file checks use `pacman -Qk`, not a full-content hash scan. `pacman -Dk`
  checks local database consistency. Both have bounded execution times.
- Security coverage is limited to Arch Security Tracker, including issues without
  an available fix. It does not cover all AUR, Flatpak, or third-party software.
- Snapshot coverage and backup restorability still depend on their configuration.
  A clean report describes performed checks, not a guarantee against all failures.
- `sys.keyring` checks installed keyring files and clock synchronization; it does
  not independently verify all package signatures. Package transactions enforce
  signature verification.
- The initial connectivity probe uses TCP port 53 on external DNS servers;
  filtering those connections can prevent updates despite working HTTPS access.
- Cancellation of audit process groups is tested separately from cancellation of
  package transactions. Do not assume that interrupting an upgrade rolls it back.

### Exit codes

| Code | Current meaning |
| --- | --- |
| `0` | Scan/fix has no FAIL; WARN and OUTD alone also return zero. Upgrade completed, or its initial audit reported no updates and no FAIL. |
| `1` | Upgrade connectivity failure or unrecovered mirror/network failure. |
| `2` | Scan/fix contains FAIL, an upgrade is blocked or fails, or CLI arguments are invalid. |
| `3` | YAML parsing/schema error, or caching sudo credentials for an upgrade failed. |
| `130` | Interrupted with Ctrl+C. |

An update accepted from the default command preserves its failure code. Use JSON
findings to distinguish warnings from a clean report; a zero exit code does not
mean that every possible check was performed. Unexpected uncaught exceptions are
not converted into a uniform configuration/runtime-error code.

### Terminal behavior

On an interactive terminal, pending checks use a dot spinner. Completed checks
show their actual status and a single-line result without changing row order;
long text is truncated during progress and the final report supplies details.
`NO_ANIMATION=1`, `DOTDOCTOR_NO_ANIMATION=1`, or `NO_COLOR=1` disables live audit
progress. Piped output and dumb terminals also use the static final report.

## Updates and fixes

`--sysup` first audits update-related checks. If it finds no updates and no FAIL,
it prints any warnings and exits without running the upgrade sequence. Package
transactions currently use noninteractive confirmation flags; read the audit
findings before starting an upgrade.

Each scan builds one task plan for both progress and execution. Failed commands,
timeouts, inaccessible managers, and unsupported output produce a finding rather
than PASS. A detected failed service remains FAIL even if another manager
cannot be queried. Read-only command cancellation is scoped to the audit; upgrade
transactions and interactive fixes use their existing execution paths.

- Pre-update system snapshot creation when Snapper or Timeshift is available.
- Strict subprocess exit code handling (`pacman`, `yay`/`paru`, `flatpak`, `fwupdmgr`).
- Distinguishes AUR out-of-date flagged packages from installable updates.
- Mirror fallback is attempted when package sync fails with mirror/network symptoms.
- Connectivity and unrecovered mirror failures return `1`; other failed or blocked
  upgrade steps return `2`. See the [exit-code table](#exit-codes).
- A failed pre-update snapshot or blocking maintenance finding aborts the update.
- Unread Arch notices require explicit confirmation (default: no); acceptance is
  stored in `$XDG_STATE_HOME/dotdoctor/maintenance.json`, or
  `~/.local/state/dotdoctor/maintenance.json`. Scanning never acknowledges notices.
- Available keyring updates are installed before the full system upgrade. A known
  signature/trust failure gets one keyring recovery attempt. Signature verification
  is never disabled. A synchronized package database is followed immediately by
  `pacman -Su`; failures stop the remaining workflow.
- Read-only privileged checks use `sudo -n` and never prompt for a password. Storage
  checks run again after sudo credentials are cached, before any upgrade transaction.
- Missing package files, database consistency, vulnerabilities, and rebuild findings are
  checked again after updating. A confirmed rebuild is checked again afterward.

## Tools

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
	- `smartmontools` (`smartctl`) for physical disk health
	- `arch-audit` for Arch Security Tracker advisories
	- `rebuild-detector` (`checkrebuild`) for foreign package compatibility
	- `btrfs-progs` when Btrfs filesystems are mounted

## Development

Run tests:

```bash
.venv/bin/pytest -v
```

The [contributing guide](../CONTRIBUTING.md) lists all local checks and safe testing
rules. GitHub Actions currently runs Ruff, Black, mypy, and tests on Python 3.11,
with a coverage threshold of 75%. Its installation uses editable source; wheel
and sdist installation checks are release tasks, not existing CI steps.

### Source layout

- `src/dotdoctor/domain`: Models, context, configuration schema
- `src/dotdoctor/application`: System audit/update orchestrators, maintenance checks, interactive auto-fixer
- `src/dotdoctor/infrastructure`: Configuration loader, bounded command readers, audit process cancellation, maintenance state and isolated news fetching
- `src/dotdoctor/cli`: Typer application, theme design tokens, terminal renderer
- `tests/`: Unit and integration test suites
