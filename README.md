DotDoctor
=========

DotDoctor is a fast, minimalist Linux CLI utility for system diagnostics, hygiene audits, and comprehensive system updates.

Key Features
------------

- **Parallel System Diagnostics & Dry-Run** (`dotdoctor`): Fast parallel audit of Arch/AUR packages, Flatpaks, firmware, Oh-My-Zsh, orphan packages, pacman cache, `.pacnew` files, disk space, and failed systemd units.
- **Sequential System Upgrade** (`dotdoctor --sysup`): Complete, safe update flow with pre-update snapshot (Snapper / Timeshift), mirror refresh, package/AUR updates, Flatpak updates, unused runtime pruning, cache cleanup, Oh-My-Zsh, and firmware checks.
- **Interactive Auto-Fix** (`dotdoctor --fix`): Clean up detected system hygiene findings (orphan packages, pacman cache, unused Flatpak runtimes) safely with interactive confirmation.
- **Zero Visual Noise**: Minimalist 2-space terminal design, clear status tokens (`PASS`, `WARN`, `FAIL`, `OLD`, `DONE`, `SKIP`), and honest reporting.
- **Cancellable Audits**: Ctrl+C stops diagnostic commands and their process groups,
  restores the cursor, and exits with code `130`. Cancelling a scan does not start fixes.
- **Live Audit Results**: Each completed check replaces its spinner with its actual
  status and a short result in the same row. Checks remain parallel with no display delays.
- **Weekly Maintenance**: Signing keys and Arch notices, verified backup freshness,
  expected timer jobs, TRIM, SMART, Btrfs scrub history,
  filesystem capacity/inodes, security advisories, package files, and rebuild findings.

System Update Safety Model
--------------------------

Each scan builds one task plan for both progress and execution. Failed commands,
timeouts, inaccessible managers, and unsupported output report an unverified result
instead of PASS. A detected failed service remains FAIL even if another manager
cannot be queried. Read-only command cancellation is scoped to the audit; upgrade
transactions and interactive fixes use their existing execution paths.

- Pre-update system snapshot creation when Snapper or Timeshift is available.
- Strict subprocess exit code handling (`pacman`, `yay`/`paru`, `flatpak`, `fwupdmgr`).
- Distinguishes AUR out-of-date flagged packages from installable updates.
- Mirror fallback is attempted when package sync fails with mirror/network symptoms.
- Fatal update failures terminate cleanly with exit code `1`.
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
- Package integrity, database consistency, vulnerabilities, and rebuild findings are
  checked again after updating. A confirmed rebuild is checked again afterward.

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
	- `smartmontools` (`smartctl`) for physical disk health
	- `arch-audit` for Arch Security Tracker advisories
	- `rebuild-detector` (`checkrebuild`) for foreign package compatibility
	- `btrfs-progs` when Btrfs filesystems are mounted

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

Configuration
-------------

DotDoctor supports YAML-based configuration for disabling checks.

- Example file: `dotdoctor.example.yml`
- Default resolution: `$XDG_CONFIG_HOME/dotdoctor/config.yml` or `~/.config/dotdoctor/config.yml`
- Override path: `--config /path/to/config.yml`
- Environment variable: `DOTDOCTOR_DISABLE_CHECKS=sys.firmware,sys.shell-omz`

Example configuration:

```yaml
disabled_checks:
  - sys.firmware
  - sys.shell-omz
```

### Regular maintenance configuration

`dotdoctor.example.yml` documents the `maintenance` section. Existing configurations
with only `disabled_checks` continue to work. The three CLI modes are unchanged.

The default scan includes new `sys.keyring`, `sys.news`, `sys.backup`, `sys.timers`,
`sys.trim`, `sys.smart`, `sys.btrfs`, `sys.mounts`, `sys.security`,
`sys.package-db`, `sys.integrity`, and `sys.rebuild` checks when applicable.
Missing optional tools or insufficient permissions produce WARN, not a health PASS.
Disabling a check also disables its upgrade gate; this is an explicit coverage override,
not a request to omit an entire package manager from the upgrade.

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
The built-in tmpfiles cleanup and Arch WKD timers are checked separately from their
triggered services. Disabled timers that are not expected are left alone.

`--fix` asks separately before enabling expected timers, starting the existing TRIM
service, running a configured backup, scrubbing an overdue Btrfs filesystem, or
reinstalling selected official packages through a full upgrade. These new actions
default to **no** and are rechecked before receiving PASS. Failed services require
manual diagnosis; resetting the failure marker is not treated as a repair.

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

Scan/fix exit codes remain `0` without FAIL, `2` with FAIL, and `3` for configuration
errors. Upgrade returns `1` for fatal connectivity/repository failures, `2` for
blocked/failed maintenance or remaining critical findings, and `3` for sudo setup
failure. An update started from the default scan preserves its failure code.

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
