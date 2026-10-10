# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added

- Live audit results in fixed rows: completed checks show PASS/WARN/FAIL/OLD and
  a short finding immediately, while other checks continue in parallel.
- Weekly maintenance checks for signing keys and Arch news, verified backup freshness,
  expected systemd jobs and TRIM, storage health and Btrfs scrub, known vulnerabilities,
  package database consistency, missing files and rebuild candidates.
- YAML configuration for existing backup adapters, expected timers and maintenance intervals.
- Upgrade preflight and postflight checks with explicit news review and keyring recovery.
- Confirmed maintenance actions with checks after completion; unavailable readers
  report findings and absent optional tools may omit checks.

### Fixed

- Pass Paru's optional rebuild value as `--rebuild=yes` so `yes` cannot become
  an unintended package target; keep Yay's boolean `--rebuild` syntax.
- Keep sudo credentials alive during Paru upgrades with `--sudoloop`, as for Yay.
- Keep reboot authentication visible outside spinners, bound authentication and
  reboot command waits, and report timeouts without automatically retrying.
- Request reboot after other fixes; keep completion unverified until the next
  boot instead of immediately rescanning or marking the reboot check PASS.
- Explain checkupdates failures with the exit code and command output; report a
  missing fakeroot dependency with its installation command instead of suggesting
  an update workflow that may stop on the same failed check.
- Distinguish failed timer jobs, skipped conditions, failed assertions, and missing
  completion records without claiming unverified jobs succeeded.
- Isolate the configuration-file detection test from the host's `/etc`, so CI
  does not depend on access to protected system directories.
- Redesign the README around installation and everyday use; move detailed
  configuration, command behavior, and limitations into a linked reference.
- Keep the upgrade spinner's animation state across progress refreshes, including
  periods when the command emits no new output.
- Refresh project documentation for the three system-maintenance modes,
  configuration precedence, actual exit codes, live results, and testing limits.
- Remove the privileged kernel journal check from audits and upgrade preflight;
  retain reboot detection without sudo.
- Treat empty AUR queries with exit code 1, fresh firmware metadata with exit code 2,
  and paccache's no-candidates message as normal command outcomes.
- Report unavailable or failed AUR, systemd, Flatpak, journal, firmware, cache and
  Oh-My-Zsh checks honestly instead of returning a clean result.
- Execute the same prepared scan plan used by the CLI progress display.
- Cancel audit process groups on Ctrl+C, including readers blocked on HTTP/DNS;
  exit with code 130 without waiting for the checks' normal timeouts.
- Stop upgrades after snapshot or package transaction failures.
- Recheck findings after auto-fixes instead of treating command success as system health.
- Preserve failed services for diagnosis instead of clearing their failed state.

## [0.1.0] - 2026-07-09

This entry records the original development-environment MVP. Later source changes
replaced those profiles and the `scan` command with the three system-maintenance
modes. The package version remains 0.1.0; this historical entry does not describe
the current CLI. See [README.md](README.md) and Unreleased above for current behavior.

### Added

- Initial production-style DotDoctor CLI skeleton using Typer + Rich + Pydantic.
- Layered architecture: CLI, application use-case, domain models, infrastructure checks.
- `scan` command with human-readable terminal report and JSON export.
- Exit code strategy:
  - `0`: only PASS
  - `1`: WARN present, no FAIL
  - `2`: FAIL present
  - `3`: DotDoctor runtime/config error
- Built-in checks for:
  - required binaries + minimum versions,
  - PATH integrity,
  - shell config sanity,
  - dev directory permissions.
- YAML config support with `python-dev` and `cpp-dev` profiles.
- Environment overrides (`DOTDOCTOR_CONFIG`, `DOTDOCTOR_DISABLE_CHECKS`).
- Unit and integration tests with edge-case coverage.
- GitHub Actions CI: ruff, black --check, mypy, pytest with coverage gate.
