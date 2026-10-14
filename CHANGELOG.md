# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Fixed

- Replace public DNS-port connectivity probes with parallel HTTPS checks and
  bounded DNS resolution; a single unavailable service does not mark the system offline.
- Use FAIL consistently for news and security checks blocked by unavailable
  internet, matching the network check and preserving the cause in JSON.

### Added

- Show the complete pacman orphan-removal plan, package versions, additional
  dependencies and estimated space to free before confirmation. Revalidate after
  sudo authentication and remove only the approved set.

## [0.2.0-beta.1] - 2026-10-11

First GitHub pre-release of the system-maintenance CLI. Python packages and
`dotdoctor version` use the normalized version `0.2.0b1`.

### Migration from the 0.1.0 development MVP

- The `scan` command, `--env`, `--sys`, `--profile`, and development-environment
  profiles are removed. Use `dotdoctor`, `dotdoctor --sysup`, or `dotdoctor --fix`.
- Audit/fix exit code 0 includes WARN, OUTD and neutral SKIP; FAIL returns 2.
  Automation should inspect JSON results for findings and coverage.
- JSON uses `OUTD` for terminal `OLD` and adds `SKIP` for neutral, unverified results.
- Backup monitoring is opt-in through `maintenance.backup`; old configurations
  containing only `disabled_checks` continue to work.

### Added

- Versioned pre-release artifacts with checksums and clean wheel/sdist installation
  checks in CI. The version command reads the package's version constant.
- Arch `dotdoctor-git` packaging recipe with wheel installation, mocked build
  checks, optional system integrations, and submission instructions.
- Live audit results in fixed rows: completed checks show PASS/WARN/FAIL/OLD/SKIP and
  a short finding immediately, while other checks continue in parallel.
- Weekly maintenance checks for signing keys and Arch news, verified backup freshness,
  expected systemd jobs and TRIM, storage health and Btrfs scrub, known vulnerabilities,
  package database consistency, missing files and rebuild candidates.
- YAML configuration for existing backup adapters, expected timers and maintenance intervals.
- Upgrade preflight and postflight checks with explicit news review and keyring recovery.
- Confirmed maintenance actions with checks after completion; unavailable readers
  report findings and absent optional tools may omit checks.

### Fixed

- Authenticate before showing orphan-removal and cleanup progress. Capture command
  output and use noninteractive sudo so password prompts and pacman progress bars
  cannot be overwritten by the spinner; apply the same runner to other cleanups.
- Omit unconfigured backup monitoring and remove the NTP requirement from keyring
  checks. Use neutral SKIP for active timers without completion history and
  advisories without fixed-version data; retain details in verbose/JSON reports
  and keep confirmed failures actionable.
- Distinguish security advisories without fixed-version data from installed
  packages below published fixes; show post-update finding details and review
  commands instead of recommending repeated upgrades.
- Recover timer service completion from the systemd journal when inactive-service
  timestamps are discarded, and allow the keyring timer's weekly randomized delay.
- Show progress during silent TRIM, scrub, timer and backup actions and their
  verification; authenticate sudo outside live displays and reveal command failures.
- Allow Rich 15, used by current Arch packages, alongside Rich 14.
- Allow seven days between tmpfiles cleanup jobs and let configured timers
  override built-in entries by unit and scope without duplicate checks.
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
modes. This historical entry does not describe the current CLI.
See [README.md](README.md) and the 0.2.0-beta.1 entry above for current behavior.

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
