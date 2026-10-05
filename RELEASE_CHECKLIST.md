# Release Checklist

This is a checklist for the current system-maintenance CLI, not evidence that a
release has already been validated. Keep items unchecked until results are recorded.
See [README.md](README.md) for behavior and [CONTRIBUTING.md](CONTRIBUTING.md) for safe testing.

## Versioning

- [ ] Version consistent in `pyproject.toml`, `src/dotdoctor/__init__.py`, and the `version` command in `src/dotdoctor/cli/app.py`.
- [ ] Changelog updated with release date and notable changes.
- [ ] Migration notes describe removed `scan`/dev-profile interfaces where relevant.

## Quality gates

- [ ] `.venv/bin/ruff check .`
- [ ] `.venv/bin/black --check .`
- [ ] `.venv/bin/mypy src`
- [ ] `.venv/bin/pytest -v --cov=src/dotdoctor --cov-fail-under=75`
- [ ] CI green on the exact commit being released. Current CI runs on Python 3.11.
- [ ] Validate the minimum supported Python and the current target Python version before claiming compatibility beyond CI coverage.

## Product checks

- [ ] `dotdoctor --help` and `dotdoctor version` match documented commands and version.
- [ ] Mocked default audit, `--sysup`, and `--fix` scenarios pass; no real system commands during development validation.
- [ ] Live results show actual statuses before slower checks finish, with stable row order and no artificial delays.
- [ ] Ctrl+C cancels audit process groups, restores the cursor, and returns 130.
- [ ] Static output works for pipes, dumb terminals, and animation/color opt-outs.
- [ ] JSON export works in default/fix modes; OUTD is preserved in JSON. Sysup currently has no JSON export.
- [ ] YAML/env/CLI configuration precedence and disabled checks match the README.
- [ ] WARN/OUTD without FAIL return 0; FAIL returns 2 in scan/fix mode. Validate handled config errors (3), upgrade failure paths (1/2/3), and invalid CLI arguments (2).
- [ ] Snapshot failure and blocking preflight findings stop updates; absent snapshot tooling is reported as SKIP.
- [ ] Ordinary no-update command outcomes do not produce false WARN/FAIL, including firmware actions during sysup.
- [ ] Backup absence is WARN, optional checks are not presented as verified when omitted, and failed services are preserved for diagnosis.

## Packaging and real-environment validation

- [ ] Build wheel and sdist and install each in a clean environment; verify entrypoint, imports, help, and version. These are not current CI steps.
- [ ] Validate real workflows only in an explicitly authorized disposable Arch/CachyOS VM or dedicated test system.
- [ ] Record configurations actually tested: filesystem, package/AUR helper, snapshots, Flatpak, and firmware tooling.
- [ ] Exercise no-update/update paths, missing tools, denied sudo, failed mirrors/snapshots, and cancellation. Mock hardware-specific actions when no test hardware is available.
- [ ] Review sysup command-specific exit handling and connectivity behavior before describing the release as stable.
- [ ] Do not claim that cancelling an upgrade rolls it back or that a snapshot is a verified independent backup.

## Documentation

- [ ] README, agent/contributor guides, portfolio pitch, and PR template match current behavior.
- [ ] Historical changelog and session notes are clearly separated from current instructions.
- [ ] Example JSON uses current system check IDs and is labeled illustrative.
- [ ] Demo uses mocks and explains coverage limits rather than promising complete system health.

## Release process

- [ ] Commit all intended source, tests, configuration examples, and documentation; inspect the working tree.
- [ ] Push the release commit and confirm the remote branch and CI results.
- [ ] Tag created (`vX.Y.Z`).
- [ ] Release notes include migration notes (if needed).
- [ ] Publish release notes/artifacts only after release checks are complete.
