# Contributing to DotDoctor

The current project has three system-maintenance modes: `dotdoctor`, `--sysup`,
and `--fix`. Read [README.md](README.md) for supported behavior and
[AGENTS.md](AGENTS.md) for architecture, CLI design, and development safety rules.

## Development setup

From the repository root:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

## Validation

Use focused tests while developing, then run the required checks before submitting:

```bash
.venv/bin/pytest -v
.venv/bin/ruff check .
.venv/bin/black --check .
.venv/bin/mypy src
```

CI currently runs these checks on Python 3.11 and additionally requires at least
75% coverage through `pytest --cov=src/dotdoctor --cov-fail-under=75`.
Add tests for changed behavior and regressions; documentation-only changes do
not need new tests. Existing tests use mocks for system commands and harmless
helper processes for cancellation.

## Safe changes

- Do not run real updates or repairs during development or demos. Mock system
  readers and action commands; `dotdoctor --help` and `dotdoctor version` are safe
  direct CLI checks. The default command can offer real actions after its audit.
- Keep the three modes and fixed status design. Parallel audits should display
  real results, preserve row order, and remain cancellable without display delays.
- Do not turn failed/unverified checks into PASS or treat an omitted optional
  check as coverage. Verify completed fixes rather than trusting exit zero alone.
- Update relevant documentation and Unreleased notes when public behavior changes.
  Preserve historical records with an explicit historical label.

Use [the PR template](.github/PULL_REQUEST_TEMPLATE.md) to describe the problem,
resulting behavior, and observed validation. Packaging, real-environment checks,
and release preparation are tracked in [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
