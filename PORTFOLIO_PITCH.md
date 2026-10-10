# DotDoctor Pitch

## 30-second pitch

DotDoctor brings regular Arch Linux maintenance into three commands: a parallel
system audit, a sequential update workflow, and confirmed hygiene fixes. It checks
available updates, package/cache/configuration issues, scheduled maintenance,
storage health, backup freshness, and known package vulnerabilities when the
required tools are available. Results appear as each check finishes, with clear
statuses, suggested actions, and JSON export for audit/fix reports.

## Problems solved

- Repeating separate commands to check updates, disk space, failed services, and cache.
- Missing `.pacnew` files, stale maintenance jobs, or an unconfigured backup.
- Starting updates without reviewing Arch notices or detecting blocking findings.
- Waiting for the slowest check before seeing any useful result.

## Engineering highlights

- Layered architecture (CLI/application/domain/infrastructure).
- One prepared audit plan for progress and parallel execution; results retain plan order.
- Scoped subprocess groups that allow Ctrl+C to cancel audit readers, including news fetching.
- Fixed status rows: pending spinner becomes PASS/WARN/FAIL/OLD with the real finding.
- Pre/post-update checks, conditional snapshots, keyring preparation, and bounded recovery attempts.
- Interactive fixes with verification afterward; command success alone does not imply health.
- YAML configuration, XDG state, JSON reports, and CI with a 75% coverage gate.

## Admission-friendly talking points

- Demonstrates systems thinking: diagnosis, upgrade gates, confirmed actions, and rechecks.
- Demonstrates reliability focus: edge-case handling and explicit remediation.
- Demonstrates software engineering maturity: typing, linting, tests, CI, changelog, release checklist.

## Suggested demo flow (2-4 minutes)

Use mocked command readers for development demos; do not run package updates or
repairs on the host. See [CONTRIBUTING.md](CONTRIBUTING.md).

1. Show `dotdoctor --help` and explain the default, `--sysup`, and `--fix` modes.
2. Show a mocked audit with mixed statuses and one slow check; explain immediate results and cancellation.
3. Show [the illustrative JSON report](artifacts/example-report.json): OUTD maps to terminal OLD.
4. Explain a blocked update and a confirmed fix that is checked again afterward.

## Scope and evidence

The former dev-environment profiles and `scan` command are no longer available.
WARN/OUTD alone return zero in audit/fix mode; automation must inspect JSON findings
when it needs stricter policy. Missing optional tools can omit checks, and security
coverage is limited to Arch Security Tracker. Snapshots depend on configuration;
backups are not created automatically. Automated tests use mocks for system tools
and harmless helper processes for cancellation. They do not certify every real
Arch installation or guarantee recovery. See [README.md](README.md) for exact behavior.
