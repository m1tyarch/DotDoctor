from pathlib import Path

from typer.testing import CliRunner

from dotdoctor.cli.app import app
from dotdoctor.domain.models import CheckResult, ScanReport, Severity

runner = CliRunner()


def test_cli_scan_pass_exit_code(tmp_path: Path) -> None:
    config = tmp_path / "dotdoctor.yml"
    config.write_text(
        """
profiles:
  python-dev:
    enabled_checks:
      - path.integrity
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", "--config", str(config)], env={"PATH": "/usr/bin"})

    assert result.exit_code == 0


def test_cli_scan_warn_exit_code(tmp_path: Path) -> None:
    config = tmp_path / "dotdoctor.yml"
    config.write_text(
        """
profiles:
  python-dev:
    enabled_checks:
      - path.integrity
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", "--config", str(config)], env={"PATH": "/missing/path"})

    assert result.exit_code == 0


def test_cli_scan_fail_exit_code_for_missing_binary(tmp_path: Path) -> None:
    config = tmp_path / "dotdoctor.yml"
    config.write_text(
        """
profiles:
  python-dev:
    enabled_checks:
      - binary.supermissing
    required_binaries:
      - name: supermissing
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", "--config", str(config)], env={"PATH": "/usr/bin"})

    assert result.exit_code == 2


def test_cli_invalid_config_returns_runtime_error_code(tmp_path: Path) -> None:
    config = tmp_path / "invalid.yml"
    config.write_text("profiles: [", encoding="utf-8")

    result = runner.invoke(app, ["scan", "--config", str(config)], env={"PATH": "/usr/bin"})

    assert result.exit_code == 3


def test_cli_fix_updates_shell_config_and_creates_backup(tmp_path: Path) -> None:
    config = tmp_path / "dotdoctor.yml"
    config.write_text(
        """
profiles:
  python-dev:
    enabled_checks:
      - path.integrity
""".strip(),
        encoding="utf-8",
    )

    home = tmp_path / "home"
    home.mkdir()
    bashrc = home / ".bashrc"
    bashrc.write_text('export PATH="$PATH:/missing/path"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", "--config", str(config), "--fix", "--no-ui"],
        input="y\nbash\n",
        env={
            "PATH": "/usr/bin:/usr/bin:/missing/path",
            "HOME": str(home),
            "SHELL": "/bin/bash",
        },
    )

    assert result.exit_code == 0
    assert "FIXED" in result.stdout
    assert "DotDoctor Scan" not in result.stdout
    assert "[Y/n] [Y/n]" not in result.stdout
    assert "Duplicate PATH entries detected. Clean shell configuration now? [Y/n]:" in result.stdout
    assert (home / ".dotdoctor.fix.json").exists()
    assert (home / ".bashrc.bak").exists()
    updated = bashrc.read_text(encoding="utf-8")
    assert "# >>> dotdoctor path cleanup >>>" in updated
    assert 'export PATH="/usr/bin"' in updated


def test_cli_fix_prints_nothing_to_fix_without_table(tmp_path: Path) -> None:
    config = tmp_path / "dotdoctor.yml"
    config.write_text(
        """
profiles:
  python-dev:
    enabled_checks:
      - path.integrity
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan", "--config", str(config), "--fix", "--no-ui"],
        env={
            "PATH": "/usr/bin",
            "HOME": str(tmp_path),
            "SHELL": "/bin/bash",
        },
    )

    assert result.exit_code == 0
    assert "Nothing to fix. All checks are PASS." in result.stdout
    assert "DotDoctor Scan" not in result.stdout


def test_root_default_runs_dry_run_report(monkeypatch) -> None:
    def fake_run(self, context, on_task_complete=None):
        if on_task_complete:
            on_task_complete("sys.packages")
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.OUTD,
                    message="Found 2 updates",
                    remediation="run dotdoctor --sysup to apply updates",
                )
            ],
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )
    monkeypatch.setattr("dotdoctor.application.system_update.SystemDryRunService.run", fake_run)

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "DotDoctor · system" in result.stdout
    assert "sys.packages" in result.stdout


def test_root_sys_runs_dry_run_report(monkeypatch) -> None:
    def fake_run(self, context, on_task_complete=None):
        if on_task_complete:
            on_task_complete("sys.packages")
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.packages",
                    severity=Severity.OUTD,
                    message="Found 2 updates",
                    remediation="run dotdoctor --sysup to apply updates",
                )
            ],
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run_with_progress",
        fake_run,
    )
    monkeypatch.setattr("dotdoctor.application.system_update.SystemDryRunService.run", fake_run)

    result = runner.invoke(app, ["--sys"])

    assert result.exit_code == 0
    assert "DotDoctor · system" in result.stdout
    assert "sys.packages" in result.stdout


def test_root_env_runs_scan(monkeypatch) -> None:
    called = []

    def fake_scan(profile, config, disable_check, json_output, ui, fix):
        called.append((profile, ui, fix))
        import typer

        raise typer.Exit(code=0)

    monkeypatch.setattr("dotdoctor.cli.app._scan_impl", fake_scan)

    result = runner.invoke(app, ["--env"])
    assert result.exit_code == 0
    assert called == [("python-dev", True, False)]

    result_fix = runner.invoke(app, ["--env", "--fix"])
    assert result_fix.exit_code == 0
    assert called == [("python-dev", True, False), ("python-dev", True, True)]


def test_root_conflicting_options() -> None:
    result = runner.invoke(app, ["--env", "--sys"])
    assert result.exit_code != 0
    assert "Use either --env, --sys, or --sysup, not combined." in result.output

    result = runner.invoke(app, ["--env", "--sysup"])
    assert result.exit_code != 0
    assert "Use either --env, --sys, or --sysup, not combined." in result.output

    result = runner.invoke(app, ["--fix"])
    assert result.exit_code != 0
    assert "--fix requires --env." in result.output


def test_root_sysup_runs_upgrade(monkeypatch) -> None:
    def fake_run(self, context, console):
        console.print("System updater stub")
        return 0

    monkeypatch.setattr("dotdoctor.application.system_update.SystemUpgradeService.run", fake_run)

    result = runner.invoke(app, ["--sysup"])

    assert result.exit_code == 0
    assert "System updater stub" in result.stdout


def test_cli_typo_option_single_line_stderr() -> None:
    result = runner.invoke(app, ["--dev"])
    assert result.exit_code == 2
    assert result.output == "error: unknown option --dev. Did you mean --env?\n"
    assert "Usage:" not in result.output
    assert "Error" not in result.output


def test_cli_unknown_option_no_suggestion_single_line_stderr() -> None:
    result = runner.invoke(app, ["--completely-unrelated-unknown-option"])
    assert result.exit_code == 2
    assert result.output == (
        "error: unknown option --completely-unrelated-unknown-option. "
        "Run 'dotdoctor --help' for usage.\n"
    )
    assert "Usage:" not in result.output


def test_cli_disable_check_legacy_id_alias(tmp_path: Path) -> None:
    config = tmp_path / "dotdoctor.yml"
    config.write_text(
        """
profiles:
  python-dev:
    enabled_checks:
      - path.integrity
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["scan", "--config", str(config), "--disable-check", "path:integrity"],
        env={"PATH": "/usr/bin"},
    )
    assert result.exit_code == 0
    assert "path.integrity" not in result.stdout
