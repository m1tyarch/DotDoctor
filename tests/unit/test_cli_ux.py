import json
from pathlib import Path

from typer.testing import CliRunner

from dotdoctor import __version__
from dotdoctor.cli.app import app

runner = CliRunner()


def test_cli_version_flags() -> None:
    res_long = runner.invoke(app, ["--version"])
    assert res_long.exit_code == 0
    assert f"dotdoctor {__version__}" in res_long.output

    res_short = runner.invoke(app, ["-V"])
    assert res_short.exit_code == 0
    assert f"dotdoctor {__version__}" in res_short.output


def test_cli_help_flag_short() -> None:
    res = runner.invoke(app, ["-h"])
    assert res.exit_code == 0
    assert "DotDoctor: Minimalist Linux system diagnostic" in res.output
    assert "Examples:" in res.output


def test_cli_config_not_found_errors_to_stderr(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yml"
    res = runner.invoke(app, ["-c", str(missing)])
    assert res.exit_code == 3
    assert "Config file not found:" in res.output
    assert str(missing) in res.output.replace("\n", "")


def test_cli_json_flag_stdout(monkeypatch) -> None:
    from dotdoctor.domain.models import CheckResult, ScanReport, Severity

    def fake_run(self, context, disabled_checks=None):
        return ScanReport(
            profile="system",
            results=[
                CheckResult(
                    check_id="sys.test",
                    severity=Severity.PASS,
                    message="ok",
                )
            ],
        )

    monkeypatch.setattr(
        "dotdoctor.application.system_update.SystemDryRunService.run",
        fake_run,
    )

    res = runner.invoke(app, ["--json"])
    assert res.exit_code == 0

    data = json.loads(res.output)
    assert data["schema_version"] == "1.0"
    assert data["dotdoctor_version"] == __version__
    assert data["summary"] == {"PASS": 1, "OUTD": 0, "WARN": 0, "FAIL": 0, "SKIP": 0}
    assert data["exit_code"] == 0
    assert len(data["results"]) == 1
    assert data["results"][0]["check_id"] == "sys.test"
