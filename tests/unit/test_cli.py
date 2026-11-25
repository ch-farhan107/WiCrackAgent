"""CLI surface: help, version, dry-run plan, report generation."""

from typer.testing import CliRunner

from wicrack import __version__
from wicrack.cli import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_lists_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("serve", "crack", "scan", "bench", "report", "assets", "vault", "selftest"):
        assert command in result.output


def test_crack_dry_run_plan(settings, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    captures = tmp_path / "caps"
    captures.mkdir()
    (captures / "one.cap").write_bytes(b"x")
    result = runner.invoke(app, ["crack", "--dry-run", "--no-benchmark", "-f", str(captures)])
    assert result.exit_code == 0
    assert "one.cap" in result.output


def test_crack_empty_folder(settings, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    result = runner.invoke(app, ["crack", "--dry-run", "-f", str(empty)])
    assert result.exit_code == 0
    assert "No capture files" in result.output


def test_report_html_generation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", "--format", "html", "--engagement", "Test Audit"])
    assert result.exit_code == 0
    generated = list((tmp_path / "data" / "reports").glob("*.html"))
    assert generated and "Test Audit" in generated[0].read_text()


def test_assets_unknown_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["assets", "download", "doesnotexist"])
    assert result.exit_code != 0
