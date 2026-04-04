"""CLI smoke tests."""

from transilience_compliance.cli import build_parser, main


def test_cli_help():
    help_text = build_parser().format_help()

    assert "transilience-compliance" in help_text
    assert "scan" in help_text


def test_cli_report_requires_scan(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    exit_code = main(["report"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "No stored scan found" in captured.err
