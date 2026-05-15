import os
import subprocess
import sys


def test_cli_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "shasta.voice", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "voice console" in result.stdout.lower()


def test_cli_missing_api_key(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    db = tmp_path / "shasta.db"
    db.touch()
    result = subprocess.run(
        [sys.executable, "-m", "shasta.voice", "--db", str(db), "--no-open"],
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "OPENAI_API_KEY": ""},
    )
    assert result.returncode == 2
    assert "OPENAI_API_KEY" in result.stderr


def test_cli_missing_db(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    missing = tmp_path / "absent.db"
    result = subprocess.run(
        [sys.executable, "-m", "shasta.voice", "--db", str(missing), "--no-open"],
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "OPENAI_API_KEY": "sk-test"},
    )
    assert result.returncode == 2
    assert "No scan data" in result.stderr
