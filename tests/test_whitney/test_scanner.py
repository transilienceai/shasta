"""Tests for the Whitney code scanning orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from whitney.code.scanner import scan_repository, _clone_repo
from tests.test_whitney.conftest import write_file


class TestScanRepository:
    """Test scan_repository orchestrator."""

    def test_empty_repo_returns_empty(self, tmp_path):
        findings = scan_repository(tmp_path)
        assert findings == []

    def test_repo_with_vulnerable_code_returns_findings(self, tmp_path):
        write_file(
            tmp_path,
            "app.py",
            'api_key = "sk-abcdef1234567890abcdefghij"\n',
        )
        findings = scan_repository(tmp_path)
        assert len(findings) > 0
        check_ids = [f.check_id for f in findings]
        assert "code-ai-api-key-exposed" in check_ids

    def test_runs_all_15_checks_without_error(self, tmp_path):
        """All checks should run even on a complex repo."""
        write_file(
            tmp_path,
            "app.py",
            '''from flask import Flask, request
import openai

app = Flask(__name__)

@app.post("/chat")
def chat():
    msg = request.json["message"]
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Help: {msg}"}]
    )
    return response.choices[0].message.content
''',
        )
        write_file(tmp_path, "requirements.txt", "langchain==0.0.300\n")
        findings = scan_repository(tmp_path)
        assert len(findings) > 0

    def test_string_path_accepted(self, tmp_path):
        findings = scan_repository(str(tmp_path))
        assert isinstance(findings, list)

    def test_nonexistent_path_raises(self, tmp_path):
        bad_path = tmp_path / "nonexistent"
        with pytest.raises(FileNotFoundError, match="does not exist"):
            scan_repository(bad_path)

    def test_file_path_raises(self, tmp_path):
        fpath = tmp_path / "file.txt"
        fpath.write_text("hello")
        with pytest.raises(NotADirectoryError):
            scan_repository(fpath)


class TestScanRepositoryClone:
    """Test clone behavior of scan_repository."""

    @patch("whitney.code.scanner._clone_repo")
    def test_clones_when_path_missing_and_repo_given(self, mock_clone, tmp_path):
        dest = tmp_path / "cloned"
        mock_clone.side_effect = lambda *a, **kw: dest.mkdir()
        scan_repository(dest, github_repo="owner/repo", github_token="tok")
        mock_clone.assert_called_once_with("owner/repo", dest, token="tok")


class TestCloneRepo:
    """Test _clone_repo function."""

    @patch("whitney.code.scanner.subprocess.run")
    def test_constructs_url_without_token(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        dest = tmp_path / "repo"
        _clone_repo("owner/repo", dest)
        args = mock_run.call_args[0][0]
        assert "https://github.com/owner/repo.git" in args

    @patch("whitney.code.scanner.subprocess.run")
    def test_constructs_url_with_token(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0)
        dest = tmp_path / "repo"
        _clone_repo("owner/repo", dest, token="ghp_abc123")
        args = mock_run.call_args[0][0]
        url_arg = " ".join(args)
        assert "x-access-token:ghp_abc123@github.com" in url_arg

    @patch("whitney.code.scanner.subprocess.run")
    def test_raises_on_clone_failure(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=1, stderr="fatal: repo not found")
        dest = tmp_path / "repo"
        with pytest.raises(RuntimeError, match="Failed to clone"):
            _clone_repo("owner/repo", dest)

    @patch("whitney.code.scanner.subprocess.run")
    def test_sanitises_token_in_error(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="fatal: could not read ghp_secret from remote",
        )
        dest = tmp_path / "repo"
        with pytest.raises(RuntimeError) as exc_info:
            _clone_repo("owner/repo", dest, token="ghp_secret")
        assert "ghp_secret" not in str(exc_info.value)
        assert "***" in str(exc_info.value)
