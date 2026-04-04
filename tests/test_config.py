"""Tests for config discovery and serialization."""

from pathlib import Path

from transilience_compliance.config import CONFIG_FILENAME, load_config, save_config


def test_save_and_load_config_round_trip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    saved_path = save_config(
        {
            "aws_profile": "compliance",
            "aws_region": "us-west-2",
            "company_name": "Transilience AI",
            "github_repos": ["transilienceai/communitytools"],
            "output_dir": "artifacts",
        }
    )

    loaded = load_config()

    assert saved_path == tmp_path / CONFIG_FILENAME
    assert loaded["aws_profile"] == "compliance"
    assert loaded["aws_region"] == "us-west-2"
    assert loaded["company_name"] == "Transilience AI"
    assert loaded["github_repos"] == ["transilienceai/communitytools"]
    assert loaded["output_dir"] == "artifacts"


def test_load_config_falls_back_to_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    loaded = load_config()

    assert loaded["aws_region"] == "us-east-1"
    assert loaded["output_dir"] == "data"
    assert Path(CONFIG_FILENAME).exists() is False
