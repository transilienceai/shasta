"""Shared test fixtures for Transilience Community Compliance."""

import pytest

from transilience_compliance.db.schema import ComplianceDB


@pytest.fixture
def db(tmp_path):
    """Provide a fresh SQLite database for each test."""
    db = ComplianceDB(db_path=tmp_path / "test.db")
    db.initialize()
    yield db
    db.close()
