"""Shared test fixtures for Shasta."""

import pytest

from shasta.db.schema import ShastaDB


@pytest.fixture
def db(tmp_path):
    """Provide a fresh SQLite database for each test."""
    db = ShastaDB(db_path=tmp_path / "test.db")
    db.initialize()
    yield db
    db.close()
