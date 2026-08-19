# tests/conftest.py
import os
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.models import Base


@pytest.fixture(scope="function")
def db_engine(tmp_path):
    """Create a temporary SQLite database with all tables."""
    db_file = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def session_factory(db_engine):
    """Return a sessionmaker bound to the test engine."""
    return sessionmaker(bind=db_engine)


@pytest.fixture(scope="function")
def session(db_engine):
    """Provide a fresh session for each test."""
    from sqlalchemy.orm import Session

    with Session(db_engine) as s:
        yield s