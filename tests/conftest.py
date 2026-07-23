import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app


@pytest.fixture()
def app(tmp_path: Path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(tmp_path / "test.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        }
    )
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()
