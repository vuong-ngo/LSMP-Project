import pandas as pd
import pytest
from unittest.mock import MagicMock, patch
from lsmp_ai.scripts.evaluate import run_evaluation


def test_run_evaluation_without_db_url(monkeypatch):
    """Test that evaluation utility cleanly returns False when DATABASE_URL is missing."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    success = run_evaluation(db_url=None)
    assert success is False


def test_run_evaluation_mocked(tmp_path):
    """Test evaluation utility with mocked DBClient."""
    with patch("lsmp_ai.scripts.evaluate.DBClient") as MockDBClient:
        mock_instance = MagicMock()
        mock_instance.db_url = "postgresql://postgres:postgres@localhost:5432/test_db"
        MockDBClient.return_value = mock_instance

        res = run_evaluation(
            db_url="postgresql://postgres:postgres@localhost:5432/test_db"
        )
        assert res is not False
        assert isinstance(res, pd.DataFrame)
