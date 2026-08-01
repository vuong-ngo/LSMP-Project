# ============================================================================
# file: tests/test_export_db.py
# Description: Unit tests for database export script export_db.py
# ============================================================================

import os
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from lsmp_ai.scripts.export_db import export_models_to_db


def test_export_models_to_db_without_db_url(monkeypatch):
    """Test that export utility cleanly returns False when DATABASE_URL is not set."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    success = export_models_to_db(db_url=None)
    assert success is False


def test_export_models_to_db_mocked(tmp_path, monkeypatch):
    """Test export utility with mocked DBClient and catalog file."""
    catalog_data = {
        "latest_version": "cascade-v1.0",
        "cascade-v1.0": {
            "registered_at": "2026-07-28T22:00:00Z",
            "metrics": {
                "accuracy": 0.98,
                "precision": 0.96,
                "recall": 0.95,
                "f1_score": 0.955,
                "false_positive_rate": 0.02,
                "roc_auc": 0.99
            },
            "hyperparameters": {"contamination": 0.05}
        }
    }

    with patch("lsmp_ai.scripts.export_db.DBClient") as MockDBClient:
        mock_instance = MagicMock()
        mock_instance.db_url = "postgresql://postgres:postgres@localhost:5432/test_db"
        MockDBClient.return_value = mock_instance

        success = export_models_to_db(db_url="postgresql://postgres:postgres@localhost:5432/test_db")
        assert success is True
        assert mock_instance.write_evaluation_metrics.call_count >= 1
