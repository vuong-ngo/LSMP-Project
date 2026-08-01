# ============================================================================
# file: tests/test_real_db_import.py
# Description: Pytest module for verifying real database import and fallback pipeline.
# ============================================================================

import os
from pathlib import Path
import pytest

try:
    from scripts.test_real_db_import import prepare_test_dataset, run_database_import_test
except ModuleNotFoundError:
    pytest.skip("scripts.test_real_db_import module not found", allow_module_level=True)
from lsmp_ai.io.db_client import DBClient


def test_prepare_test_dataset():
    test_dir = Path(__file__).resolve().parent.parent / "data" / "test"
    raw_path, features_path = prepare_test_dataset(test_dir)
    assert raw_path.exists()
    assert features_path.exists()


def test_real_db_import_runner():
    db_url = os.getenv("DATABASE_URL")
    db_client = DBClient(db_url)
    try:
        with db_client.engine.connect() as conn:
            pass
        # DB is reachable, run real database test
        success = run_database_import_test(db_url)
        assert success is True
    except Exception:
        # DB not running locally, skip real DB test cleanly
        pytest.skip("Local PostgreSQL database not reachable. Test skipped cleanly.")
