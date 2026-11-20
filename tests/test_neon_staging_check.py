"""Offline tests for the read-only Neon schema inspector and fail-closed guard."""
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from project_x.server.db import engine_for
from scripts.check_neon_staging import StagingCheckError, check_schema, verify_target


def test_verify_target_rejects_production_or_insecure_urls():
    with pytest.raises(StagingCheckError):
        verify_target("postgresql+psycopg://u:secret@ep-falling-bird-bdgbs39b.c-8.us-east-2.aws.neon.tech/neondb?sslmode=require")
    with pytest.raises(StagingCheckError):
        verify_target("postgresql+psycopg://u:secret@ep-crimson-cherry-bdz9jf81.c-8.us-east-2.aws.neon.tech/neondb")
    with pytest.raises(StagingCheckError):
        verify_target("sqlite:///./test.db")


def test_staging_schema_check_and_revision_guard(tmp_path, monkeypatch):
    db_url = f"sqlite:///{tmp_path / 'staging_check.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("CODE_PEPPER", "A" * 40)
    monkeypatch.setenv("TOKEN_PEPPER", "B" * 40)
    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    command.upgrade(cfg, "head")
    engine = engine_for(db_url)
    try:
        report = check_schema(engine)
        assert report["status"] == "pass"
        assert report["revision"] == "c8ad20261120"
        assert report["foreign_key_count"] >= 14
        with engine.begin() as conn:
            conn.execute(text("UPDATE alembic_version SET version_num='bad-version'"))
        with pytest.raises(StagingCheckError):
            check_schema(engine)
    finally:
        engine.dispose()
