"""
SQLAlchemy engine and session factory for AIAAP services.
All three services (ingest, detections, identity) import from here.

DATABASE_URL defaults to the docker-compose PostgreSQL instance.
Override via environment variable for local dev or other environments.
"""

import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql://aiaap:aiaap@postgres:5432/aiaap",
)

# pool_pre_ping=True drops dead connections automatically
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a DB session and closes it when done."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all_tables() -> None:
    """Create all ORM tables. Called at service startup."""
    from saas.services.shared import models  # noqa: F401 - ensures models are registered
    Base.metadata.create_all(bind=engine)
    _apply_column_migrations()


def _apply_column_migrations() -> None:
    """
    Idempotent ADD COLUMN migrations for columns added after initial schema.
    Uses IF NOT EXISTS so safe to run on every startup.
    Each entry: (table, column, type_sql, default_sql)
    """
    migrations = [
        # Phase 4: signal_source - separates lab signals from operational signals
        ("normalized_events",   "signal_source",         "VARCHAR(32) NOT NULL DEFAULT 'operational'", None),
        ("tool_usages",         "signal_source",         "VARCHAR(32) NOT NULL DEFAULT 'operational'", None),
        ("findings",            "signal_source",         "VARCHAR(32) NOT NULL DEFAULT 'operational'", None),
        # Phase 4: risk_score_updated_at - timestamp for last risk score computation
        ("agent_principals",    "risk_score_updated_at", "TIMESTAMP",                                  None),
        # Phase 7: connector tracking - which connector sent each event
        ("raw_events",          "connector_type",        "VARCHAR(32)",                                None),
        ("raw_events",          "connector_instance_id", "VARCHAR(255)",                               None),
        ("normalized_events",   "connector_type",        "VARCHAR(32)",                                None),
        ("normalized_events",   "connector_instance_id", "VARCHAR(255)",                               None),
    ]
    with engine.connect() as conn:
        for table, col, col_type, _ in migrations:
            try:
                conn.execute(
                    __import__("sqlalchemy").text(
                        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {col_type}"
                    )
                )
                conn.commit()
            except Exception:
                conn.rollback()
