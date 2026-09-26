import os
import time
import logging
from typing import Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool, NullPool
from app.db.base import Base
from app.core.config import settings

logger = logging.getLogger("threatlens.database")

def get_database_url() -> str:
    """
    Determine the canonical database URL.
    Prefers explicit DATABASE_URL env var, then PostgreSQL in production/explicit mode,
    falling back to local SQLite for offline development.
    """
    explicit_url = os.getenv("DATABASE_URL")
    if explicit_url:
        return explicit_url

    if settings.ENVIRONMENT == "production" or os.getenv("USE_POSTGRES", "").lower() in ("true", "1"):
        return settings.DATABASE_URL

    return "sqlite:///./threatlens.db"

DATABASE_URL = get_database_url()
is_sqlite = DATABASE_URL.startswith("sqlite")
is_postgres = DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres")

if is_sqlite:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=NullPool
    )
else:
    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
_initialized = False

def setup_audit_immutability(conn):
    """
    Enforce database-level immutability triggers on the audit_log table.
    Blocks all UPDATE and DELETE operations directly inside the database engine.
    """
    try:
        if is_postgres:
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
                RETURNS TRIGGER AS $$
                BEGIN
                    RAISE EXCEPTION 'AuditLog records are append-only and cannot be updated or deleted.';
                END;
                $$ LANGUAGE plpgsql;
            """))
            conn.execute(text("""
                DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
                CREATE TRIGGER trg_audit_log_immutable
                BEFORE UPDATE OR DELETE ON audit_log
                FOR EACH ROW
                EXECUTE FUNCTION prevent_audit_log_modification();
            """))
        elif is_sqlite:
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
                BEFORE UPDATE ON audit_log
                BEGIN
                    SELECT RAISE(FAIL, 'AuditLog records are append-only and cannot be updated or deleted.');
                END;
            """))
            conn.execute(text("""
                CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
                BEFORE DELETE ON audit_log
                BEGIN
                    SELECT RAISE(FAIL, 'AuditLog records are append-only and cannot be updated or deleted.');
                END;
            """))
    except Exception as e:
        logger.warning(f"Could not apply audit immutability triggers: {e}")

def init_db():
    """Ensure all canonical models are registered and tables exist with immutability rules."""
    global _initialized
    import app.models  # Register all canonical models with Base metadata
    Base.metadata.create_all(bind=engine)

    with engine.begin() as conn:
        # 1. SQLite schema auto-migration helper
        if is_sqlite:
            for table_name, table in Base.metadata.tables.items():
                try:
                    res = conn.exec_driver_sql(f"PRAGMA table_info({table_name})")
                    existing_cols = {row[1] for row in res.fetchall()}
                    if not existing_cols:
                        continue
                    for col in table.columns:
                        if col.name not in existing_cols:
                            col_type = col.type.compile(engine.dialect)
                            conn.exec_driver_sql(f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}")
                except Exception:
                    pass

        # 2. Database-level audit log immutability
        setup_audit_immutability(conn)

    _initialized = True

def check_db_health() -> Dict[str, Any]:
    """Execute live DB probe and return health status without leaking secrets."""
    start_time = time.time()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "status": "healthy",
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "dialect": engine.dialect.name,
            "error": "Database connection failed"
        }

def get_db():
    """FastAPI dependency yielding a thread-safe scoped database session."""
    global _initialized
    if not _initialized:
        init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auto-initialize on import
try:
    init_db()
except Exception as _e:
    logger.warning(f"Database auto-initialization deferred: {_e}")

__all__ = [
    "engine",
    "SessionLocal",
    "Base",
    "get_db",
    "init_db",
    "check_db_health",
    "get_database_url",
    "setup_audit_immutability"
]
