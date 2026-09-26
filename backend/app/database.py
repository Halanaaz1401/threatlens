import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threatlens.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

_initialized = False

def init_db():
    """Ensure all canonical tables and columns exist in the database."""
    global _initialized
    import app.models  # Register all canonical models with Base metadata
    Base.metadata.create_all(bind=engine)
    if str(engine.url).startswith("sqlite"):
        with engine.begin() as conn:
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
    _initialized = True

def get_db():
    global _initialized
    if not _initialized:
        init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Ensure tables are created upon module import
try:
    init_db()
except Exception as _e:
    pass

__all__ = ["engine", "SessionLocal", "Base", "get_db", "init_db"]
