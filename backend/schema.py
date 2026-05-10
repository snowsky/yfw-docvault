"""DocVault lightweight schema compatibility helpers."""

from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session


def ensure_docvault_schema(db: Session) -> None:
    """Apply small idempotent compatibility fixes for existing DocVault tables."""
    bind = db.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("docvault_entry_history"):
        return

    columns = {column["name"] for column in inspector.get_columns("docvault_entry_history")}
    if "snapshot" not in columns:
        db.execute(text("ALTER TABLE docvault_entry_history ADD COLUMN snapshot JSON"))
        db.commit()
