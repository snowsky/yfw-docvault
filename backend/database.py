"""Standalone DocVault database wiring."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


DATABASE_URL = os.environ.get(
    "DOCVAULT_DATABASE_URL",
    "postgresql://docvault:docvault_pass@db:5432/docvault",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class StandaloneUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False, unique=True, default="standalone@docvault.local")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


def init_db() -> None:
    import backend.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        user = db.query(StandaloneUser).filter(StandaloneUser.id == 1).first()
        if not user:
            db.add(StandaloneUser(id=1, email="standalone@docvault.local"))
            db.commit()
    finally:
        db.close()


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
