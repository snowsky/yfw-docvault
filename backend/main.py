"""Standalone DocVault FastAPI application."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db
from backend.router import router


app = FastAPI(title="DocVault", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/plugin.json")
def plugin_manifest() -> dict:
    manifest_path = Path(__file__).resolve().parents[1] / "plugin.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


app.include_router(router, prefix="/api/v1/docvault", tags=["docvault"])
