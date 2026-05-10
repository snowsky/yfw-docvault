"""Standalone DocVault sharing endpoints."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .auth import StandaloneUser, get_current_user
from .database import get_db
from .models import DocVaultEntry, DocVaultMFAEnrollment, DocVaultShareToken
from .router import _verify_mfa
from .schemas import DocVaultUnlockRequest

router = APIRouter(tags=["sharing"])

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5174")


class StandaloneShareTokenCreate(BaseModel):
    record_type: str = Field("docvault_item")
    record_id: int
    access_type: str = Field("public")
    expires_in_hours: int = Field(24, ge=1, le=8760)


class StandaloneShareTokenResponse(BaseModel):
    token: str
    record_type: str = "docvault_item"
    record_id: int
    share_url: str
    created_at: datetime
    expires_at: datetime | None = None
    is_active: bool
    access_type: str = "public"
    security_question: str | None = None
    one_time: bool = False
    access_count: int = 0
    max_access_count: int | None = None


class StandalonePublicDocVaultItem(BaseModel):
    record_type: str = "docvault_item"
    id: int
    category: str
    title: str | None = None
    owner_name: str | None = None
    issuer: str | None = None
    expiry_date: str | None = None
    issue_date: str | None = None
    public_metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    file_name: str | None = None
    file_mime_type: str | None = None
    file_size: int | None = None
    file_data_url: str | None = None
    sensitive_payload: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = None
    unlocked: bool = False
    created_at: datetime
    updated_at: datetime


class SharedUnlockMethod(BaseModel):
    factor_id: str
    label: str
    input_label: str
    placeholder: str
    input_type: str = "text"


def _share_url(token: str) -> str:
    return f"{FRONTEND_URL.rstrip('/')}/shared/{token}"


def _token_response(share: DocVaultShareToken) -> StandaloneShareTokenResponse:
    return StandaloneShareTokenResponse(
        token=share.token,
        record_id=share.entry_id,
        share_url=_share_url(share.token),
        created_at=share.created_at,
        expires_at=share.expires_at,
        is_active=share.is_active,
        access_count=share.access_count or 0,
    )


def _public_entry(entry: DocVaultEntry, reveal: bool = False) -> StandalonePublicDocVaultItem:
    metadata = dict(entry.public_metadata or {})
    cloud_integration = metadata.get("cloud_integration")
    if isinstance(cloud_integration, dict) and not reveal:
        metadata["cloud_integration"] = {
            key: cloud_integration.get(key)
            for key in ("provider", "provider_label", "file_name", "linked_at")
            if cloud_integration.get(key) is not None
        }
    return StandalonePublicDocVaultItem(
        id=entry.id,
        category=entry.category,
        title=entry.title,
        owner_name=entry.owner_name,
        issuer=entry.issuer,
        expiry_date=entry.expiry_date.isoformat() if entry.expiry_date else None,
        issue_date=entry.issue_date.isoformat() if entry.issue_date else None,
        public_metadata=metadata,
        tags=entry.tags or [],
        file_name=entry.file_name,
        file_mime_type=entry.file_mime_type,
        file_size=entry.file_size,
        file_data_url=entry.file_data_url if reveal else None,
        sensitive_payload=dict(entry.sensitive_payload or {}) if reveal else {},
        notes=entry.notes if reveal else None,
        unlocked=reveal,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


def _get_share_or_404(db: Session, token: str) -> DocVaultShareToken:
    share = db.query(DocVaultShareToken).filter(
        DocVaultShareToken.token == token,
        DocVaultShareToken.is_active.is_(True),
    ).first()
    if not share:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found or has been revoked")
    if share.expires_at and share.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="This link has expired")
    return share


def _get_shared_entry_or_404(db: Session, share: DocVaultShareToken) -> DocVaultEntry:
    entry = db.query(DocVaultEntry).filter(
        DocVaultEntry.id == share.entry_id,
        DocVaultEntry.is_archived.is_(False),
    ).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found")
    return entry


@router.post("/share-tokens/", response_model=StandaloneShareTokenResponse)
def create_share_token(
    payload: StandaloneShareTokenCreate,
    db: Session = Depends(get_db),
    current_user: StandaloneUser = Depends(get_current_user),
):
    if payload.record_type != "docvault_item":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Standalone DocVault can only share DocVault items")
    if payload.access_type != "public":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Standalone DocVault share links are public links")

    entry = db.query(DocVaultEntry).filter(
        DocVaultEntry.id == payload.record_id,
        DocVaultEntry.is_archived.is_(False),
    ).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DocVault entry not found")

    now = datetime.now(timezone.utc)
    share = DocVaultShareToken(
        token=uuid.uuid4().hex,
        entry_id=entry.id,
        created_by=current_user.id,
        created_at=now,
        expires_at=now + timedelta(hours=payload.expires_in_hours),
        access_count=0,
    )
    db.add(share)
    db.commit()
    db.refresh(share)
    return _token_response(share)


@router.get("/shared/{token}", response_model=StandalonePublicDocVaultItem)
def get_shared_record(token: str, db: Session = Depends(get_db)):
    share = _get_share_or_404(db, token)
    entry = _get_shared_entry_or_404(db, share)

    share.access_count = (share.access_count or 0) + 1
    db.add(share)
    db.commit()
    return _public_entry(entry)


@router.get("/shared/{token}/unlock-methods", response_model=list[SharedUnlockMethod])
def get_shared_unlock_methods(token: str, db: Session = Depends(get_db)):
    _get_share_or_404(db, token)
    labels = {
        "google_auth": ("Google Authenticator", "Authenticator code", "6-digit code", "text"),
        "ms_auth": ("Microsoft Authenticator", "Authenticator code", "6-digit code", "text"),
        "vault_password": ("Vault password", "Vault password", "Enter vault password", "password"),
        "recovery_code": ("Recovery code", "Recovery code", "Enter recovery code", "text"),
        "local_fallback": ("Local confirmation", "Confirmation", "Type UNLOCK", "text"),
    }
    enrollments = db.query(DocVaultMFAEnrollment).filter(
        DocVaultMFAEnrollment.user_id == 1,
        DocVaultMFAEnrollment.is_verified.is_(True),
    ).all()
    return [
        SharedUnlockMethod(
            factor_id=enrollment.factor_id,
            label=labels.get(enrollment.factor_id, (enrollment.factor_id, "Unlock value", "Enter unlock value", "text"))[0],
            input_label=labels.get(enrollment.factor_id, (enrollment.factor_id, "Unlock value", "Enter unlock value", "text"))[1],
            placeholder=labels.get(enrollment.factor_id, (enrollment.factor_id, "Unlock value", "Enter unlock value", "text"))[2],
            input_type=labels.get(enrollment.factor_id, (enrollment.factor_id, "Unlock value", "Enter unlock value", "text"))[3],
        )
        for enrollment in enrollments
    ]


@router.post("/shared/{token}/unlock", response_model=StandalonePublicDocVaultItem)
def unlock_shared_record(token: str, payload: DocVaultUnlockRequest, db: Session = Depends(get_db)):
    share = _get_share_or_404(db, token)
    entry = _get_shared_entry_or_404(db, share)
    _verify_mfa(db, StandaloneUser(), payload)
    share.access_count = (share.access_count or 0) + 1
    db.add(share)
    db.commit()
    return _public_entry(entry, reveal=True)
