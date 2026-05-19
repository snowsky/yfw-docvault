"""DocVault API router."""

from __future__ import annotations

import re
import hashlib
import base64
import hmac
import io
import os
import secrets
import struct
import time
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

try:
    from core.models.database import get_db
    from core.models.models import MasterUser
    from core.models.models_per_tenant import User as TenantUser
    from core.routers.auth import get_current_user
    from core.utils.audit import log_audit_event

    IS_PLUGIN_MODE = True
except ModuleNotFoundError:
    from .auth import StandaloneUser as MasterUser
    from .auth import get_current_user
    from .database import StandaloneUser as TenantUser
    from .database import get_db

    IS_PLUGIN_MODE = False

    def log_audit_event(**kwargs):
        return None

from .models import (
    DocVaultAttachmentLocator,
    DocVaultAttachmentVersion,
    DocVaultDocumentLink,
    DocVaultEntry,
    DocVaultEntryHistory,
    DocVaultMFAEnrollment,
    DocVaultSignature,
)
from .schema import ensure_docvault_schema
from .schemas import (
    DocVaultAttachmentVersionCreate,
    DocVaultAttachmentVersionResponse,
    DocVaultAuditPackageRequest,
    DocVaultAuditPackageResponse,
    DocVaultCloudLinkRequest,
    DocVaultCopyEventRequest,
    DocVaultDocumentLinkCreate,
    DocVaultDocumentLinkResponse,
    DocVaultEntryCreate,
    DocVaultEntryHistoryResponse,
    DocVaultEntryResponse,
    DocVaultEntryUpdate,
    DocVaultMFAEnrollmentResponse,
    DocVaultLocalUnlockSetupRequest,
    DocVaultMFASetupRequest,
    DocVaultMFASetupResponse,
    DocVaultMFAVerifyRequest,
    DocVaultSystemMFAStatusResponse,
    DocVaultImportCandidate,
    DocVaultImportRunRequest,
    DocVaultImportRunResponse,
    DocVaultImportScanRequest,
    DocVaultImportScanResponse,
    DocVaultImportSummary,
    DocVaultRetentionRunResponse,
    DocVaultRestoreResponse,
    DocVaultScanRequest,
    DocVaultScanResponse,
    DocVaultSignatureCreate,
    DocVaultSignatureResponse,
    DocVaultUnlockRequest,
    VALID_OWNER_TYPES,
)

router = APIRouter()

DOCUMENT_LABELS = {"unclassified", "confidential", "finance", "legal", "hr", "identity", "tax", "vendor", "audit"}
DOCUMENT_APPROVAL_STATUSES = {"draft", "review_requested", "approved", "rejected", "needs_changes"}


def _metadata_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _warning_days(category: str) -> int:
    return 60 if category == "credit_card" else 30


def _expiry_status(category: str, expiry_date: date | None) -> tuple[str, int | None, bool]:
    if not expiry_date:
        return "valid", None, False
    today = date.today()
    days = (expiry_date - today).days
    if days < 0:
        return "expired", days, True
    if days <= _warning_days(category):
        return "expiring_soon", days, True
    return "valid", days, False


def _mask_entry_payload(category: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(payload or {})
    if category == "credit_card":
        number = re.sub(r"\D", "", str(payload.get("card_number") or payload.get("full_number") or ""))
        payload.pop("card_number", None)
        payload.pop("full_number", None)
        payload["last4"] = payload.get("last4") or (number[-4:] if number else "")
    else:
        for key in ("password", "private_key", "secret", "recovery_codes", "document_data"):
            payload.pop(key, None)
    return payload


def _password_fingerprint(password: str | None) -> str | None:
    if not password:
        return None
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _password_score(password: str | None) -> int:
    if not password:
        return 0
    score = 0
    length = len(password)
    if length >= 8:
        score += 20
    if length >= 12:
        score += 20
    if length >= 16:
        score += 15
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 15
    if re.search(r"\d", password):
        score += 10
    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    if len(set(password)) >= min(8, length):
        score += 5
    if re.fullmatch(r"[A-Za-z]+", password or "") or re.fullmatch(r"\d+", password or ""):
        score -= 20
    return max(0, min(score, 100))


def _secret_health(entry: DocVaultEntry, *, reused_password: bool = False) -> dict[str, Any] | None:
    if entry.category != "secret":
        return None

    metadata = dict(entry.public_metadata or {})
    payload = dict(entry.sensitive_payload or {})
    password = str(payload.get("password") or "")
    score = _password_score(password)
    issues: list[dict[str, str]] = []

    if not password:
        issues.append({"id": "missing_password", "label": "Missing password", "severity": "high"})
    elif score < 60:
        issues.append({"id": "weak_password", "label": "Weak password", "severity": "high"})
    elif score < 80:
        issues.append({"id": "could_be_stronger", "label": "Could be stronger", "severity": "medium"})

    if password and reused_password:
        issues.append({"id": "reused_password", "label": "Reused password", "severity": "high"})

    password_updated_at = metadata.get("password_updated_at")
    rotation_days = int(metadata.get("rotation_interval_days") or 180)
    days_since_rotation = None
    if password_updated_at:
        try:
            updated = date.fromisoformat(str(password_updated_at)[:10])
            days_since_rotation = (date.today() - updated).days
            if days_since_rotation > rotation_days:
                issues.append({"id": "rotation_overdue", "label": "Rotation overdue", "severity": "medium"})
        except ValueError:
            issues.append({"id": "rotation_unknown", "label": "Rotation date invalid", "severity": "medium"})
    elif password:
        issues.append({"id": "rotation_unknown", "label": "Rotation date missing", "severity": "low"})

    if not metadata.get("username"):
        issues.append({"id": "missing_username", "label": "Missing username", "severity": "low"})
    if not metadata.get("login_url"):
        issues.append({"id": "missing_login_url", "label": "Missing login URL", "severity": "low"})

    high_count = sum(1 for issue in issues if issue["severity"] == "high")
    medium_count = sum(1 for issue in issues if issue["severity"] == "medium")
    status_name = "healthy"
    if high_count:
        status_name = "at_risk"
    elif medium_count:
        status_name = "needs_review"

    return {
        "score": score,
        "status": status_name,
        "issues": issues,
        "days_since_rotation": days_since_rotation,
        "rotation_interval_days": rotation_days,
    }


def _checksum(data: str | None) -> str:
    return hashlib.sha256((data or "").encode("utf-8")).hexdigest()


def _normalize_unlock_secret(value: str) -> str:
    return value.strip()


def _hash_unlock_secret(value: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{_normalize_unlock_secret(value)}".encode("utf-8")).hexdigest()


def _local_secret_payload(values: list[str]) -> dict[str, Any]:
    salt = secrets.token_hex(16)
    normalized = [_normalize_unlock_secret(value) for value in values if _normalize_unlock_secret(value)]
    return {
        "salt": salt,
        "hashes": [_hash_unlock_secret(value, salt) for value in normalized],
    }


def _parse_local_secret_payload(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {"salt": "", "hashes": []}
    if not raw.startswith("{"):
        return {"salt": "", "hashes": [raw]}
    try:
        import json

        parsed = json.loads(raw)
    except Exception:
        return {"salt": "", "hashes": []}
    return {
        "salt": str(parsed.get("salt") or ""),
        "hashes": [str(value) for value in parsed.get("hashes") or []],
    }


def _verify_local_secret(enrollment: DocVaultMFAEnrollment, value: str) -> bool:
    payload = _parse_local_secret_payload(enrollment.secret)
    salt = payload.get("salt") or ""
    if not salt:
        return False
    candidate = _hash_unlock_secret(value, salt)
    return any(hmac.compare_digest(candidate, saved) for saved in payload.get("hashes") or [])


def _provider_label(provider: str) -> str:
    return {"google_drive": "Google Drive", "onedrive": "OneDrive"}.get(provider, provider)


def _normalize_cloud_link(payload: DocVaultCloudLinkRequest) -> dict[str, Any]:
    url = payload.file_url.strip()
    hostname = (urlparse(url).hostname or "").lower()
    if payload.provider == "google_drive" and hostname not in {"drive.google.com", "docs.google.com"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Google Drive links must use drive.google.com or docs.google.com")
    if payload.provider == "onedrive" and hostname not in {"onedrive.live.com", "1drv.ms"} and not hostname.endswith(".sharepoint.com"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OneDrive links must use onedrive.live.com, 1drv.ms, or sharepoint.com")
    return {
        "provider": payload.provider,
        "provider_label": _provider_label(payload.provider),
        "file_url": url,
        "file_id": payload.file_id,
        "file_name": payload.file_name,
        "linked_at": datetime.now(timezone.utc).isoformat(),
    }


def _normalize_document_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(metadata)
    label = normalized.get("document_label")
    approval_status = normalized.get("approval_status")
    if label and label not in DOCUMENT_LABELS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown document label")
    if approval_status and approval_status not in DOCUMENT_APPROVAL_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown approval status")
    normalized["approval_status"] = approval_status or "draft"
    return normalized


def _is_immutable(entry: DocVaultEntry) -> bool:
    return bool((entry.public_metadata or {}).get("immutable"))


def _ensure_mutable(entry: DocVaultEntry) -> None:
    if _is_immutable(entry):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This DocVault item is immutable")


def _document_workflow(entry: DocVaultEntry) -> dict[str, Any] | None:
    if entry.category != "document":
        return None
    metadata = dict(entry.public_metadata or {})
    return {
        "document_label": metadata.get("document_label"),
        "approval_status": metadata.get("approval_status") or "draft",
    }


def _version_response(version: DocVaultAttachmentVersion) -> DocVaultAttachmentVersionResponse:
    return DocVaultAttachmentVersionResponse(
        id=version.id,
        entry_id=version.entry_id,
        version=version.version,
        file_name=version.file_name,
        file_mime_type=version.file_mime_type,
        file_size=version.file_size,
        file_data_url=version.file_data_url,
        checksum_sha256=version.checksum_sha256,
        change_note=version.change_note,
        is_current=version.is_current,
        created_by=version.created_by,
        created_at=version.created_at,
    )


def _history_response(history: DocVaultEntryHistory) -> DocVaultEntryHistoryResponse:
    return DocVaultEntryHistoryResponse(
        id=history.id,
        entry_id=history.entry_id,
        action=history.action,
        changed_fields=history.changed_fields or [],
        details=history.details or {},
        restorable=bool(history.snapshot),
        created_by=history.created_by,
        created_at=history.created_at,
    )


def _signature_response(signature: DocVaultSignature) -> DocVaultSignatureResponse:
    return DocVaultSignatureResponse(
        id=signature.id,
        entry_id=signature.entry_id,
        signer_name=signature.signer_name,
        signer_email=signature.signer_email,
        provider=signature.provider,
        status=signature.status,
        signature_reference=signature.signature_reference,
        signed_payload=signature.signed_payload or {},
        created_by=signature.created_by,
        signed_at=signature.signed_at,
        created_at=signature.created_at,
    )


def _public_metadata_for_response(entry: DocVaultEntry, reveal: bool) -> dict[str, Any]:
    metadata = dict(entry.public_metadata or {})
    cloud_integration = metadata.get("cloud_integration")
    if reveal or not isinstance(cloud_integration, dict):
        return metadata

    metadata["cloud_integration"] = {
        key: cloud_integration.get(key)
        for key in ("provider", "provider_label", "file_name", "linked_at")
        if cloud_integration.get(key) is not None
    }
    return metadata


def _has_sensitive_material(entry: DocVaultEntry) -> bool:
    cloud_integration = (entry.public_metadata or {}).get("cloud_integration")
    return bool(
        entry.sensitive_payload
        or entry.file_data_url
        or entry.notes
        or (isinstance(cloud_integration, dict) and cloud_integration.get("file_url"))
    )


def _serialize(entry: DocVaultEntry, reveal: bool = False, reused_password: bool = False) -> DocVaultEntryResponse:
    status_name, days_delta, alerting = _expiry_status(entry.category, entry.expiry_date)
    payload = dict(entry.sensitive_payload or {}) if reveal else _mask_entry_payload(entry.category, entry.sensitive_payload)
    return DocVaultEntryResponse(
        id=entry.id,
        category=entry.category,
        title=entry.title,
        owner_name=entry.owner_name,
        issuer=entry.issuer,
        expiry_date=entry.expiry_date,
        issue_date=entry.issue_date,
        public_metadata=_public_metadata_for_response(entry, reveal),
        sensitive_payload=payload,
        notes=entry.notes if reveal else None,
        tags=entry.tags or [],
        thumbnail_data_url=entry.thumbnail_data_url,
        file_name=entry.file_name,
        file_mime_type=entry.file_mime_type,
        file_size=entry.file_size,
        file_data_url=entry.file_data_url if reveal else None,
        created_by=entry.created_by,
        is_archived=entry.is_archived,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
        expiry_status=status_name,
        days_delta=days_delta,
        alerting=alerting,
        sensitive_available=_has_sensitive_material(entry),
        secret_health=_secret_health(entry, reused_password=reused_password),
        attachment_versions_count=0,
        signatures_count=0,
    )


def _password_reuse_counts(entries: list[DocVaultEntry]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        if entry.category != "secret":
            continue
        fingerprint = _password_fingerprint((entry.sensitive_payload or {}).get("password"))
        if fingerprint:
            counts[fingerprint] = counts.get(fingerprint, 0) + 1
    return counts


def _is_reused_secret(entry: DocVaultEntry, fingerprint_counts: dict[str, int] | None = None) -> bool:
    fingerprint = _password_fingerprint((entry.sensitive_payload or {}).get("password") if entry.category == "secret" else None)
    return bool(fingerprint and (fingerprint_counts or {}).get(fingerprint, 0) > 1)


def _serialize_with_counts(
    db: Session,
    entry: DocVaultEntry,
    reveal: bool = False,
    fingerprint_counts: dict[str, int] | None = None,
) -> DocVaultEntryResponse:
    response = _serialize(entry, reveal=reveal, reused_password=_is_reused_secret(entry, fingerprint_counts))
    response.attachment_versions_count = db.query(DocVaultAttachmentVersion).filter(
        DocVaultAttachmentVersion.entry_id == entry.id
    ).count()
    response.signatures_count = db.query(DocVaultSignature).filter(DocVaultSignature.entry_id == entry.id).count()
    return response


def _normalize_owner_type(owner_type: str) -> str:
    normalized = owner_type.strip().lower()
    if normalized not in VALID_OWNER_TYPES:
        allowed = ", ".join(sorted(VALID_OWNER_TYPES))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported owner_type. Expected one of: {allowed}",
        )
    return normalized


def _link_response(db: Session, link: DocVaultDocumentLink) -> DocVaultDocumentLinkResponse:
    entry = db.query(DocVaultEntry).filter(DocVaultEntry.id == link.entry_id).first()
    return DocVaultDocumentLinkResponse(
        id=link.id,
        entry_id=link.entry_id,
        owner_type=link.owner_type,
        owner_id=link.owner_id,
        linked_by=link.linked_by,
        created_at=link.created_at,
        entry_title=entry.title if entry else None,
        entry_category=entry.category if entry else None,
        file_name=entry.file_name if entry else None,
    )


def _sort_key(entry: DocVaultEntry) -> tuple[int, int]:
    status_name, days_delta, _ = _expiry_status(entry.category, entry.expiry_date)
    bucket = {"expired": 0, "expiring_soon": 1, "valid": 2}.get(status_name, 3)
    return bucket, days_delta if days_delta is not None else 999999


def _get_entry_or_404(db: Session, entry_id: int) -> DocVaultEntry:
    entry = db.query(DocVaultEntry).filter(DocVaultEntry.id == entry_id, DocVaultEntry.is_archived.is_(False)).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DocVault entry not found")
    return entry


def _totp_code(secret: str, counter: int) -> str:
    key = base64.b32decode(secret.upper())
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def _verify_totp(secret: str, code: str, window: int = 1) -> bool:
    normalized = re.sub(r"\s", "", code)
    counter = int(time.time() // 30)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_totp_code(secret, counter + drift), normalized):
            return True
    return False


def _otpauth_uri(secret: str, *, label: str, issuer: str = "DocVault") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(label)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def _qr_data_url(value: str) -> str | None:
    try:
        import qrcode
    except ModuleNotFoundError:
        return None
    image = qrcode.make(value)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _mfa_response(enrollment: DocVaultMFAEnrollment) -> DocVaultMFAEnrollmentResponse:
    recovery_code_count = 0
    if enrollment.factor_id == "recovery_code":
        recovery_code_count = len(_parse_local_secret_payload(enrollment.secret).get("hashes") or [])
    return DocVaultMFAEnrollmentResponse(
        factor_id=enrollment.factor_id,
        label=enrollment.label,
        is_verified=enrollment.is_verified,
        recovery_code_count=recovery_code_count,
        created_at=enrollment.created_at,
        verified_at=enrollment.verified_at,
    )


def _user_for_system_mfa(db: Session, current_user: MasterUser):
    try:
        return db.query(TenantUser).filter(TenantUser.id == current_user.id).first() or current_user
    except Exception:
        return current_user


def _system_mfa_status(db: Session, current_user: MasterUser) -> DocVaultSystemMFAStatusResponse:
    try:
        from commercial.mfa_chain.utils import get_user_mfa_settings
    except ModuleNotFoundError:
        return DocVaultSystemMFAStatusResponse(
            available=False,
            enabled=False,
            configured=False,
            message="System MFA is not available in this DocVault deployment. Configure a DocVault unlock method before revealing sensitive details.",
        )

    settings = get_user_mfa_settings(_user_for_system_mfa(db, current_user))
    enabled = bool(settings.get("enabled"))
    enrolled_factors = list(settings.get("enrolled_factors") or [])
    factors = list(settings.get("factors") or [])
    configured = enabled and bool(enrolled_factors) and all(factor_id in enrolled_factors for factor_id in factors)
    if configured:
        message = "DocVault is using system MFA for sensitive unlocks."
    elif enabled:
        message = "System MFA is enabled but incomplete. Finish authenticator enrollment or disable MFA with the admin script."
    else:
        message = "System MFA is not enabled. Configure MFA in your profile, enroll a DocVault authenticator, or use the admin script to disable MFA."

    return DocVaultSystemMFAStatusResponse(
        available=True,
        enabled=enabled,
        configured=configured,
        mode=settings.get("mode"),
        factors=factors,
        enrolled_factors=enrolled_factors,
        supported_factors=list(settings.get("supported_factors") or []),
        message=message,
    )


def _latest_version_number(db: Session, entry_id: int) -> int:
    latest = (
        db.query(DocVaultAttachmentVersion)
        .filter(DocVaultAttachmentVersion.entry_id == entry_id)
        .order_by(DocVaultAttachmentVersion.version.desc())
        .first()
    )
    return latest.version if latest else 0


def _create_attachment_version(
    db: Session,
    entry: DocVaultEntry,
    *,
    file_name: str | None,
    file_mime_type: str | None,
    file_size: int | None,
    file_data_url: str | None,
    change_note: str | None,
    user_id: int | None,
    checksum_sha256: str | None = None,
) -> DocVaultAttachmentVersion | None:
    if not file_name and not file_data_url:
        return None

    db.query(DocVaultAttachmentVersion).filter(DocVaultAttachmentVersion.entry_id == entry.id).update({"is_current": False})
    version = DocVaultAttachmentVersion(
        entry_id=entry.id,
        version=_latest_version_number(db, entry.id) + 1,
        file_name=file_name or entry.file_name or f"docvault-entry-{entry.id}",
        file_mime_type=file_mime_type or entry.file_mime_type,
        file_size=file_size if file_size is not None else entry.file_size,
        file_data_url=file_data_url or entry.file_data_url,
        checksum_sha256=checksum_sha256 or _checksum(file_data_url or entry.file_data_url),
        change_note=change_note,
        is_current=True,
        created_by=user_id,
    )
    db.add(version)
    return version


def _snapshot_date(value: date | None) -> str | None:
    return value.isoformat() if value else None


def _parse_snapshot_date(value: Any) -> date | None:
    if not value:
        return None
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


def _entry_snapshot(entry: DocVaultEntry) -> dict[str, Any]:
    return {
        "category": entry.category,
        "title": entry.title,
        "owner_name": entry.owner_name,
        "issuer": entry.issuer,
        "expiry_date": _snapshot_date(entry.expiry_date),
        "issue_date": _snapshot_date(entry.issue_date),
        "public_metadata": dict(entry.public_metadata or {}),
        "sensitive_payload": dict(entry.sensitive_payload or {}),
        "notes": entry.notes,
        "tags": list(entry.tags or []),
        "thumbnail_data_url": entry.thumbnail_data_url,
        "file_name": entry.file_name,
        "file_mime_type": entry.file_mime_type,
        "file_size": entry.file_size,
        "file_data_url": entry.file_data_url,
    }


def _restore_entry_snapshot(entry: DocVaultEntry, snapshot: dict[str, Any]) -> None:
    entry.category = snapshot.get("category") or entry.category
    entry.title = snapshot.get("title") or entry.title
    entry.owner_name = snapshot.get("owner_name")
    entry.issuer = snapshot.get("issuer")
    entry.expiry_date = _parse_snapshot_date(snapshot.get("expiry_date"))
    entry.issue_date = _parse_snapshot_date(snapshot.get("issue_date"))
    entry.public_metadata = dict(snapshot.get("public_metadata") or {})
    entry.sensitive_payload = dict(snapshot.get("sensitive_payload") or {})
    entry.notes = snapshot.get("notes")
    entry.tags = list(snapshot.get("tags") or [])
    entry.thumbnail_data_url = snapshot.get("thumbnail_data_url")
    entry.file_name = snapshot.get("file_name")
    entry.file_mime_type = snapshot.get("file_mime_type")
    entry.file_size = snapshot.get("file_size")
    entry.file_data_url = snapshot.get("file_data_url")


def _changed_snapshot_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return sorted(key for key, value in after.items() if before.get(key) != value)


def _record_entry_history(
    db: Session,
    entry: DocVaultEntry,
    *,
    action: str,
    changed_fields: list[str],
    user_id: int | None,
    details: dict[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
) -> DocVaultEntryHistory:
    history = DocVaultEntryHistory(
        entry_id=entry.id,
        action=action,
        changed_fields=sorted(set(changed_fields)),
        details=details or {},
        snapshot=snapshot if snapshot is not None else _entry_snapshot(entry),
        created_by=user_id,
    )
    db.add(history)
    return history


def _verify_mfa(db: Session, current_user: MasterUser, payload: DocVaultUnlockRequest) -> None:
    local_unlock_factors = {"local_fallback", "vault_password", "recovery_code"}

    try:
        from commercial.mfa_chain.utils import get_user_mfa_settings, verify_factor_enrollment
    except ModuleNotFoundError:
        get_user_mfa_settings = None
        verify_factor_enrollment = None

    if get_user_mfa_settings and verify_factor_enrollment:
        user_for_mfa = _user_for_system_mfa(db, current_user)
        settings = get_user_mfa_settings(user_for_mfa)
    else:
        settings = {"enabled": False, "factors": [], "enrolled_factors": []}

    system_configured = bool(settings.get("enabled")) and bool(settings.get("enrolled_factors")) and all(
        factor_id in settings.get("enrolled_factors", []) for factor_id in settings.get("factors", [])
    )
    if system_configured:
        if payload.factor_id in local_unlock_factors:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Use an enrolled MFA factor for this vault")
        if payload.factor_id not in settings.get("enrolled_factors", []):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authenticator is not enrolled")
        if not verify_factor_enrollment(user_for_mfa, payload.factor_id, payload.user_input, payload.window):  # type: ignore[misc]
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authenticator code")
        return

    if settings.get("enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System MFA is enabled but incomplete. Finish enrollment or disable MFA before unlocking DocVault.",
        )

    enrollment = db.query(DocVaultMFAEnrollment).filter(
        DocVaultMFAEnrollment.user_id == current_user.id,
        DocVaultMFAEnrollment.factor_id == payload.factor_id,
        DocVaultMFAEnrollment.is_verified.is_(True),
    ).first()
    if enrollment:
        if payload.factor_id in local_unlock_factors:
            if _verify_local_secret(enrollment, payload.user_input):
                return
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid unlock secret")
        if _verify_totp(enrollment.secret, payload.user_input, payload.window):
            return
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authenticator code")

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This unlock method is not configured")


def _host_statement_models():
    try:
        from core.models.models_per_tenant import BankStatement, BankStatementAttachment
    except ModuleNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Attachment import scanning is available only in invoice_app plugin mode",
        )
    return BankStatement, BankStatementAttachment


def _host_document_models():
    try:
        from core.models.models_per_tenant import Expense, ExpenseAttachment, InventoryItem, Invoice, InvoiceAttachment, ItemAttachment
    except ModuleNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Attachment import scanning is available only in invoice_app plugin mode",
        )
    return Invoice, InvoiceAttachment, Expense, ExpenseAttachment, InventoryItem, ItemAttachment


def _host_portfolio_models():
    try:
        from plugins.investments.models import FileAttachment, InvestmentPortfolio
    except ModuleNotFoundError:
        return None, None
    return InvestmentPortfolio, FileAttachment


def _current_tenant_id(current_user: MasterUser) -> int | None:
    try:
        from core.models.database import get_tenant_context

        tenant_id = get_tenant_context()
        if tenant_id:
            return tenant_id
    except Exception:
        pass
    return getattr(current_user, "tenant_id", None)


def _infer_mime_type(filename: str | None, fallback: str | None = None) -> str | None:
    if fallback:
        return fallback
    name = (filename or "").lower()
    if name.endswith(".pdf"):
        return "application/pdf"
    if name.endswith(".csv"):
        return "text/csv"
    return None


def _local_file_size(path: str | None) -> int | None:
    if not path:
        return None
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _storage_provider(storage_key: str | None, cloud_url: str | None = None) -> str:
    if cloud_url:
        return "cloud"
    if not storage_key:
        return "local"
    if os.path.isabs(storage_key) or storage_key.startswith("attachments/"):
        return "local"
    return "cloud"


def _statement_reference_key(statement_id: int) -> str:
    return f"docvault://statement/{statement_id}"


def _source_url(owner_type: str, owner_id: int) -> str | None:
    return {
        "statement": f"/statements?id={owner_id}",
        "invoice": f"/invoices/view/{owner_id}",
        "expense": f"/expenses/view/{owner_id}",
        "inventory": f"/inventory/view/{owner_id}",
        "portfolio": f"/investments/portfolio/{owner_id}",
    }.get(owner_type)


def _locator_for_source(db: Session, source_table: str, source_attachment_id: int) -> DocVaultAttachmentLocator | None:
    return (
        db.query(DocVaultAttachmentLocator)
        .filter(
            DocVaultAttachmentLocator.source_table == source_table,
            DocVaultAttachmentLocator.source_attachment_id == source_attachment_id,
        )
        .first()
    )


def _scan_bank_statement_import_candidates(
    db: Session,
    current_user: MasterUser,
    payload: DocVaultImportScanRequest,
) -> list[DocVaultImportCandidate]:
    BankStatement, BankStatementAttachment = _host_statement_models()
    tenant_id = _current_tenant_id(current_user)
    candidates: list[DocVaultImportCandidate] = []

    statements_query = db.query(BankStatement).filter(BankStatement.is_deleted.is_(False))
    if tenant_id is not None:
        statements_query = statements_query.filter(BankStatement.tenant_id == tenant_id)
    statements = statements_query.order_by(BankStatement.created_at.desc()).all()

    for statement in statements:
        if payload.limit is not None and len(candidates) >= payload.limit:
            break

        if payload.include_statement_files:
            locator = _locator_for_source(db, "bank_statements", statement.id)
            statement_path = getattr(statement, "file_path", None)
            statement_cloud_url = getattr(statement, "cloud_file_url", None)
            candidates.append(
                DocVaultImportCandidate(
                    component="bank_statement",
                    owner_type="statement",
                    owner_id=statement.id,
                    source_table="bank_statements",
                    source_attachment_id=statement.id,
                    file_name=statement.original_filename or statement.stored_filename,
                    file_mime_type=_infer_mime_type(statement.original_filename),
                    file_size=_local_file_size(statement_path),
                    storage_provider=_storage_provider(statement_path, statement_cloud_url) if statement_path or statement_cloud_url else "reference",
                    storage_key=statement_cloud_url or statement_path or _statement_reference_key(statement.id),
                    checksum_sha256=statement.file_hash,
                    already_imported=locator is not None,
                    existing_entry_id=locator.entry_id if locator else None,
                )
            )

        if payload.limit is not None and len(candidates) >= payload.limit:
            break

        if payload.include_statement_attachments:
            attachments = (
                db.query(BankStatementAttachment)
                .filter(
                    BankStatementAttachment.statement_id == statement.id,
                    BankStatementAttachment.is_active.is_(True),
                )
                .order_by(BankStatementAttachment.created_at.desc())
                .all()
            )
            for attachment in attachments:
                if payload.limit is not None and len(candidates) >= payload.limit:
                    break
                locator = _locator_for_source(db, "bank_statement_attachments", attachment.id)
                candidates.append(
                    DocVaultImportCandidate(
                        component="bank_statement",
                        owner_type="statement",
                        owner_id=statement.id,
                        source_table="bank_statement_attachments",
                        source_attachment_id=attachment.id,
                        file_name=attachment.filename or attachment.stored_filename,
                        file_mime_type=_infer_mime_type(attachment.filename, attachment.content_type),
                        file_size=attachment.file_size,
                        storage_provider="cloud" if attachment.cloud_file_url else "local",
                        storage_key=attachment.cloud_file_url or attachment.file_path,
                        checksum_sha256=attachment.file_hash,
                        already_imported=locator is not None,
                        existing_entry_id=locator.entry_id if locator else None,
                    )
                )

    return candidates


def _scan_invoice_import_candidates(
    db: Session,
    payload: DocVaultImportScanRequest,
) -> list[DocVaultImportCandidate]:
    if not payload.include_invoice_attachments:
        return []
    Invoice, InvoiceAttachment, _, _, _, _ = _host_document_models()
    candidates: list[DocVaultImportCandidate] = []

    query = (
        db.query(InvoiceAttachment)
        .join(Invoice, InvoiceAttachment.invoice_id == Invoice.id)
        .filter(
            InvoiceAttachment.is_active.is_(True),
            Invoice.is_deleted.is_(False),
        )
        .order_by(InvoiceAttachment.created_at.desc())
    )
    attachments = query.all()

    for attachment in attachments:
        if payload.limit is not None and len(candidates) >= payload.limit:
            break
        locator = _locator_for_source(db, "invoice_attachments", attachment.id)
        candidates.append(
            DocVaultImportCandidate(
                component="invoice",
                owner_type="invoice",
                owner_id=attachment.invoice_id,
                source_table="invoice_attachments",
                source_attachment_id=attachment.id,
                file_name=attachment.filename or attachment.stored_filename,
                file_mime_type=_infer_mime_type(attachment.filename, attachment.content_type),
                file_size=attachment.file_size,
                storage_provider=_storage_provider(attachment.file_path),
                storage_key=attachment.file_path,
                checksum_sha256=attachment.file_hash,
                already_imported=locator is not None,
                existing_entry_id=locator.entry_id if locator else None,
            )
        )

    return candidates


def _scan_expense_import_candidates(
    db: Session,
    payload: DocVaultImportScanRequest,
) -> list[DocVaultImportCandidate]:
    if not payload.include_expense_attachments:
        return []
    _, _, Expense, ExpenseAttachment, _, _ = _host_document_models()
    candidates: list[DocVaultImportCandidate] = []

    query = (
        db.query(ExpenseAttachment)
        .join(Expense, ExpenseAttachment.expense_id == Expense.id)
        .filter(Expense.is_deleted.is_(False))
        .order_by(ExpenseAttachment.uploaded_at.desc())
    )
    attachments = query.all()

    for attachment in attachments:
        if payload.limit is not None and len(candidates) >= payload.limit:
            break
        locator = _locator_for_source(db, "expense_attachments", attachment.id)
        candidates.append(
            DocVaultImportCandidate(
                component="expense",
                owner_type="expense",
                owner_id=attachment.expense_id,
                source_table="expense_attachments",
                source_attachment_id=attachment.id,
                file_name=attachment.filename,
                file_mime_type=_infer_mime_type(attachment.filename, attachment.content_type),
                file_size=attachment.file_size or _local_file_size(attachment.file_path),
                storage_provider=_storage_provider(attachment.file_path),
                storage_key=attachment.file_path,
                checksum_sha256=None,
                already_imported=locator is not None,
                existing_entry_id=locator.entry_id if locator else None,
            )
        )

    return candidates


def _scan_inventory_import_candidates(
    db: Session,
    payload: DocVaultImportScanRequest,
) -> list[DocVaultImportCandidate]:
    if not payload.include_inventory_attachments:
        return []
    _, _, _, _, InventoryItem, ItemAttachment = _host_document_models()
    candidates: list[DocVaultImportCandidate] = []

    query = (
        db.query(ItemAttachment)
        .join(InventoryItem, ItemAttachment.item_id == InventoryItem.id)
        .filter(
            ItemAttachment.is_active.is_(True),
            InventoryItem.is_active.is_(True),
        )
        .order_by(ItemAttachment.created_at.desc())
    )
    attachments = query.all()

    for attachment in attachments:
        if payload.limit is not None and len(candidates) >= payload.limit:
            break
        locator = _locator_for_source(db, "item_attachments", attachment.id)
        candidates.append(
            DocVaultImportCandidate(
                component="inventory",
                owner_type="inventory",
                owner_id=attachment.item_id,
                source_table="item_attachments",
                source_attachment_id=attachment.id,
                file_name=attachment.filename or attachment.stored_filename,
                file_mime_type=_infer_mime_type(attachment.filename, attachment.content_type),
                file_size=attachment.file_size,
                storage_provider=_storage_provider(attachment.file_path),
                storage_key=attachment.file_path,
                checksum_sha256=attachment.file_hash,
                already_imported=locator is not None,
                existing_entry_id=locator.entry_id if locator else None,
            )
        )

    return candidates


def _host_api_base_url(request: Request) -> str:
    configured = os.getenv("DOCVAULT_HOST_API_URL") or os.getenv("YFW_HOST_API_URL")
    if configured:
        return configured.rstrip("/")
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1"


async def _fetch_portfolio_import_sources(request: Request) -> list[dict[str, Any]]:
    headers = {"X-Plugin-Caller": "docvault"}
    authorization = request.headers.get("authorization")
    cookie = request.headers.get("cookie")
    if authorization:
        headers["Authorization"] = authorization
    if cookie:
        headers["Cookie"] = cookie

    url = f"{_host_api_base_url(request)}/investments/docvault/import-sources/portfolio-files"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url, headers=headers)
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail")
        except Exception:
            detail = response.text
        raise ValueError(detail or response.reason_phrase)
    payload = response.json()
    return payload if isinstance(payload, list) else []


async def _scan_portfolio_import_candidates(
    db: Session,
    current_user: MasterUser,
    payload: DocVaultImportScanRequest,
    request: Request,
) -> list[DocVaultImportCandidate]:
    if not payload.include_portfolio_files:
        return []

    candidates: list[DocVaultImportCandidate] = []
    attachments = await _fetch_portfolio_import_sources(request)
    for attachment in attachments:
        if payload.limit is not None and len(candidates) >= payload.limit:
            break
        attachment_id = int(attachment.get("id"))
        locator = _locator_for_source(db, "investment_file_attachments", attachment_id)
        file_type = attachment.get("file_type")
        original_filename = attachment.get("original_filename")
        stored_filename = attachment.get("stored_filename")
        file_name = original_filename or stored_filename
        local_path = attachment.get("local_path")
        cloud_url = attachment.get("cloud_url")
        storage_key = cloud_url or local_path
        if not file_name or not storage_key:
            continue
        candidates.append(
            DocVaultImportCandidate(
                component="portfolio",
                owner_type="portfolio",
                owner_id=int(attachment.get("portfolio_id")),
                source_table="investment_file_attachments",
                source_attachment_id=attachment_id,
                file_name=file_name,
                file_mime_type=_infer_mime_type(original_filename, f"text/{file_type}" if file_type == "csv" else "application/pdf"),
                file_size=attachment.get("file_size"),
                storage_provider=_storage_provider(local_path, cloud_url),
                storage_key=storage_key,
                checksum_sha256=attachment.get("file_hash"),
                already_imported=locator is not None,
                existing_entry_id=locator.entry_id if locator else None,
            )
        )

    return candidates


def _scan_import_candidates(
    db: Session,
    current_user: MasterUser,
    payload: DocVaultImportScanRequest,
) -> list[DocVaultImportCandidate]:
    raise RuntimeError("Use _scan_import_candidates_with_errors for import scans.")


def _is_plugin_access_denied(exc: Exception) -> bool:
    return "Access Denied:" in str(exc) and "is not allowed to access table" in str(exc)


async def _scan_import_candidates_with_errors(
    db: Session,
    current_user: MasterUser,
    payload: DocVaultImportScanRequest,
    request: Request,
) -> tuple[list[DocVaultImportCandidate], list[dict[str, Any]]]:
    candidates: list[DocVaultImportCandidate] = []
    errors: list[dict[str, Any]] = []

    def add_component(component: str, scan_fn):
        try:
            candidates.extend(scan_fn())
        except Exception as exc:
            if not _is_plugin_access_denied(exc):
                raise
            db.rollback()
            errors.append(
                {
                    "component": component,
                    "source_table": component,
                    "error": (
                        f"{exc}. The plugin access setting permits API calls between plugins, "
                        "but this scanner attempted direct table access. Other components were still scanned."
                    ),
                }
            )

    if "bank_statement" in payload.components:
        add_component("bank_statement", lambda: _scan_bank_statement_import_candidates(db, current_user, payload))
    if "invoice" in payload.components:
        add_component("invoice", lambda: _scan_invoice_import_candidates(db, payload))
    if "expense" in payload.components:
        add_component("expense", lambda: _scan_expense_import_candidates(db, payload))
    if "inventory" in payload.components:
        add_component("inventory", lambda: _scan_inventory_import_candidates(db, payload))
    if "portfolio" in payload.components:
        try:
            candidates.extend(await _scan_portfolio_import_candidates(db, current_user, payload, request))
        except Exception as exc:
            db.rollback()
            errors.append(
                {
                    "component": "portfolio",
                    "source_table": "portfolio",
                    "error": str(exc),
                }
            )
    if payload.limit is not None:
        candidates = candidates[:payload.limit]
    return candidates, errors


def _import_summary(candidates: list[DocVaultImportCandidate], *, imported: int = 0, errors: list[dict[str, Any]] | None = None) -> DocVaultImportSummary:
    already_imported = sum(1 for candidate in candidates if candidate.already_imported)
    return DocVaultImportSummary(
        scanned=len(candidates),
        importable=len(candidates) - already_imported,
        already_imported=already_imported,
        imported=imported,
        skipped=already_imported,
        errors=errors or [],
    )


def _create_imported_document(
    db: Session,
    candidate: DocVaultImportCandidate,
    current_user: MasterUser,
) -> DocVaultEntry:
    source_label = candidate.owner_type.replace("_", " ")
    import_note = (
        f"Imported from {source_label} #{candidate.owner_id}"
        f" ({candidate.source_table} #{candidate.source_attachment_id})."
    )
    if candidate.storage_provider == "reference":
        import_note += " This source record does not have a stored attachment, so DocVault keeps a reference to the original record."
    metadata = _normalize_document_metadata(
        {
            "source_module": candidate.component,
            "source_table": candidate.source_table,
            "source_attachment_id": candidate.source_attachment_id,
            "source_owner_type": candidate.owner_type,
            "source_owner_id": candidate.owner_id,
            "source_url": _source_url(candidate.owner_type, candidate.owner_id),
            "import_note": import_note,
            "document_label": "finance",
            "approval_status": "draft",
            "immutable": False,
        }
    )
    entry = DocVaultEntry(
        category="document",
        title=candidate.file_name,
        file_name=candidate.file_name,
        file_mime_type=candidate.file_mime_type,
        file_size=candidate.file_size,
        public_metadata=metadata,
        sensitive_payload={},
        notes=import_note,
        tags=["imported", candidate.component],
        created_by=current_user.id,
    )
    db.add(entry)
    db.flush()

    db.add(
        DocVaultDocumentLink(
            entry_id=entry.id,
            owner_type=candidate.owner_type,
            owner_id=candidate.owner_id,
            linked_by=current_user.id,
        )
    )
    db.add(
        DocVaultAttachmentLocator(
            entry_id=entry.id,
            storage_provider=candidate.storage_provider,
            storage_key=candidate.storage_key,
            source_table=candidate.source_table,
            source_attachment_id=candidate.source_attachment_id,
            original_checksum=candidate.checksum_sha256,
        )
    )
    _create_attachment_version(
        db,
        entry,
        file_name=candidate.file_name,
        file_mime_type=candidate.file_mime_type,
        file_size=candidate.file_size,
        file_data_url=None,
        change_note="Imported external attachment reference",
        user_id=current_user.id,
        checksum_sha256=candidate.checksum_sha256,
    )
    import_snapshot = {
        "category": "document",
        "title": candidate.file_name,
        "owner_name": None,
        "issuer": None,
        "expiry_date": None,
        "issue_date": None,
        "public_metadata": dict(metadata),
        "sensitive_payload": {},
        "notes": import_note,
        "tags": ["imported", candidate.component],
        "thumbnail_data_url": None,
        "file_name": candidate.file_name,
        "file_mime_type": candidate.file_mime_type,
        "file_size": candidate.file_size,
        "file_data_url": None,
    }
    _record_entry_history(
        db,
        entry,
        action="imported",
        changed_fields=["created"],
        user_id=current_user.id,
        details={
            "owner_type": candidate.owner_type,
            "owner_id": candidate.owner_id,
            "source_table": candidate.source_table,
            "source_attachment_id": candidate.source_attachment_id,
        },
        snapshot=import_snapshot,
    )
    return entry


@router.post("/import/scan", response_model=DocVaultImportScanResponse)
async def scan_existing_documents(
    payload: DocVaultImportScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    candidates, errors = await _scan_import_candidates_with_errors(db, current_user, payload, request)
    return DocVaultImportScanResponse(
        summary=_import_summary(candidates, errors=errors),
        candidates=candidates,
    )


@router.post("/import/run", response_model=DocVaultImportRunResponse)
async def import_existing_documents(
    payload: DocVaultImportRunRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    candidates, errors = await _scan_import_candidates_with_errors(db, current_user, payload, request)
    created_entry_ids: list[int] = []

    if not payload.dry_run:
        for candidate in candidates:
            if candidate.already_imported:
                continue
            try:
                entry = _create_imported_document(db, candidate, current_user)
                db.commit()
                db.refresh(entry)
                created_entry_ids.append(entry.id)
            except Exception as exc:
                db.rollback()
                errors.append(
                    {
                        "source_table": candidate.source_table,
                        "source_attachment_id": candidate.source_attachment_id,
                        "file_name": candidate.file_name,
                        "error": str(exc),
                    }
                )

    return DocVaultImportRunResponse(
        dry_run=payload.dry_run,
        summary=_import_summary(candidates, imported=len(created_entry_ids), errors=errors),
        candidates=candidates,
        created_entry_ids=created_entry_ids,
    )


@router.get("", response_model=list[DocVaultEntryResponse])
async def list_entries(
    category: str | None = Query(default=None),
    q: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    query = db.query(DocVaultEntry).filter(DocVaultEntry.is_archived.is_(False))
    if category:
        query = query.filter(DocVaultEntry.category == category)
    entries = query.all()
    if q:
        needle = q.lower()
        entries = [entry for entry in entries if needle in (entry.title or "").lower() or needle in (entry.file_name or "").lower()]
    if tag:
        entries = [entry for entry in entries if tag in (entry.tags or [])]
    fingerprint_counts = _password_reuse_counts(entries)
    return [_serialize_with_counts(db, entry, fingerprint_counts=fingerprint_counts) for entry in sorted(entries, key=_sort_key)]


@router.get("/runtime")
async def runtime_info(
    current_user: MasterUser = Depends(get_current_user),
):
    return {
        "mode": "plugin" if IS_PLUGIN_MODE else "standalone",
        "plugin_mode": IS_PLUGIN_MODE,
        "standalone": not IS_PLUGIN_MODE,
        "features": {
            "import_existing": IS_PLUGIN_MODE,
        },
    }


@router.get("/by-entity/{owner_type}/{owner_id}", response_model=list[DocVaultEntryResponse])
async def list_documents_for_entity(
    owner_type: str,
    owner_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    normalized_owner_type = _normalize_owner_type(owner_type)
    entries = (
        db.query(DocVaultEntry)
        .join(DocVaultDocumentLink, DocVaultDocumentLink.entry_id == DocVaultEntry.id)
        .filter(
            DocVaultDocumentLink.owner_type == normalized_owner_type,
            DocVaultDocumentLink.owner_id == owner_id,
            DocVaultEntry.is_archived.is_(False),
        )
        .order_by(DocVaultEntry.created_at.desc())
        .all()
    )
    fingerprint_counts = _password_reuse_counts(entries)
    return [_serialize_with_counts(db, entry, fingerprint_counts=fingerprint_counts) for entry in entries]


@router.get("/mfa/status", response_model=DocVaultSystemMFAStatusResponse)
async def get_mfa_status(
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    return _system_mfa_status(db, current_user)


@router.get("/mfa/enrollments", response_model=list[DocVaultMFAEnrollmentResponse])
async def list_mfa_enrollments(
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    enrollments = db.query(DocVaultMFAEnrollment).filter(DocVaultMFAEnrollment.user_id == current_user.id).all()
    return [_mfa_response(enrollment) for enrollment in enrollments]


@router.post("/mfa/enrollments/setup", response_model=DocVaultMFASetupResponse)
async def setup_mfa_enrollment(
    payload: DocVaultMFASetupRequest,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    label = payload.label or current_user.email or "DocVault user"
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    enrollment = db.query(DocVaultMFAEnrollment).filter(
        DocVaultMFAEnrollment.user_id == current_user.id,
        DocVaultMFAEnrollment.factor_id == payload.factor_id,
    ).first()
    if enrollment:
        enrollment.label = label
        enrollment.secret = secret
        enrollment.is_verified = False
        enrollment.verified_at = None
    else:
        enrollment = DocVaultMFAEnrollment(
            user_id=current_user.id,
            factor_id=payload.factor_id,
            label=label,
            secret=secret,
            is_verified=False,
        )
    db.add(enrollment)
    db.commit()
    db.refresh(enrollment)

    uri = _otpauth_uri(secret, label=label)
    return DocVaultMFASetupResponse(
        factor_id=enrollment.factor_id,
        label=enrollment.label,
        secret=secret,
        otpauth_uri=uri,
        qr_data_url=_qr_data_url(uri),
        is_verified=enrollment.is_verified,
    )


@router.post("/mfa/enrollments/verify", response_model=DocVaultMFAEnrollmentResponse)
async def verify_mfa_enrollment(
    payload: DocVaultMFAVerifyRequest,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    enrollment = db.query(DocVaultMFAEnrollment).filter(
        DocVaultMFAEnrollment.user_id == current_user.id,
        DocVaultMFAEnrollment.factor_id == payload.factor_id,
    ).first()
    if not enrollment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="MFA enrollment not found")
    if not _verify_totp(enrollment.secret, payload.code, payload.window):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authenticator code")
    enrollment.is_verified = True
    enrollment.verified_at = datetime.now(timezone.utc)
    db.add(enrollment)
    db.commit()
    db.refresh(enrollment)
    return _mfa_response(enrollment)


@router.post("/mfa/local-unlock", response_model=DocVaultMFAEnrollmentResponse)
async def setup_local_unlock_method(
    payload: DocVaultLocalUnlockSetupRequest,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    if payload.factor_id == "vault_password":
        values = [payload.secret or ""]
        label = "Vault password"
    elif payload.factor_id == "recovery_code":
        values = payload.codes
        label = "Recovery codes"
    else:
        values = ["UNLOCK"]
        label = "Local confirmation"
    normalized = [_normalize_unlock_secret(value) for value in values if _normalize_unlock_secret(value)]
    if not normalized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Add at least one unlock secret")

    import json

    enrollment = db.query(DocVaultMFAEnrollment).filter(
        DocVaultMFAEnrollment.user_id == current_user.id,
        DocVaultMFAEnrollment.factor_id == payload.factor_id,
    ).first()
    secret = json.dumps(_local_secret_payload(normalized))
    now = datetime.now(timezone.utc)
    if enrollment:
        enrollment.label = label
        enrollment.secret = secret
        enrollment.is_verified = True
        enrollment.verified_at = now
    else:
        enrollment = DocVaultMFAEnrollment(
            user_id=current_user.id,
            factor_id=payload.factor_id,
            label=label,
            secret=secret,
            is_verified=True,
            verified_at=now,
        )
    db.add(enrollment)
    db.commit()
    db.refresh(enrollment)
    return _mfa_response(enrollment)


@router.delete("/mfa/local-unlock/{factor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disable_local_unlock_method(
    factor_id: str,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    if factor_id not in {"vault_password", "recovery_code", "local_fallback"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown local unlock method")
    enrollment = db.query(DocVaultMFAEnrollment).filter(
        DocVaultMFAEnrollment.user_id == current_user.id,
        DocVaultMFAEnrollment.factor_id == factor_id,
    ).first()
    if enrollment:
        db.delete(enrollment)
        db.commit()
    return None


@router.post("", response_model=DocVaultEntryResponse, status_code=status.HTTP_201_CREATED)
async def create_entry(
    payload: DocVaultEntryCreate,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    values = payload.model_dump()
    metadata = dict(values.get("public_metadata") or {})
    metadata["immutable"] = _metadata_bool(metadata.get("immutable"))
    cloud_integration = metadata.get("cloud_integration")
    if values.get("category") == "document":
        metadata = _normalize_document_metadata(metadata)
        if cloud_integration:
            if cloud_integration.get("provider") not in {"google_drive", "onedrive"} or not cloud_integration.get("file_url"):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cloud document links require google_drive or onedrive and file_url")
            cloud_payload = DocVaultCloudLinkRequest(
                provider=cloud_integration.get("provider"),
                file_url=cloud_integration.get("file_url"),
                file_id=cloud_integration.get("file_id"),
                file_name=cloud_integration.get("file_name") or values.get("file_name"),
                file_mime_type=values.get("file_mime_type"),
            )
            metadata["cloud_integration"] = _normalize_cloud_link(cloud_payload)
            values["file_name"] = values.get("file_name") or cloud_payload.file_name or _provider_label(cloud_payload.provider)
            values["file_data_url"] = None
        values["public_metadata"] = metadata
    if values.get("category") == "secret":
        metadata = dict(values.get("public_metadata") or {})
        metadata["immutable"] = _metadata_bool(metadata.get("immutable"))
        payload = dict(values.get("sensitive_payload") or {})
        if payload.get("password") and not metadata.get("password_updated_at"):
            metadata["password_updated_at"] = date.today().isoformat()
        values["public_metadata"] = metadata
    if values.get("category") not in {"document", "secret"}:
        values["public_metadata"] = metadata
    entry = DocVaultEntry(**values, created_by=current_user.id)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    _record_entry_history(
        db,
        entry,
        action="created",
        changed_fields=["created"],
        user_id=current_user.id,
        details={"category": entry.category},
    )
    if entry.category == "document" and (entry.file_name or entry.file_data_url):
        _create_attachment_version(
            db,
            entry,
            file_name=entry.file_name,
            file_mime_type=entry.file_mime_type,
            file_size=entry.file_size,
            file_data_url=entry.file_data_url,
            change_note="Initial cloud link" if cloud_integration else "Initial upload",
            user_id=current_user.id,
        )
        db.commit()
    else:
        db.commit()
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_CREATE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"category": entry.category},
    )
    return _serialize_with_counts(db, entry)


@router.put("/{entry_id}", response_model=DocVaultEntryResponse)
async def update_entry(
    entry_id: int,
    payload: DocVaultEntryUpdate,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    entry = _get_entry_or_404(db, entry_id)
    _ensure_mutable(entry)
    incoming = payload.model_dump(exclude_unset=True)
    incoming_sensitive_payload = dict(incoming.get("sensitive_payload") or {}) if "sensitive_payload" in incoming else {}
    old_document_snapshot = {
        "category": entry.category,
        "title": entry.title,
        "owner_name": entry.owner_name,
        "issuer": entry.issuer,
        "expiry_date": entry.expiry_date,
        "issue_date": entry.issue_date,
        "public_metadata": dict(entry.public_metadata or {}),
        "notes": entry.notes,
        "tags": list(entry.tags or []),
        "file_name": entry.file_name,
        "file_mime_type": entry.file_mime_type,
        "file_size": entry.file_size,
        "file_data_url": entry.file_data_url,
    }
    if "sensitive_payload" in incoming and incoming["sensitive_payload"] is not None:
        incoming["sensitive_payload"] = {
            **dict(entry.sensitive_payload or {}),
            **dict(incoming["sensitive_payload"] or {}),
        }
    for key, value in incoming.items():
        setattr(entry, key, value)
    if entry.category == "document" and "public_metadata" in incoming:
        entry.public_metadata = _normalize_document_metadata(dict(entry.public_metadata or {}))
    if entry.category == "secret" and incoming_sensitive_payload.get("password"):
        metadata = dict(entry.public_metadata or {})
        metadata["password_updated_at"] = date.today().isoformat()
        entry.public_metadata = metadata
    changed_fields = [
        key
        for key in (
            "title",
            "owner_name",
            "issuer",
            "expiry_date",
            "issue_date",
            "public_metadata",
            "notes",
            "tags",
            "file_name",
            "file_mime_type",
            "file_size",
            "file_data_url",
        )
        if key in incoming and old_document_snapshot.get(key) != getattr(entry, key)
    ]
    if incoming_sensitive_payload:
        changed_fields.append("sensitive_payload")
    old_cloud = (old_document_snapshot["public_metadata"] or {}).get("cloud_integration")
    new_cloud = (entry.public_metadata or {}).get("cloud_integration")
    attachment_changed = entry.category == "document" and any(
        field in changed_fields for field in ("file_name", "file_mime_type", "file_size", "file_data_url")
    )
    cloud_link_changed = entry.category == "document" and old_cloud != new_cloud
    if attachment_changed or cloud_link_changed:
        _create_attachment_version(
            db,
            entry,
            file_name=incoming.get("file_name") or entry.file_name,
            file_mime_type=incoming.get("file_mime_type") or entry.file_mime_type,
            file_size=incoming.get("file_size") if incoming.get("file_size") is not None else entry.file_size,
            file_data_url=incoming.get("file_data_url") or entry.file_data_url,
            change_note="Uploaded replacement" if old_document_snapshot["file_data_url"] != entry.file_data_url else "Updated document details",
            user_id=current_user.id,
        )
    if changed_fields:
        _record_entry_history(
            db,
            entry,
            action="updated",
            changed_fields=changed_fields,
            user_id=current_user.id,
            details={
                "category": entry.category,
                "attachment_changed": attachment_changed or cloud_link_changed,
            },
        )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_UPDATE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"category": entry.category},
    )
    return _serialize_with_counts(db, entry)


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    entry = _get_entry_or_404(db, entry_id)
    entry.is_archived = True
    db.add(entry)
    db.commit()
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_ARCHIVE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"category": entry.category},
    )
    return None


@router.post("/{entry_id}/links", response_model=DocVaultDocumentLinkResponse, status_code=status.HTTP_201_CREATED)
async def link_document_to_entity(
    entry_id: int,
    payload: DocVaultDocumentLinkCreate,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    entry = _get_entry_or_404(db, entry_id)
    normalized_owner_type = _normalize_owner_type(payload.owner_type)
    existing = (
        db.query(DocVaultDocumentLink)
        .filter(
            DocVaultDocumentLink.entry_id == entry.id,
            DocVaultDocumentLink.owner_type == normalized_owner_type,
            DocVaultDocumentLink.owner_id == payload.owner_id,
        )
        .first()
    )
    if existing:
        return _link_response(db, existing)

    link = DocVaultDocumentLink(
        entry_id=entry.id,
        owner_type=normalized_owner_type,
        owner_id=payload.owner_id,
        linked_by=current_user.id,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_LINK_CREATE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"owner_type": normalized_owner_type, "owner_id": payload.owner_id, "link_id": link.id},
    )
    return _link_response(db, link)


@router.get("/{entry_id}/links", response_model=list[DocVaultDocumentLinkResponse])
async def list_document_links(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    _get_entry_or_404(db, entry_id)
    links = (
        db.query(DocVaultDocumentLink)
        .filter(DocVaultDocumentLink.entry_id == entry_id)
        .order_by(DocVaultDocumentLink.created_at.desc())
        .all()
    )
    return [_link_response(db, link) for link in links]


@router.delete("/{entry_id}/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unlink_document_from_entity(
    entry_id: int,
    link_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    entry = _get_entry_or_404(db, entry_id)
    link = (
        db.query(DocVaultDocumentLink)
        .filter(DocVaultDocumentLink.id == link_id, DocVaultDocumentLink.entry_id == entry.id)
        .first()
    )
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DocVault document link not found")
    details = {"owner_type": link.owner_type, "owner_id": link.owner_id, "link_id": link.id}
    db.delete(link)
    db.commit()
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_LINK_DELETE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details=details,
    )
    return None


@router.post("/{entry_id}/unlock", response_model=DocVaultEntryResponse)
async def unlock_entry(
    entry_id: int,
    payload: DocVaultUnlockRequest,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    entry = _get_entry_or_404(db, entry_id)
    _verify_mfa(db, current_user, payload)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_UNLOCK",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"category": entry.category},
    )
    return _serialize_with_counts(db, entry, reveal=True)


@router.post("/{entry_id}/copy-event", status_code=status.HTTP_204_NO_CONTENT)
async def record_copy_event(
    entry_id: int,
    payload: DocVaultCopyEventRequest,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    entry = _get_entry_or_404(db, entry_id)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_COPY",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"category": entry.category, "field_name": payload.field_name},
    )
    return None


@router.get("/{entry_id}/attachments", response_model=list[DocVaultAttachmentVersionResponse])
async def list_attachment_versions(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    _get_entry_or_404(db, entry_id)
    versions = (
        db.query(DocVaultAttachmentVersion)
        .filter(DocVaultAttachmentVersion.entry_id == entry_id)
        .order_by(DocVaultAttachmentVersion.version.desc())
        .all()
    )
    return [_version_response(version) for version in versions]


@router.get("/{entry_id}/history", response_model=list[DocVaultEntryHistoryResponse])
async def list_entry_history(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    _get_entry_or_404(db, entry_id)
    history = (
        db.query(DocVaultEntryHistory)
        .filter(DocVaultEntryHistory.entry_id == entry_id)
        .order_by(DocVaultEntryHistory.created_at.desc(), DocVaultEntryHistory.id.desc())
        .all()
    )
    return [_history_response(item) for item in history]


@router.post("/{entry_id}/history/{history_id}/restore", response_model=DocVaultRestoreResponse)
async def restore_entry_history(
    entry_id: int,
    history_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    entry = _get_entry_or_404(db, entry_id)
    _ensure_mutable(entry)
    history = (
        db.query(DocVaultEntryHistory)
        .filter(DocVaultEntryHistory.id == history_id, DocVaultEntryHistory.entry_id == entry_id)
        .first()
    )
    if not history or not history.snapshot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Restorable history version not found")

    before = _entry_snapshot(entry)
    _restore_entry_snapshot(entry, dict(history.snapshot or {}))
    changed_fields = _changed_snapshot_fields(before, _entry_snapshot(entry))
    attachment_changed = entry.category == "document" and any(
        field in changed_fields for field in ("file_name", "file_mime_type", "file_size", "file_data_url")
    )
    if attachment_changed:
        _create_attachment_version(
            db,
            entry,
            file_name=entry.file_name,
            file_mime_type=entry.file_mime_type,
            file_size=entry.file_size,
            file_data_url=entry.file_data_url,
            change_note=f"Restored from item history #{history.id}",
            user_id=current_user.id,
        )
    if changed_fields:
        _record_entry_history(
            db,
            entry,
            action="restored",
            changed_fields=changed_fields,
            user_id=current_user.id,
            details={
                "category": entry.category,
                "restored_from": "item_history",
                "history_id": history.id,
                "history_action": history.action,
                "attachment_changed": attachment_changed,
            },
        )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_RESTORE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"source": "item_history", "history_id": history.id},
    )
    return DocVaultRestoreResponse(
        entry=_serialize_with_counts(db, entry),
        restored_from={"source": "item_history", "history_id": history.id},
    )


@router.post("/{entry_id}/attachments/{version_id}/restore", response_model=DocVaultRestoreResponse)
async def restore_attachment_version(
    entry_id: int,
    version_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    entry = _get_entry_or_404(db, entry_id)
    _ensure_mutable(entry)
    version = (
        db.query(DocVaultAttachmentVersion)
        .filter(DocVaultAttachmentVersion.id == version_id, DocVaultAttachmentVersion.entry_id == entry_id)
        .first()
    )
    if not version:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment version not found")

    before = _entry_snapshot(entry)
    entry.category = "document"
    entry.file_name = version.file_name
    entry.file_mime_type = version.file_mime_type
    entry.file_size = version.file_size
    entry.file_data_url = version.file_data_url
    restored_version = _create_attachment_version(
        db,
        entry,
        file_name=version.file_name,
        file_mime_type=version.file_mime_type,
        file_size=version.file_size,
        file_data_url=version.file_data_url,
        change_note=f"Restored from v{version.version}",
        user_id=current_user.id,
    )
    changed_fields = _changed_snapshot_fields(before, _entry_snapshot(entry))
    _record_entry_history(
        db,
        entry,
        action="restored",
        changed_fields=changed_fields or ["file_name", "file_mime_type", "file_size", "file_data_url"],
        user_id=current_user.id,
        details={
            "category": entry.category,
            "attachment_changed": True,
            "restored_from": "attachment_version",
            "attachment_version": version.version,
            "restored_attachment_version": restored_version.version if restored_version else None,
        },
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_ATTACHMENT_RESTORE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"version": version.version},
    )
    return DocVaultRestoreResponse(
        entry=_serialize_with_counts(db, entry),
        restored_from={"source": "attachment_version", "version": version.version},
    )


@router.post("/{entry_id}/attachments", response_model=DocVaultAttachmentVersionResponse, status_code=status.HTTP_201_CREATED)
async def create_attachment_version(
    entry_id: int,
    payload: DocVaultAttachmentVersionCreate,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    entry = _get_entry_or_404(db, entry_id)
    _ensure_mutable(entry)
    entry.category = "document"
    entry.file_name = payload.file_name
    entry.file_mime_type = payload.file_mime_type
    entry.file_size = payload.file_size
    entry.file_data_url = payload.file_data_url
    version = _create_attachment_version(
        db,
        entry,
        file_name=payload.file_name,
        file_mime_type=payload.file_mime_type,
        file_size=payload.file_size,
        file_data_url=payload.file_data_url,
        change_note=payload.change_note,
        user_id=current_user.id,
    )
    db.add(entry)
    _record_entry_history(
        db,
        entry,
        action="updated",
        changed_fields=["file_name", "file_mime_type", "file_size", "file_data_url"],
        user_id=current_user.id,
        details={"category": entry.category, "attachment_changed": True},
    )
    db.commit()
    db.refresh(version)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_ATTACHMENT_VERSION_CREATE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"version": version.version, "checksum_sha256": version.checksum_sha256},
    )
    return _version_response(version)


@router.post("/{entry_id}/cloud-link", response_model=DocVaultEntryResponse)
async def link_cloud_document(
    entry_id: int,
    payload: DocVaultCloudLinkRequest,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    ensure_docvault_schema(db)
    entry = _get_entry_or_404(db, entry_id)
    _ensure_mutable(entry)
    metadata = dict(entry.public_metadata or {})
    metadata["cloud_integration"] = _normalize_cloud_link(payload)
    entry.category = "document"
    entry.public_metadata = _normalize_document_metadata(metadata)
    entry.file_name = payload.file_name or entry.file_name or _provider_label(payload.provider)
    entry.file_mime_type = payload.file_mime_type or entry.file_mime_type
    entry.file_data_url = None
    _create_attachment_version(
        db,
        entry,
        file_name=entry.file_name,
        file_mime_type=entry.file_mime_type,
        file_size=entry.file_size,
        file_data_url=None,
        change_note=payload.change_note or f"Linked {_provider_label(payload.provider)} file",
        user_id=current_user.id,
    )
    db.add(entry)
    _record_entry_history(
        db,
        entry,
        action="updated",
        changed_fields=["public_metadata", "file_name", "file_mime_type", "file_data_url"],
        user_id=current_user.id,
        details={"category": entry.category, "attachment_changed": True},
    )
    db.commit()
    db.refresh(entry)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_CLOUD_LINK",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"provider": payload.provider, "file_name": entry.file_name},
    )
    return _serialize_with_counts(db, entry)


@router.get("/{entry_id}/signatures", response_model=list[DocVaultSignatureResponse])
async def list_signatures(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    _get_entry_or_404(db, entry_id)
    signatures = (
        db.query(DocVaultSignature)
        .filter(DocVaultSignature.entry_id == entry_id)
        .order_by(DocVaultSignature.signed_at.desc())
        .all()
    )
    return [_signature_response(signature) for signature in signatures]


@router.post("/{entry_id}/signatures", response_model=DocVaultSignatureResponse, status_code=status.HTTP_201_CREATED)
async def create_signature(
    entry_id: int,
    payload: DocVaultSignatureCreate,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    entry = _get_entry_or_404(db, entry_id)
    latest_version = (
        db.query(DocVaultAttachmentVersion)
        .filter(DocVaultAttachmentVersion.entry_id == entry.id, DocVaultAttachmentVersion.is_current.is_(True))
        .first()
    )
    signed_payload = {
        "entry_id": entry.id,
        "entry_title": entry.title,
        "file_name": entry.file_name,
        "attachment_version": latest_version.version if latest_version else None,
        "checksum_sha256": latest_version.checksum_sha256 if latest_version else _checksum(entry.file_data_url),
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    signature = DocVaultSignature(
        entry_id=entry.id,
        signer_name=payload.signer_name,
        signer_email=payload.signer_email,
        provider=payload.provider,
        status=payload.status,
        signature_reference=payload.signature_reference,
        signed_payload=signed_payload,
        created_by=current_user.id,
    )
    db.add(signature)
    db.commit()
    db.refresh(signature)
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_SIGNATURE_CREATE",
        resource_type="docvault_entry",
        resource_id=str(entry.id),
        resource_name=entry.title,
        details={"provider": signature.provider, "status": signature.status},
    )
    return _signature_response(signature)


@router.post("/retention/run", response_model=DocVaultRetentionRunResponse)
async def run_retention_policies(
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    today = date.today()
    archived_ids: list[int] = []
    entries = db.query(DocVaultEntry).filter(DocVaultEntry.is_archived.is_(False)).all()
    for entry in entries:
        metadata = dict(entry.public_metadata or {})
        years = metadata.get("retention_years")
        if not years:
            continue
        if _is_immutable(entry):
            continue
        try:
            years_int = int(years)
        except (TypeError, ValueError):
            continue
        basis_raw = metadata.get("retention_start_date") or entry.created_at.date().isoformat()
        try:
            basis_date = date.fromisoformat(str(basis_raw))
        except ValueError:
            basis_date = entry.created_at.date()
        if (today - basis_date).days >= years_int * 365:
            entry.is_archived = True
            metadata["retention_archived_at"] = datetime.now(timezone.utc).isoformat()
            entry.public_metadata = metadata
            archived_ids.append(entry.id)
            db.add(entry)

    db.commit()
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_RETENTION_RUN",
        resource_type="docvault",
        resource_id="retention",
        resource_name="DocVault retention policies",
        details={"archived_entry_ids": archived_ids},
    )
    return DocVaultRetentionRunResponse(archived_count=len(archived_ids), archived_entry_ids=archived_ids)


@router.post("/audit-package", response_model=DocVaultAuditPackageResponse)
async def create_audit_package(
    payload: DocVaultAuditPackageRequest,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
    query = db.query(DocVaultEntry)
    if not payload.include_archived:
        query = query.filter(DocVaultEntry.is_archived.is_(False))
    if payload.entry_ids:
        query = query.filter(DocVaultEntry.id.in_(payload.entry_ids))
    entries = query.order_by(DocVaultEntry.created_at.asc()).all()
    package_entries: list[dict[str, Any]] = []
    for entry in entries:
        versions = (
            db.query(DocVaultAttachmentVersion)
            .filter(DocVaultAttachmentVersion.entry_id == entry.id)
            .order_by(DocVaultAttachmentVersion.version.asc())
            .all()
        )
        signatures = (
            db.query(DocVaultSignature)
            .filter(DocVaultSignature.entry_id == entry.id)
            .order_by(DocVaultSignature.signed_at.asc())
            .all()
        )
        serialized = _serialize(entry, reveal=payload.include_file_data).model_dump(mode="json")
        if not payload.include_file_data:
            serialized.pop("file_data_url", None)
        package_entries.append({
            "entry": serialized,
            "document_workflow": _document_workflow(entry),
            "versions": [
                {
                    **_version_response(version).model_dump(mode="json"),
                    **({} if payload.include_file_data else {"file_data_url": None}),
                }
                for version in versions
            ],
            "signatures": [_signature_response(signature).model_dump(mode="json") for signature in signatures],
        })

    manifest = {
        "format": "docvault-audit-package",
        "version": "1.0",
        "entry_count": len(package_entries),
        "include_file_data": payload.include_file_data,
        "package_checksum_sha256": _checksum(str(package_entries)),
    }
    log_audit_event(
        db=db,
        user_id=current_user.id,
        user_email=current_user.email,
        action="DOCVAULT_AUDIT_PACKAGE_CREATE",
        resource_type="docvault",
        resource_id="audit_package",
        resource_name="DocVault audit package",
        details=manifest,
    )
    return DocVaultAuditPackageResponse(
        generated_at=datetime.now(timezone.utc),
        generated_by=getattr(current_user, "email", None),
        entries=package_entries,
        manifest=manifest,
    )


@router.post("/scan-card", response_model=DocVaultScanResponse)
async def scan_card(
    payload: DocVaultScanRequest,
    current_user: MasterUser = Depends(get_current_user),
):
    hint = f"{payload.file_name or ''} {payload.image_data_url or ''}"[:2000]
    digits = re.sub(r"\D", "", hint)
    expiry_match = re.search(r"(0[1-9]|1[0-2])[/\-. ]?([0-9]{2,4})", hint)
    yyyy_date = re.search(r"(20[0-9]{2})[-/](0[1-9]|1[0-2])[-/]([0-3][0-9])", hint)

    if payload.category == "credit_card":
        network = "Visa"
        if digits.startswith(("34", "37")):
            network = "Amex"
        elif digits.startswith(("51", "52", "53", "54", "55", "22")):
            network = "Mastercard"
        elif digits.startswith("6"):
            network = "Discover"
        elif digits.startswith("62"):
            network = "UnionPay"
        extracted = {
            "network": network,
            "last4": digits[-4:] if len(digits) >= 4 else "",
            "expiry": f"{expiry_match.group(1)}/{expiry_match.group(2)[-2:]}" if expiry_match else "",
            "cardholder_name": "",
            "bank": "",
            "card_label": payload.file_name or "Scanned card",
            "card_number": digits if len(digits) >= 12 else "",
        }
        confidence = 0.74 if extracted["last4"] or extracted["expiry"] else 0.42
    else:
        extracted = {
            "card_type": "ID / Health Card",
            "holder_name": "",
            "expiry_date": f"{yyyy_date.group(1)}-{yyyy_date.group(2)}-{yyyy_date.group(3)}" if yyyy_date else "",
            "issuing_authority": "",
            "confidence_level": 0.7 if yyyy_date else 0.45,
        }
        confidence = extracted["confidence_level"]

    return DocVaultScanResponse(
        category=payload.category,
        extracted=extracted,
        confidence=confidence,
        method="ai_vision_with_filename_fallback",
    )
