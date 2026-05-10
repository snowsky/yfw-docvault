"""DocVault API router."""

from __future__ import annotations

import re
import hashlib
import base64
import hmac
import io
import secrets
import struct
import time
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

try:
    from core.models.database import get_db
    from core.models.models import MasterUser
    from core.models.models_per_tenant import User as TenantUser
    from core.routers.auth import get_current_user
    from core.utils.audit import log_audit_event
except ModuleNotFoundError:
    from .auth import StandaloneUser as MasterUser
    from .auth import get_current_user
    from .database import StandaloneUser as TenantUser
    from .database import get_db

    def log_audit_event(**kwargs):
        return None

from .models import DocVaultAttachmentVersion, DocVaultEntry, DocVaultMFAEnrollment, DocVaultSignature
from .schemas import (
    DocVaultAttachmentVersionCreate,
    DocVaultAttachmentVersionResponse,
    DocVaultAuditPackageRequest,
    DocVaultAuditPackageResponse,
    DocVaultCloudLinkRequest,
    DocVaultCopyEventRequest,
    DocVaultEntryCreate,
    DocVaultEntryResponse,
    DocVaultEntryUpdate,
    DocVaultMFAEnrollmentResponse,
    DocVaultLocalUnlockSetupRequest,
    DocVaultMFASetupRequest,
    DocVaultMFASetupResponse,
    DocVaultMFAVerifyRequest,
    DocVaultSystemMFAStatusResponse,
    DocVaultRetentionRunResponse,
    DocVaultScanRequest,
    DocVaultScanResponse,
    DocVaultSignatureCreate,
    DocVaultSignatureResponse,
    DocVaultUnlockRequest,
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
        checksum_sha256=_checksum(file_data_url or entry.file_data_url),
        change_note=change_note,
        is_current=True,
        created_by=user_id,
    )
    db.add(version)
    return version


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
    if entry.category == "document" and any(
        old_document_snapshot.get(key) != getattr(entry, key)
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
    ):
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


@router.post("/{entry_id}/attachments", response_model=DocVaultAttachmentVersionResponse, status_code=status.HTTP_201_CREATED)
async def create_attachment_version(
    entry_id: int,
    payload: DocVaultAttachmentVersionCreate,
    db: Session = Depends(get_db),
    current_user: MasterUser = Depends(get_current_user),
):
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
