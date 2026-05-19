"""Model Context Protocol (MCP) Server for DocVault.

Exposes DocVault entries (cards, SSL certificates, passwords, private keys, documents)
as secure tools for external AI models and assistants to view and manage.
"""

from __future__ import annotations

import os
import sys
import json
import hashlib
from datetime import date, datetime, timezone
from typing import Any, List, Optional, Dict

# Add the parent directory to the path so python imports from 'backend' work properly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    # Fallback to general import if standard path varies
    try:
        from mcp.server import FastMCP
    except ImportError:
        # If running offline or testing pre-installation
        class FastMCP:
            def __init__(self, *args, **kwargs):
                pass
            def tool(self):
                return lambda f: f
            def run(self):
                pass

from backend.database import SessionLocal, StandaloneUser
from backend.models import (
    DocVaultEntry,
    DocVaultDocumentLink,
    DocVaultAttachmentVersion,
    DocVaultSignature,
    DocVaultEntryHistory,
    DocVaultAttachmentLocator,
)

# Initialize the MCP Server
mcp = FastMCP("DocVault")

# User ID context (defaults to local StandaloneUser ID 1)
DEFAULT_USER_ID = 1

# Helper functions for calculations and formatting
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

def _entry_snapshot(entry: DocVaultEntry) -> dict[str, Any]:
    return {
        "category": entry.category,
        "title": entry.title,
        "owner_name": entry.owner_name,
        "issuer": entry.issuer,
        "expiry_date": entry.expiry_date.isoformat() if entry.expiry_date else None,
        "issue_date": entry.issue_date.isoformat() if entry.issue_date else None,
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

def _record_entry_history(
    db: Session,
    entry: DocVaultEntry,
    action: str,
    changed_fields: list[str],
    user_id: int | None = DEFAULT_USER_ID,
    details: dict[str, Any] | None = None,
) -> DocVaultEntryHistory:
    history = DocVaultEntryHistory(
        entry_id=entry.id,
        action=action,
        changed_fields=sorted(set(changed_fields)),
        details=details or {},
        snapshot=_entry_snapshot(entry),
        created_by=user_id,
    )
    db.add(history)
    return history

def _checksum(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def _serialize_entry(entry: DocVaultEntry) -> dict[str, Any]:
    """Serialize standard docvault entry fields for tool response."""
    status_name, days_delta, alerting = _expiry_status(entry.category, entry.expiry_date)
    return {
        "id": entry.id,
        "category": entry.category,
        "title": entry.title,
        "owner_name": entry.owner_name,
        "issuer": entry.issuer,
        "expiry_date": entry.expiry_date.isoformat() if entry.expiry_date else None,
        "issue_date": entry.issue_date.isoformat() if entry.issue_date else None,
        "status_override": entry.status_override,
        "public_metadata": entry.public_metadata or {},
        "notes": entry.notes,
        "tags": entry.tags or [],
        "file_name": entry.file_name,
        "file_mime_type": entry.file_mime_type,
        "file_size": entry.file_size,
        "is_archived": entry.is_archived,
        "created_by": entry.created_by,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
        "expiry_status": status_name,
        "days_delta": days_delta,
        "alerting": alerting,
    }

# --- Tools Definitions ---

@mcp.tool()
def list_entries(
    category: Optional[str] = None,
    tag: Optional[str] = None,
    query: Optional[str] = None,
) -> str:
    """List and filter active DocVault entries (documents, credentials, SSL certs, etc.).

    Args:
        category: Filter by entry type (e.g. card, ssl, id, document, password, key).
        tag: Filter by a specific tag.
        query: Full-text search term in titles and filenames (case-insensitive).
    """
    db = SessionLocal()
    try:
        q = db.query(DocVaultEntry).filter(DocVaultEntry.is_archived.is_(False))
        if category:
            q = q.filter(DocVaultEntry.category == category)
        entries = q.all()

        if query:
            needle = query.lower()
            entries = [
                e for e in entries
                if needle in (e.title or "").lower() or needle in (e.file_name or "").lower()
            ]

        if tag:
            entries = [e for e in entries if tag in (e.tags or [])]

        results = [_serialize_entry(e) for e in entries]
        return json.dumps(results, indent=2)
    finally:
        db.close()


@mcp.tool()
def get_entry(entry_id: int) -> str:
    """Retrieve full details of a specific active DocVault entry by its ID.

    Args:
        entry_id: The ID of the DocVault entry to fetch.
    """
    db = SessionLocal()
    try:
        entry = db.query(DocVaultEntry).filter(
            DocVaultEntry.id == entry_id,
            DocVaultEntry.is_archived.is_(False)
        ).first()

        if not entry:
            return f"Error: Entry with ID {entry_id} not found."

        serialized = _serialize_entry(entry)
        # Expose the sensitive payload mask if requested or structure details
        serialized["sensitive_payload_available"] = bool(entry.sensitive_payload)
        
        # Include versions and signatures count
        serialized["attachment_versions_count"] = db.query(DocVaultAttachmentVersion).filter(
            DocVaultAttachmentVersion.entry_id == entry.id
        ).count()
        serialized["signatures_count"] = db.query(DocVaultSignature).filter(
            DocVaultSignature.entry_id == entry.id
        ).count()

        return json.dumps(serialized, indent=2)
    finally:
        db.close()


@mcp.tool()
def check_expiring_soon(days: int = 30) -> str:
    """Identify documents, cards, or SSL certificates that are expired or expiring within the specified days.

    Args:
        days: Threshold in days to check for upcoming expiration (default is 30).
    """
    db = SessionLocal()
    try:
        today = date.today()
        entries = db.query(DocVaultEntry).filter(
            DocVaultEntry.is_archived.is_(False),
            DocVaultEntry.expiry_date.isnot(None)
        ).all()

        expiring = []
        for entry in entries:
            status_name, days_delta, alerting = _expiry_status(entry.category, entry.expiry_date)
            if days_delta is not None and days_delta <= days:
                serialized = _serialize_entry(entry)
                expiring.append({
                    "id": serialized["id"],
                    "category": serialized["category"],
                    "title": serialized["title"],
                    "expiry_date": serialized["expiry_date"],
                    "days_remaining": days_delta,
                    "status": status_name,
                })

        # Sort by days remaining (most urgent first)
        expiring.sort(key=lambda x: x["days_remaining"])
        return json.dumps(expiring, indent=2)
    finally:
        db.close()


@mcp.tool()
def create_entry(
    category: str,
    title: str,
    owner_name: Optional[str] = None,
    issuer: Optional[str] = None,
    expiry_date: Optional[str] = None,
    issue_date: Optional[str] = None,
    notes: Optional[str] = None,
    tags: Optional[List[str]] = None,
    sensitive_payload: Optional[Dict[str, Any]] = None,
) -> str:
    """Create a new DocVault entry (card, certificate, document, credential, password, etc.).

    Args:
        category: The category (e.g. "document", "password", "ssl", "credit_card", "id").
        title: The title or label for this entry.
        owner_name: Owner name if applicable.
        issuer: Issuing authority or organization (e.g. issuer bank or certificate host).
        expiry_date: Expiration date in "YYYY-MM-DD" format.
        issue_date: Date of issue in "YYYY-MM-DD" format.
        notes: General notes or description.
        tags: List of tag strings to categorize the entry.
        sensitive_payload: Secure key-value parameters (e.g. {"password": "x", "cvv": "123"}).
    """
    db = SessionLocal()
    try:
        exp_date = date.fromisoformat(expiry_date) if expiry_date else None
        iss_date = date.fromisoformat(issue_date) if issue_date else None
        
        entry = DocVaultEntry(
            category=category,
            title=title,
            owner_name=owner_name,
            issuer=issuer,
            expiry_date=exp_date,
            issue_date=iss_date,
            notes=notes,
            tags=tags or [],
            sensitive_payload=sensitive_payload or {},
            created_by=DEFAULT_USER_ID,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)

        _record_entry_history(db, entry, action="created", changed_fields=["created"])
        db.commit()

        return json.dumps(_serialize_entry(entry), indent=2)
    except ValueError as val_err:
        return f"Error: Date parsing error. Ensure YYYY-MM-DD format. Detail: {str(val_err)}"
    except Exception as exc:
        db.rollback()
        return f"Error: Could not create entry. Detail: {str(exc)}"
    finally:
        db.close()


@mcp.tool()
def update_entry(
    entry_id: int,
    title: Optional[str] = None,
    owner_name: Optional[str] = None,
    issuer: Optional[str] = None,
    expiry_date: Optional[str] = None,
    issue_date: Optional[str] = None,
    notes: Optional[str] = None,
    tags: Optional[List[str]] = None,
    sensitive_payload: Optional[Dict[str, Any]] = None,
) -> str:
    """Update details of an existing DocVault entry.

    Args:
        entry_id: The ID of the entry to update.
        title: New title.
        owner_name: New owner name.
        issuer: New issuing authority.
        expiry_date: Expiry date in "YYYY-MM-DD" format.
        issue_date: Issue date in "YYYY-MM-DD" format.
        notes: New notes text.
        tags: New list of tags.
        sensitive_payload: Secure key-value parameters to merge with existing ones.
    """
    db = SessionLocal()
    try:
        entry = db.query(DocVaultEntry).filter(
            DocVaultEntry.id == entry_id,
            DocVaultEntry.is_archived.is_(False)
        ).first()

        if not entry:
            return f"Error: Entry with ID {entry_id} not found."

        changed_fields = []
        if title is not None and entry.title != title:
            entry.title = title
            changed_fields.append("title")
        if owner_name is not None and entry.owner_name != owner_name:
            entry.owner_name = owner_name
            changed_fields.append("owner_name")
        if issuer is not None and entry.issuer != issuer:
            entry.issuer = issuer
            changed_fields.append("issuer")
        
        if expiry_date is not None:
            new_exp = date.fromisoformat(expiry_date) if expiry_date else None
            if entry.expiry_date != new_exp:
                entry.expiry_date = new_exp
                changed_fields.append("expiry_date")
        if issue_date is not None:
            new_iss = date.fromisoformat(issue_date) if issue_date else None
            if entry.issue_date != new_iss:
                entry.issue_date = new_iss
                changed_fields.append("issue_date")

        if notes is not None and entry.notes != notes:
            entry.notes = notes
            changed_fields.append("notes")
        if tags is not None and entry.tags != tags:
            entry.tags = tags
            changed_fields.append("tags")

        if sensitive_payload is not None:
            current_sens = dict(entry.sensitive_payload or {})
            merged_sens = {**current_sens, **sensitive_payload}
            if current_sens != merged_sens:
                entry.sensitive_payload = merged_sens
                changed_fields.append("sensitive_payload")

        if changed_fields:
            _record_entry_history(db, entry, action="updated", changed_fields=changed_fields)
            db.commit()
            db.refresh(entry)

        return json.dumps(_serialize_entry(entry), indent=2)
    except ValueError as val_err:
        return f"Error: Date parsing error. Ensure YYYY-MM-DD format. Detail: {str(val_err)}"
    except Exception as exc:
        db.rollback()
        return f"Error: Could not update entry. Detail: {str(exc)}"
    finally:
        db.close()


@mcp.tool()
def delete_entry(entry_id: int) -> str:
    """Soft delete/archive a DocVault entry.

    Args:
        entry_id: The ID of the entry to archive.
    """
    db = SessionLocal()
    try:
        entry = db.query(DocVaultEntry).filter(
            DocVaultEntry.id == entry_id,
            DocVaultEntry.is_archived.is_(False)
        ).first()

        if not entry:
            return f"Error: Entry with ID {entry_id} not found."

        entry.is_archived = True
        _record_entry_history(db, entry, action="archived", changed_fields=["is_archived"])
        db.commit()
        return f"Success: Entry {entry_id} successfully archived."
    except Exception as exc:
        db.rollback()
        return f"Error: Could not delete entry. Detail: {str(exc)}"
    finally:
        db.close()


@mcp.tool()
def get_document_links(entry_id: int) -> str:
    """List references/links connecting a document to host-app modules (expenses, inventory, etc.).

    Args:
        entry_id: ID of the DocVault document entry.
    """
    db = SessionLocal()
    try:
        links = db.query(DocVaultDocumentLink).filter(
            DocVaultDocumentLink.entry_id == entry_id
        ).all()

        results = []
        for link in links:
            results.append({
                "id": link.id,
                "entry_id": link.entry_id,
                "owner_type": link.owner_type,
                "owner_id": link.owner_id,
                "linked_by": link.linked_by,
                "created_at": link.created_at.isoformat() if link.created_at else None,
            })
        return json.dumps(results, indent=2)
    finally:
        db.close()


@mcp.tool()
def get_entry_history(entry_id: int) -> str:
    """Retrieve audit history and snapshots of changes for a specific entry.

    Args:
        entry_id: The entry ID to inspect.
    """
    db = SessionLocal()
    try:
        histories = db.query(DocVaultEntryHistory).filter(
            DocVaultEntryHistory.entry_id == entry_id
        ).order_by(DocVaultEntryHistory.created_at.desc()).all()

        results = []
        for h in histories:
            results.append({
                "id": h.id,
                "entry_id": h.entry_id,
                "action": h.action,
                "changed_fields": h.changed_fields,
                "details": h.details,
                "snapshot": h.snapshot,
                "created_by": h.created_by,
                "created_at": h.created_at.isoformat() if h.created_at else None,
            })
        return json.dumps(results, indent=2)
    finally:
        db.close()


@mcp.tool()
def get_signatures(entry_id: int) -> str:
    """Retrieve approval and digital signature records for a specific document.

    Args:
        entry_id: The document ID.
    """
    db = SessionLocal()
    try:
        signatures = db.query(DocVaultSignature).filter(
            DocVaultSignature.entry_id == entry_id
        ).order_by(DocVaultSignature.signed_at.desc()).all()

        results = []
        for s in signatures:
            results.append({
                "id": s.id,
                "signer_name": s.signer_name,
                "signer_email": s.signer_email,
                "provider": s.provider,
                "status": s.status,
                "signature_reference": s.signature_reference,
                "signed_payload": s.signed_payload,
                "signed_at": s.signed_at.isoformat() if s.signed_at else None,
            })
        return json.dumps(results, indent=2)
    finally:
        db.close()


@mcp.tool()
def add_signature(
    entry_id: int,
    signer_name: str,
    signer_email: Optional[str] = None,
    provider: str = "manual",
) -> str:
    """Log/record a digital approval signature for a document.

    Args:
        entry_id: The ID of the document to approve.
        signer_name: Full name of the signer.
        signer_email: Email of the signer.
        provider: Signature provider or type (e.g. "manual", "docusign").
    """
    db = SessionLocal()
    try:
        entry = db.query(DocVaultEntry).filter(
            DocVaultEntry.id == entry_id,
            DocVaultEntry.is_archived.is_(False)
        ).first()

        if not entry:
            return f"Error: Document with ID {entry_id} not found."

        sig = DocVaultSignature(
            entry_id=entry_id,
            signer_name=signer_name,
            signer_email=signer_email,
            provider=provider,
            status="signed",
            created_by=DEFAULT_USER_ID,
        )
        db.add(sig)
        
        # Log to entry history
        _record_entry_history(
            db, entry,
            action="signed",
            changed_fields=["signature"],
            details={"signer": signer_name, "provider": provider}
        )
        
        db.commit()
        db.refresh(sig)

        return json.dumps({
            "id": sig.id,
            "entry_id": sig.entry_id,
            "signer_name": sig.signer_name,
            "signer_email": sig.signer_email,
            "status": sig.status,
            "signed_at": sig.signed_at.isoformat() if sig.signed_at else None,
        }, indent=2)
    except Exception as exc:
        db.rollback()
        return f"Error: Could not record signature. Detail: {str(exc)}"
    finally:
        db.close()


@mcp.tool()
def run_retention_policy(dry_run: bool = True) -> str:
    """Scan and archive documents that have exceeded their designated retention periods.

    Args:
        dry_run: If True, only lists candidates without archiving them (default is True).
    """
    db = SessionLocal()
    try:
        today = date.today()
        archived_ids = []
        candidates_info = []

        entries = db.query(DocVaultEntry).filter(DocVaultEntry.is_archived.is_(False)).all()
        for entry in entries:
            metadata = dict(entry.public_metadata or {})
            years = metadata.get("retention_years")
            if not years:
                continue
            
            # Skip immutable documents
            if metadata.get("immutable") is True:
                continue

            try:
                years_int = int(years)
            except (TypeError, ValueError):
                continue

            basis_raw = metadata.get("retention_start_date") or (
                entry.created_at.date().isoformat() if entry.created_at else today.isoformat()
            )
            try:
                basis_date = date.fromisoformat(str(basis_raw))
            except ValueError:
                basis_date = entry.created_at.date() if entry.created_at else today

            if (today - basis_date).days >= years_int * 365:
                candidates_info.append({
                    "id": entry.id,
                    "title": entry.title,
                    "retention_years": years_int,
                    "start_date": basis_raw,
                })
                if not dry_run:
                    entry.is_archived = True
                    metadata["retention_archived_at"] = datetime.now(timezone.utc).isoformat()
                    entry.public_metadata = metadata
                    archived_ids.append(entry.id)
                    db.add(entry)
                    _record_entry_history(
                        db, entry, 
                        action="archived", 
                        changed_fields=["is_archived"],
                        details={"reason": "retention_policy"}
                    )

        if not dry_run and archived_ids:
            db.commit()

        return json.dumps({
            "dry_run": dry_run,
            "matched_count": len(candidates_info),
            "processed_count": len(archived_ids),
            "entries": candidates_info,
        }, indent=2)
    except Exception as exc:
        db.rollback()
        return f"Error: Failed to execute retention policy. Detail: {str(exc)}"
    finally:
        db.close()


@mcp.tool()
def generate_audit_package(include_file_data: bool = False) -> str:
    """Generate an audit-ready compliance package compiling entries, history, and approval signatures.

    Args:
        include_file_data: If True, exports full document data URLs (default is False).
    """
    db = SessionLocal()
    try:
        entries = db.query(DocVaultEntry).order_by(DocVaultEntry.created_at.asc()).all()
        package_entries = []

        for entry in entries:
            versions = db.query(DocVaultAttachmentVersion).filter(
                DocVaultAttachmentVersion.entry_id == entry.id
            ).order_by(DocVaultAttachmentVersion.version.asc()).all()

            signatures = db.query(DocVaultSignature).filter(
                DocVaultSignature.entry_id == entry.id
            ).order_by(DocVaultSignature.signed_at.asc()).all()

            serialized = _serialize_entry(entry)
            if not include_file_data:
                # Exclude any file bytes url
                serialized.pop("file_data_url", None)

            package_entries.append({
                "entry": serialized,
                "versions": [
                    {
                        "id": v.id,
                        "version": v.version,
                        "file_name": v.file_name,
                        "file_mime_type": v.file_mime_type,
                        "file_size": v.file_size,
                        "checksum_sha256": v.checksum_sha256,
                        "change_note": v.change_note,
                        "created_at": v.created_at.isoformat() if v.created_at else None,
                    }
                    for v in versions
                ],
                "signatures": [
                    {
                        "id": s.id,
                        "signer_name": s.signer_name,
                        "signer_email": s.signer_email,
                        "provider": s.provider,
                        "status": s.status,
                        "signed_at": s.signed_at.isoformat() if s.signed_at else None,
                    }
                    for s in signatures
                ],
            })

        manifest = {
            "format": "docvault-audit-package",
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(package_entries),
            "include_file_data": include_file_data,
            "package_checksum_sha256": _checksum(str(package_entries)),
        }

        return json.dumps({
            "manifest": manifest,
            "entries": package_entries,
        }, indent=2)
    except Exception as exc:
        return f"Error: Audit package compilation failed. Detail: {str(exc)}"
    finally:
        db.close()


# Run the MCP Server
if __name__ == "__main__":
    mcp.run()
