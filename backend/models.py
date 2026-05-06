"""DocVault models.

In plugin mode this module uses the host app tenant ``Base`` and encrypted
column helpers. In standalone mode those imports are unavailable, so it falls
back to local SQLAlchemy primitives and the standalone Postgres database.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, JSON, String, Text

try:
    from core.models.models_per_tenant import Base
    from core.utils.column_encryptor import EncryptedColumn, EncryptedJSON
except ModuleNotFoundError:
    from .database import Base

    def EncryptedColumn(*args, **kwargs):  # type: ignore[override]
        return Text(*args, **kwargs)

    def EncryptedJSON(*args, **kwargs):  # type: ignore[override]
        return JSON(*args, **kwargs)


class DocVaultEntry(Base):
    __tablename__ = "docvault_entries"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, nullable=False, index=True)
    title = Column(EncryptedColumn(), nullable=False)
    owner_name = Column(EncryptedColumn(), nullable=True)
    issuer = Column(EncryptedColumn(), nullable=True)
    expiry_date = Column(Date, nullable=True, index=True)
    issue_date = Column(Date, nullable=True)
    status_override = Column(String, nullable=True)
    public_metadata = Column(JSON, nullable=True)
    sensitive_payload = Column(EncryptedJSON(), nullable=True)
    notes = Column(EncryptedColumn(), nullable=True)
    tags = Column(JSON, nullable=True)
    thumbnail_data_url = Column(Text, nullable=True)
    file_name = Column(EncryptedColumn(), nullable=True)
    file_mime_type = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)
    file_data_url = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    is_archived = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class DocVaultAttachmentVersion(Base):
    __tablename__ = "docvault_attachment_versions"

    id = Column(Integer, primary_key=True, index=True)
    entry_id = Column(Integer, ForeignKey("docvault_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    file_name = Column(EncryptedColumn(), nullable=False)
    file_mime_type = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)
    file_data_url = Column(Text, nullable=True)
    checksum_sha256 = Column(String, nullable=False)
    change_note = Column(EncryptedColumn(), nullable=True)
    is_current = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class DocVaultSignature(Base):
    __tablename__ = "docvault_signatures"

    id = Column(Integer, primary_key=True, index=True)
    entry_id = Column(Integer, ForeignKey("docvault_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    signer_name = Column(EncryptedColumn(), nullable=False)
    signer_email = Column(EncryptedColumn(), nullable=True)
    provider = Column(String, nullable=False, default="manual")
    status = Column(String, nullable=False, default="signed")
    signature_reference = Column(EncryptedColumn(), nullable=True)
    signed_payload = Column(JSON, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    signed_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
