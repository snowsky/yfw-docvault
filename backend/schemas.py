"""DocVault API schemas."""

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

DocVaultCategory = Literal["credit_card", "ssl_certificate", "id_card", "document", "secret"]


class DocVaultEntryBase(BaseModel):
    category: DocVaultCategory
    title: str = Field(min_length=1, max_length=160)
    owner_name: str | None = None
    issuer: str | None = None
    expiry_date: date | None = None
    issue_date: date | None = None
    public_metadata: dict[str, Any] = Field(default_factory=dict)
    sensitive_payload: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = None
    tags: list[str] = Field(default_factory=list)
    thumbnail_data_url: str | None = None
    file_name: str | None = None
    file_mime_type: str | None = None
    file_size: int | None = None
    file_data_url: str | None = None


class DocVaultEntryCreate(DocVaultEntryBase):
    pass


class DocVaultEntryUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=160)
    owner_name: str | None = None
    issuer: str | None = None
    expiry_date: date | None = None
    issue_date: date | None = None
    public_metadata: dict[str, Any] | None = None
    sensitive_payload: dict[str, Any] | None = None
    notes: str | None = None
    tags: list[str] | None = None
    thumbnail_data_url: str | None = None
    file_name: str | None = None
    file_mime_type: str | None = None
    file_size: int | None = None
    file_data_url: str | None = None


class DocVaultEntryResponse(DocVaultEntryBase):
    id: int
    created_by: int | None = None
    is_archived: bool
    created_at: datetime
    updated_at: datetime
    expiry_status: str
    days_delta: int | None = None
    alerting: bool = False
    sensitive_available: bool = False
    attachment_versions_count: int = 0
    signatures_count: int = 0

    model_config = {"from_attributes": True}


class DocVaultUnlockRequest(BaseModel):
    factor_id: str = Field(min_length=1)
    user_input: str = Field(min_length=1)
    window: int = Field(default=1, ge=0)


class DocVaultScanRequest(BaseModel):
    category: Literal["credit_card", "id_card"]
    file_name: str | None = None
    image_data_url: str | None = None


class DocVaultScanResponse(BaseModel):
    category: str
    extracted: dict[str, Any]
    confidence: float
    method: str
    requires_confirmation: bool = True


class DocVaultAttachmentVersionCreate(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    file_mime_type: str | None = None
    file_size: int | None = None
    file_data_url: str | None = None
    change_note: str | None = None


class DocVaultAttachmentVersionResponse(DocVaultAttachmentVersionCreate):
    id: int
    entry_id: int
    version: int
    checksum_sha256: str
    is_current: bool
    created_by: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class DocVaultSignatureCreate(BaseModel):
    signer_name: str = Field(min_length=1, max_length=160)
    signer_email: str | None = None
    provider: str = Field(default="manual", max_length=60)
    status: str = Field(default="signed", max_length=60)
    signature_reference: str | None = None


class DocVaultSignatureResponse(DocVaultSignatureCreate):
    id: int
    entry_id: int
    signed_payload: dict[str, Any] = Field(default_factory=dict)
    created_by: int | None = None
    signed_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class DocVaultRetentionRunResponse(BaseModel):
    archived_count: int
    archived_entry_ids: list[int]


class DocVaultAuditPackageRequest(BaseModel):
    entry_ids: list[int] | None = None
    include_archived: bool = False
    include_file_data: bool = False


class DocVaultAuditPackageResponse(BaseModel):
    generated_at: datetime
    generated_by: str | None = None
    entries: list[dict[str, Any]]
    manifest: dict[str, Any]
