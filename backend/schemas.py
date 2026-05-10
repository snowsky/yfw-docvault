"""DocVault API schemas."""

from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

DocVaultCategory = Literal["credit_card", "ssl_certificate", "id_card", "document", "secret"]
DocVaultCloudProvider = Literal["google_drive", "onedrive"]


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
    secret_health: dict[str, Any] | None = None
    attachment_versions_count: int = 0
    signatures_count: int = 0

    model_config = {"from_attributes": True}


class DocVaultUnlockRequest(BaseModel):
    factor_id: str = Field(min_length=1)
    user_input: str = Field(min_length=1)
    window: int = Field(default=1, ge=0)


class DocVaultCopyEventRequest(BaseModel):
    field_name: str = Field(min_length=1, max_length=80)


class DocVaultMFASetupRequest(BaseModel):
    factor_id: Literal["google_auth", "ms_auth"]
    label: str | None = Field(default=None, max_length=160)


class DocVaultMFASetupResponse(BaseModel):
    factor_id: str
    label: str | None = None
    secret: str
    otpauth_uri: str
    qr_data_url: str | None = None
    is_verified: bool = False


class DocVaultMFAVerifyRequest(BaseModel):
    factor_id: Literal["google_auth", "ms_auth"]
    code: str = Field(min_length=1)
    window: int = Field(default=1, ge=0)


class DocVaultMFAEnrollmentResponse(BaseModel):
    factor_id: str
    label: str | None = None
    is_verified: bool
    recovery_code_count: int = 0
    created_at: datetime
    verified_at: datetime | None = None


class DocVaultLocalUnlockSetupRequest(BaseModel):
    factor_id: Literal["vault_password", "recovery_code", "local_fallback"]
    secret: str | None = Field(default=None, min_length=1)
    codes: list[str] = Field(default_factory=list)


class DocVaultSystemMFAStatusResponse(BaseModel):
    available: bool
    enabled: bool
    configured: bool
    mode: str | None = None
    factors: list[str] = Field(default_factory=list)
    enrolled_factors: list[str] = Field(default_factory=list)
    supported_factors: list[dict[str, Any]] = Field(default_factory=list)
    message: str
    settings_path: str = "/settings?tab=profile"
    disable_script: str = "api/scripts/disable_user_mfa.py"


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


class DocVaultEntryHistoryResponse(BaseModel):
    id: int
    entry_id: int
    action: str
    changed_fields: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    restorable: bool = False
    created_by: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class DocVaultRestoreResponse(BaseModel):
    entry: DocVaultEntryResponse
    restored_from: dict[str, Any]


class DocVaultCloudLinkRequest(BaseModel):
    provider: DocVaultCloudProvider
    file_url: str = Field(min_length=1, max_length=2048)
    file_id: str | None = Field(default=None, max_length=255)
    file_name: str | None = Field(default=None, max_length=255)
    file_mime_type: str | None = None
    change_note: str | None = None


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


DocVaultImportComponent = Literal["bank_statement", "invoice", "expense"]


class DocVaultImportScanRequest(BaseModel):
    components: list[DocVaultImportComponent] = Field(default_factory=lambda: ["bank_statement", "invoice", "expense"])
    include_statement_files: bool = True
    include_statement_attachments: bool = True
    include_invoice_attachments: bool = True
    include_expense_attachments: bool = True
    limit: int | None = Field(default=None, ge=1, le=10000)


class DocVaultImportRunRequest(DocVaultImportScanRequest):
    dry_run: bool = False


class DocVaultImportCandidate(BaseModel):
    component: str
    owner_type: str
    owner_id: int
    source_table: str
    source_attachment_id: int
    file_name: str
    file_mime_type: str | None = None
    file_size: int | None = None
    storage_provider: str
    storage_key: str
    checksum_sha256: str | None = None
    already_imported: bool = False
    existing_entry_id: int | None = None


class DocVaultImportSummary(BaseModel):
    scanned: int
    importable: int
    already_imported: int
    imported: int = 0
    skipped: int = 0
    errors: list[dict[str, Any]] = Field(default_factory=list)


class DocVaultImportScanResponse(BaseModel):
    summary: DocVaultImportSummary
    candidates: list[DocVaultImportCandidate]


class DocVaultImportRunResponse(DocVaultImportScanResponse):
    dry_run: bool
    created_entry_ids: list[int] = Field(default_factory=list)
