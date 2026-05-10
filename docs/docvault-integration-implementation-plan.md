# DocVault API & MCP Integration — Implementation Plan

> Based on [api-and-mcp-integration-plan.md](./api-and-mcp-integration-plan.md)
>
> Created: 2026-05-10 | Revised: 2026-05-10

---

## Current State Summary

| Component | What exists today | Gap |
|---|---|---|
| **DocVault backend** | Full router (1 259 lines), models, schemas, MFA, versioned attachments, signatures, retention, audit packaging | No service layer — all logic is inline in `router.py` |
| **DocVault plugin hook** | `backend/__init__.py` registers routes at `/api/v1/docvault` | No MCP registration |
| **Expense attachments** | `ExpenseAttachment` model + `core/routers/expenses/attachments.py` | Files in `attachments/tenant_X/expenses/` or cloud. No DocVault link |
| **Invoice attachments** | `InvoiceAttachment` model + `core/routers/invoices/attachments.py` | Same pattern. No DocVault link |
| **Statement attachments** | `BankStatementAttachment` model + `core/routers/sync.py` | Same pattern. No DocVault link |
| **Inventory attachments** | `ItemAttachment` model + `core/services/attachment_service.py` | Same pattern. No DocVault link |
| **MCP server** | `api/MCP/` with FastMCP, tools, api_client | No `docvault_*` tools |
| **Generic document model** | Plan calls for `owner_type` / `owner_id` on documents | **Does not exist yet** |

---

## Deployment Model

DocVault remains a **separate repo** (`yfw-docvault/`). In plugin mode it is mounted as a **dynamic in-process plugin** via `docker-compose.plugin.yml` (volume-mounted into `/app/plugins_dynamic/docvault`). It uses the host app's tenant database, encrypted columns, auth, and MFA. This is distinct from sidecar plugins (like SocialHub) which run as separate Docker services behind nginx.

| Mode | Document API | MCP | Primary use case |
|---|---|---|---|
| **Plugin API + host MCP** | In-process inside `invoice_app` | Tools registered into the main YFW MCP server | Normal YFW deployments |
| **Standalone API + standalone MCP** | Own FastAPI service + DB | Own FastMCP server (`mcp/server.py`) | Self-hosted DocVault, demos |
| **Plugin API only** | In-process inside `invoice_app` | Disabled | Minimal plugin deployments |
| **Standalone API only** | Own FastAPI service + DB | Disabled | Simple vault app deployments |

Key principle: `invoice_app` components gain the _ability_ to cross-link attachments into DocVault when the plugin is present, but all hooks are optional and fail-safe.

---

## Architecture Overview

```text
Plugin mode (dynamic in-process plugin)
  invoice_app
    auth / tenants / audit / MFA / encryption
    DocVault plugin API  (plugins_dynamic/docvault/backend/)
    main YFW MCP server  (api/MCP/)
      docvault_* tools  (api/MCP/server/docvault.py)

    Plugin Hook Registry  (core/hooks/attachment_hooks.py)
      on_attachment_uploaded → DocVaultAdapter (if plugin loaded)

    Expense router ──┐
    Invoice router ──┤── fire("attachment_uploaded", ...) ──▶ Hook Registry
    Statement router ─┤                                          │
    Inventory router ─┘                                          ▼
                                                       DocVaultAdapter
                                                       (isolated session)
                                                              │
                                                              ▼
                                                    DocVaultDocumentLink
                                                    (owner_type + owner_id)
                                                              │
                                                              ▼
                                                    DocVaultEntry

Standalone mode
  yfw-docvault
    DocVault FastAPI  (backend/main.py)
    DocVault database (backend/database.py)
    DocVault MCP server  (mcp/server.py)
      mcp/client.py → DocVault API
      docvault_* tools
```

---

## Phase 1 — Extract Service Layer

**Goal:** Move all business logic out of `router.py` into `service.py` so API routes _and_ MCP tools share the same code path.

### Files

| File | Action |
|---|---|
| `yfw-docvault/backend/service.py` | **Create** — `DocVaultService` class |
| `yfw-docvault/backend/router.py` | **Refactor** — thin routes delegating to service |

### `DocVaultService` outline

```python
class DocVaultService:
    def __init__(self, db: Session, user_id: int | None = None):
        self.db = db
        self.user_id = user_id

    # Entry CRUD
    def list_entries(self, *, category=None, q=None, tag=None) -> list: ...
    def create_entry(self, payload) -> dict: ...
    def update_entry(self, entry_id: int, payload) -> dict: ...
    def archive_entry(self, entry_id: int) -> None: ...

    # MFA / Unlock
    def unlock_entry(self, entry_id: int, mfa_payload) -> dict: ...

    # Attachment Versions
    def list_attachment_versions(self, entry_id: int) -> list: ...
    def create_attachment_version(self, entry_id: int, payload) -> dict: ...

    # Signatures
    def list_signatures(self, entry_id: int) -> list: ...
    def create_signature(self, entry_id: int, payload) -> dict: ...

    # Cross-service document linking (Phase 2)
    def link_document(self, entry_id: int, owner_type: str, owner_id: int) -> dict: ...
    def list_documents_for_entity(self, owner_type: str, owner_id: int) -> list: ...
    def register_external_document(self, *, owner_type, owner_id, ...) -> dict: ...

    # Audit & retention
    def run_retention_policies(self) -> dict: ...
    def create_audit_package(self, payload) -> dict: ...

    # Search / classification (for MCP)
    def search_documents(self, *, q=None, category=None, tag=None, owner_type=None) -> list: ...
    def list_expiring_items(self, *, days_ahead: int = 30) -> list: ...
    def list_missing_classification(self) -> list: ...
    def classify_document(self, entry_id: int, label: str) -> dict: ...
    def get_retention_risks(self) -> list: ...
```

Private helpers (`_serialize`, `_expiry_status`, `_verify_mfa`, etc.) move into the service. Route handlers become ~5 lines each.

---

## Phase 2 — Generic Document Link Model

**Goal:** Create `DocVaultDocumentLink` + `DocVaultAttachmentLocator` tables for cross-entity linking with secure file references.

### New models

```python
# yfw-docvault/backend/models.py  (append)

class DocVaultDocumentLink(Base):
    __tablename__ = "docvault_document_links"

    id = Column(Integer, primary_key=True, index=True)
    entry_id = Column(Integer, ForeignKey("docvault_entries.id", ondelete="CASCADE"),
                      nullable=False, index=True)
    owner_type = Column(String, nullable=False, index=True)
    owner_id = Column(Integer, nullable=False, index=True)
    linked_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("entry_id", "owner_type", "owner_id", name="uq_docvault_link"),
    )


class DocVaultAttachmentLocator(Base):
    """Secure storage locator for externally-linked attachments.

    File paths, cloud keys, and storage implementation details are stored
    here — NOT in public_metadata — so they are never exposed through
    list/search/MCP metadata responses.
    """
    __tablename__ = "docvault_attachment_locators"

    id = Column(Integer, primary_key=True, index=True)
    entry_id = Column(Integer, ForeignKey("docvault_entries.id", ondelete="CASCADE"),
                      nullable=False, index=True, unique=True)
    storage_provider = Column(String, nullable=False, default="local")  # local, s3, azure, gcs
    storage_key = Column(String, nullable=False)       # file path or cloud object key
    source_table = Column(String, nullable=True)       # expense_attachments, invoice_attachments, etc.
    source_attachment_id = Column(Integer, nullable=True)  # PK in the source attachment table
    original_checksum = Column(String(64), nullable=True)  # SHA-256 from the source system
    created_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))
```

### New schemas

```python
VALID_OWNER_TYPES = {"invoice", "expense", "statement", "inventory", "portfolio", "docvault_entry"}

class DocVaultDocumentLinkCreate(BaseModel):
    owner_type: str = Field(min_length=1, max_length=60)
    owner_id: int

class DocVaultDocumentLinkResponse(DocVaultDocumentLinkCreate):
    id: int
    entry_id: int
    linked_by: int | None = None
    created_at: datetime
    entry_title: str | None = None
    entry_category: str | None = None
    file_name: str | None = None
    model_config = {"from_attributes": True}
```

### Update `plugin.json` (complete table list)

```diff
- "database_tables": ["docvault_entries", "docvault_attachment_versions", "docvault_signatures"],
+ "database_tables": [
+   "docvault_entries",
+   "docvault_attachment_versions",
+   "docvault_signatures",
+   "docvault_mfa_enrollments",
+   "docvault_share_tokens",
+   "docvault_document_links",
+   "docvault_attachment_locators"
+ ],
```

### Migration

```sql
CREATE TABLE docvault_document_links (
    id SERIAL PRIMARY KEY,
    entry_id INTEGER NOT NULL REFERENCES docvault_entries(id) ON DELETE CASCADE,
    owner_type VARCHAR NOT NULL,
    owner_id INTEGER NOT NULL,
    linked_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_docvault_link UNIQUE (entry_id, owner_type, owner_id)
);
CREATE INDEX ix_dv_links_entry ON docvault_document_links(entry_id);
CREATE INDEX ix_dv_links_owner ON docvault_document_links(owner_type, owner_id);

CREATE TABLE docvault_attachment_locators (
    id SERIAL PRIMARY KEY,
    entry_id INTEGER NOT NULL UNIQUE REFERENCES docvault_entries(id) ON DELETE CASCADE,
    storage_provider VARCHAR NOT NULL DEFAULT 'local',
    storage_key VARCHAR NOT NULL,
    source_table VARCHAR,
    source_attachment_id INTEGER,
    original_checksum VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Phase 3 — Plugin Hook Registry & Cross-Service Integration

**Goal:** Decouple cross-service hooks so core routers never import the DocVault plugin directly. Use a host-side **plugin hook registry** that DocVault registers into at plugin load time.

### 3a. Plugin Hook Registry (host-side)

```python
# core/hooks/attachment_hooks.py

"""Optional plugin hook registry for attachment lifecycle events.

Core routers fire events here. Plugins register handlers at load time.
If no handlers are registered, calls are no-ops.
"""

import logging
from typing import Callable, Optional
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Handler type: (db_session_factory, user_id, event_data) -> None
AttachmentHandler = Callable

_handlers: list[AttachmentHandler] = []


def register_handler(handler: AttachmentHandler) -> None:
    _handlers.append(handler)
    logger.info("Attachment hook registered: %s", handler.__qualname__)


def fire_attachment_uploaded(
    db_session_factory: Callable[[], Session],
    user_id: int,
    *,
    owner_type: str,
    owner_id: int,
    file_name: str | None = None,
    file_mime_type: str | None = None,
    file_size: int | None = None,
    file_hash: str | None = None,
    storage_provider: str = "local",
    storage_key: str = "",
    source_table: str | None = None,
    source_attachment_id: int | None = None,
) -> None:
    """Fire the attachment_uploaded event to all registered handlers.

    Each handler runs in its OWN database session to prevent shared-session
    failures from corrupting the caller's transaction.
    """
    if not _handlers:
        return

    event_data = {
        "owner_type": owner_type,
        "owner_id": owner_id,
        "file_name": file_name,
        "file_mime_type": file_mime_type,
        "file_size": file_size,
        "file_hash": file_hash,
        "storage_provider": storage_provider,
        "storage_key": storage_key,
        "source_table": source_table,
        "source_attachment_id": source_attachment_id,
    }

    for handler in _handlers:
        try:
            handler(db_session_factory, user_id, event_data)
        except Exception as exc:
            logger.warning("Attachment hook %s failed (non-fatal): %s",
                           handler.__qualname__, exc)
```

### 3b. DocVault adapter (plugin-side, registers at load time)

```python
# yfw-docvault/backend/hooks.py

"""DocVault handler for the host attachment hook registry."""

import logging
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def handle_attachment_uploaded(db_session_factory, user_id: int, event_data: dict):
    """Create a DocVaultEntry + link for an externally uploaded attachment.

    Runs in its own session so failures never corrupt the caller's transaction.
    """
    from .service import DocVaultService
    from .models import DocVaultDocumentLink, DocVaultAttachmentLocator, DocVaultEntry

    db: Session = db_session_factory()
    try:
        svc = DocVaultService(db, user_id=user_id)
        svc.register_external_document(
            owner_type=event_data["owner_type"],
            owner_id=event_data["owner_id"],
            file_name=event_data.get("file_name"),
            file_mime_type=event_data.get("file_mime_type"),
            file_size=event_data.get("file_size"),
            file_hash=event_data.get("file_hash"),
            storage_provider=event_data.get("storage_provider", "local"),
            storage_key=event_data.get("storage_key", ""),
            source_table=event_data.get("source_table"),
            source_attachment_id=event_data.get("source_attachment_id"),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
```

### 3c. Registration at plugin load time

```python
# yfw-docvault/backend/__init__.py  (updated)

def register_plugin(app, mcp_registry=None, feature_gate=None):
    from .router import router
    app.include_router(router, prefix="/api/v1/docvault", tags=["docvault"])

    # Register cross-service hook (optional — if host supports it)
    try:
        from core.hooks.attachment_hooks import register_handler
        from .hooks import handle_attachment_uploaded
        register_handler(handle_attachment_uploaded)
    except ImportError:
        pass  # Host doesn't have hook registry, or standalone mode

    # Register MCP tools (optional)
    if mcp_registry is not None:
        try:
            from .mcp_registration import register_docvault_tools
            register_docvault_tools(mcp_registry)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("DocVault MCP registration failed: %s", exc)

    return {"name": "docvault", "version": "1.0.0", "routes": ["/api/v1/docvault"]}
```

### 3d. Core routers fire the event (no plugin imports)

```python
# Example: core/routers/expenses/attachments.py — after db.commit()

from core.hooks.attachment_hooks import fire_attachment_uploaded
from core.models.database import SessionLocal

fire_attachment_uploaded(
    db_session_factory=SessionLocal,
    user_id=current_user.id,
    owner_type="expense",
    owner_id=expense_id,
    file_name=file.filename,
    file_mime_type=file.content_type,
    file_size=len(contents),
    file_hash=file_hash,
    storage_provider="local",         # or "s3" if cloud
    storage_key=str(file_path),
    source_table="expense_attachments",
    source_attachment_id=attachment.id,
)
```

### 3e. Secure `register_external_document` (service-side)

```python
def register_external_document(self, *, owner_type, owner_id,
                               file_name=None, file_mime_type=None,
                               file_size=None, file_hash=None,
                               storage_provider="local", storage_key="",
                               source_table=None, source_attachment_id=None):
    """Create a DocVault entry + locator + link for an external attachment.

    - File paths/keys go into DocVaultAttachmentLocator (never public_metadata).
    - Original checksum is stored from the source system (not recomputed from absent bytes).
    - No file bytes are duplicated.
    """
    entry = DocVaultEntry(
        category="document",
        title=file_name or f"{owner_type}_{owner_id}_attachment",
        file_name=file_name,
        file_mime_type=file_mime_type,
        file_size=file_size,
        public_metadata={
            "source_module": owner_type,
            "source_id": owner_id,
            "document_label": "unclassified",
            "approval_status": "draft",
        },
        created_by=self.user_id,
    )
    self.db.add(entry)
    self.db.flush()

    # Secure locator — file path/key never in public metadata
    locator = DocVaultAttachmentLocator(
        entry_id=entry.id,
        storage_provider=storage_provider,
        storage_key=storage_key,
        source_table=source_table,
        source_attachment_id=source_attachment_id,
        original_checksum=file_hash,
    )
    self.db.add(locator)

    # Attachment version (metadata only — no file_data_url unless provided)
    self._create_attachment_version(
        entry,
        file_name=file_name,
        file_mime_type=file_mime_type,
        file_size=file_size,
        change_note=f"Linked from {owner_type} module",
        external_checksum=file_hash,
    )

    link = DocVaultDocumentLink(
        entry_id=entry.id,
        owner_type=owner_type,
        owner_id=owner_id,
        linked_by=self.user_id,
    )
    self.db.add(link)
    # NOTE: caller is responsible for commit (isolated session pattern)
    return {"entry_id": entry.id, "link_id": link.id if link.id else None}
```

### 3f. New API routes on the DocVault router

| Method | Path | Description |
|---|---|---|
| `POST` | `/{entry_id}/links` | Link a docvault entry to an entity |
| `GET` | `/{entry_id}/links` | List all entity links for an entry |
| `DELETE` | `/{entry_id}/links/{link_id}` | Remove a link |
| `GET` | `/by-entity/{owner_type}/{owner_id}` | List all docvault entries linked to an entity |

---

## Phase 4 — MCP Tools (Plugin + Standalone)

**Goal:** Provide MCP tools in **both** deployment modes.

### 4a. Plugin mode — host MCP server

Add `api/MCP/server/docvault.py` following the existing pattern (see `investments.py`):

```python
# api/MCP/server/docvault.py
from ._shared import mcp, server_context

@mcp.tool()
async def docvault_search_documents(q: str = "", category: str = "", tag: str = "") -> dict:
    """Search DocVault entries by keyword, category, or tag."""
    if server_context.tools is None:
        return {"success": False, "error": "Server not properly initialized"}
    return await server_context.tools.docvault_search_documents(q=q, category=category, tag=tag)

# ... 8 more tools (see tool table below)
```

Register in `api/MCP/server/__init__.py`:
```diff
  from . import (
      ...
      investments,
+     docvault,
  )
```

Add tool methods to `api/MCP/tools/__init__.py` (or a new `docvault_tools.py`) calling the DocVault API endpoints via `api_client`.

### 4b. Standalone mode — own MCP server

Create these files inside `yfw-docvault/`:

| File | Description |
|---|---|
| `mcp/__init__.py` | Package init |
| `mcp/server.py` | Standalone FastMCP server with lifespan, auth config, and `docvault_*` tools |
| `mcp/client.py` | HTTP client for the standalone DocVault API (auth, token refresh) |
| `mcp/config.py` | Env var config: `DOCVAULT_API_URL`, `DOCVAULT_API_EMAIL`, `DOCVAULT_API_PASSWORD` |
| `mcp/__main__.py` | Entry point: `python -m mcp` |

```python
# yfw-docvault/mcp/config.py
import os

DOCVAULT_API_URL = os.environ.get("DOCVAULT_API_URL", "http://localhost:8000/api/v1/docvault")
DOCVAULT_API_EMAIL = os.environ.get("DOCVAULT_API_EMAIL", "")
DOCVAULT_API_PASSWORD = os.environ.get("DOCVAULT_API_PASSWORD", "")
```

```python
# yfw-docvault/mcp/server.py  (skeleton)
from fastmcp import FastMCP
from .client import DocVaultAPIClient
from .config import DOCVAULT_API_URL, DOCVAULT_API_EMAIL, DOCVAULT_API_PASSWORD

mcp = FastMCP("DocVault MCP Server")
_client: DocVaultAPIClient | None = None

@mcp.on_event("startup")
async def startup():
    global _client
    _client = DocVaultAPIClient(DOCVAULT_API_URL, DOCVAULT_API_EMAIL, DOCVAULT_API_PASSWORD)
    await _client.authenticate()

@mcp.tool()
async def docvault_search_documents(q: str = "", category: str = "") -> dict:
    return await _client.get("/", params={"q": q, "category": category})

# ... same 9 tools as plugin mode, calling _client instead of server_context.tools

def main():
    mcp.run()
```

### Tool table (both modes)

| Tool | Description |
|---|---|
| `docvault_search_documents` | Search entries by keyword, category, tag, linked entity |
| `docvault_get_document_metadata` | Get metadata for an entry (no sensitive content) |
| `docvault_list_expiring_items` | List entries expiring within N days |
| `docvault_list_missing_classification` | List document entries lacking a label |
| `docvault_classify_document` | Set/update classification label |
| `docvault_link_document_to_entity` | Link an entry to a domain entity |
| `docvault_list_entity_documents` | List entries linked to a specific entity |
| `docvault_create_audit_package` | Generate audit-ready package |
| `docvault_get_retention_risks` | List entries approaching/past retention |

Sensitive tools (deferred — require capability flags + MFA):
`docvault_unlock_sensitive_entry`, `docvault_reveal_secret`, `docvault_download_attachment`, `docvault_delete_document`, `docvault_share_document`.

---

## Phase 5 — Higher-Level Agent Workflows

| Workflow | Description |
|---|---|
| **Missing receipt detection** | Agent queries expenses without linked DocVault documents |
| **Audit readiness** | Agent checks entries for classification, signatures, retention |
| **Retention risk review** | Agent flags entries past retention deadline |
| **Document classification** | Agent suggests labels based on filename, metadata, tags |
| **Duplicate detection** | Agent compares `original_checksum` across `DocVaultAttachmentLocator` rows |

---

## Security Rules for Agents

- Return metadata, risk signals, summaries, checksums, labels, and links — never raw file paths or cloud keys.
- Do not reveal passwords, private keys, recovery codes, or sensitive payloads unless the user has satisfied the required unlock flow.
- Treat file download and attachment content extraction as privileged actions.
- Log all reveal, copy, download, export, share, and delete actions.
- Keep tenant context and user identity attached to every MCP tool call.

---

## Execution Order

| Phase | Effort | Dependencies |
|---|---|---|
| **Phase 1:** Service layer extraction | ~2-3 hours | None |
| **Phase 2:** Document link + locator models, migration | ~1-2 hours | Phase 1 |
| **Phase 3:** Hook registry + adapter + API routes | ~3-4 hours | Phase 2 |
| **Phase 4a:** Host MCP tools (`api/MCP/server/docvault.py`) | ~2 hours | Phase 1 + 3 |
| **Phase 4b:** Standalone MCP server (`mcp/server.py`) | ~2-3 hours | Phase 1 |
| **Phase 5:** Agent workflows | ~2-3 hours | Phase 4 |

---

## Design Decisions

1. **No file duplication.** DocVault entries for cross-linked attachments reference the original via `DocVaultAttachmentLocator`. File paths and cloud keys are stored there — never in `public_metadata`.

2. **Source checksums.** `original_checksum` is stored from the source system at link time. DocVault does not recompute checksums from absent file bytes. Duplicate detection and audit manifests use this stored value.

3. **Session isolation.** Cross-service hooks run in their own `Session` (provided by `db_session_factory`) so failures never corrupt the caller's transaction. The adapter handles commit/rollback internally.

4. **Decoupled integration.** Core routers fire events on `core.hooks.attachment_hooks` — they never import the DocVault plugin. DocVault registers a handler at plugin load time. If DocVault is not installed, the hook registry has zero handlers and calls are no-ops.

5. **Complete `plugin.json`.** The manifest lists all 7 tables: `docvault_entries`, `docvault_attachment_versions`, `docvault_signatures`, `docvault_mfa_enrollments`, `docvault_share_tokens`, `docvault_document_links`, `docvault_attachment_locators`.

6. **Plugin event bus.** The hook registry is intentionally minimal (a list of callables). It can be extended to support more event types (`attachment_deleted`, `attachment_updated`) as needed, but this plan only introduces `attachment_uploaded`.

7. **Frontend.** This plan is backend-only. Frontend changes ("View in DocVault" link, classification badge) are a follow-up.
