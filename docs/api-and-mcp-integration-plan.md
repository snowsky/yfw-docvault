# DocVault API And MCP Integration Plan

This plan defines how DocVault should expose document capabilities to other YourFinanceWORKS services and to AI agents while remaining usable as either a plugin or a standalone application.

## Decision

DocVault should expose both:

- A document API for product and service integration.
- MCP tools for AI agent integration.

The API is the canonical contract. MCP tools should call the API instead of bypassing it or querying DocVault tables directly.

```text
UI / mobile / services -> DocVault or platform document API
AI agents             -> MCP tools -> DocVault or platform document API
```

## Integration Modes

DocVault should support four deployment combinations:

| Mode | Document API | MCP | Primary use case |
| --- | --- | --- | --- |
| Plugin API + host MCP | Runs inside `invoice_app` with the host tenant database | Registered into the main YFW MCP server | Normal YFW deployments |
| Standalone API + standalone MCP | Runs as its own DocVault service and database | Runs as a DocVault MCP server | Self-hosted DocVault, demos, external installs |
| Plugin API only | Runs inside `invoice_app` | Disabled | Minimal plugin deployments |
| Standalone API only | Runs as its own DocVault service and database | Disabled | Simple vault/document app deployments |

## Recommended Architecture

```text
Plugin mode
  invoice_app
    auth / tenants / audit / MFA / encryption
    DocVault plugin API
    main YFW MCP server
      docvault_* tools

Standalone mode
  yfw-docvault
    DocVault API
    DocVault database
    optional DocVault MCP server
      docvault_* tools
```

## API Responsibilities

The document API should be the stable service contract for invoices, expenses, statements, portfolio, mobile clients, plugins, and external clients.

Core API responsibilities:

- Create, upload, and register documents.
- Link documents to domain entities such as invoices, expenses, statements, portfolio records, and DocVault entries.
- List documents for an entity.
- Read document metadata.
- Download or retrieve an attachment when permitted.
- Track document versions and checksums.
- Set classification, approval status, expiry, retention policy, and ownership metadata.
- Record audit events for access, changes, exports, unlocks, copies, and sharing.
- Enforce tenant isolation, authorization, MFA gates, encryption, and retention rules.

For cross-service use, the preferred relationship model is a generic document owner reference:

```text
document
  id
  tenant_id
  owner_type     # invoice, expense, statement, portfolio, docvault_entry, etc.
  owner_id
  classification
  approval_status
  retention_policy
```

## MCP Responsibilities

MCP should expose agent-friendly workflows on top of the API. It should not be the primary integration path for backend services.

Initial MCP tools should focus on safe read, search, classification, and workflow actions:

- `docvault_search_documents`
- `docvault_get_document_metadata`
- `docvault_list_expiring_items`
- `docvault_list_missing_classification`
- `docvault_classify_document`
- `docvault_link_document_to_entity`
- `docvault_create_audit_package`
- `docvault_get_retention_risks`

Sensitive tools require stricter controls:

- `docvault_unlock_sensitive_entry`
- `docvault_reveal_secret`
- `docvault_download_attachment`
- `docvault_delete_document`
- `docvault_share_document`

These sensitive tools should require explicit capability flags, user confirmation where appropriate, MFA or unlock checks, and audit logging.

## Security Rules For Agents

Agents should receive the minimum useful information by default.

- Return metadata, risk signals, summaries, checksums, labels, and links before returning raw file contents.
- Do not reveal passwords, private keys, recovery codes, or sensitive payloads unless the user has satisfied the required unlock flow.
- Treat file download and attachment content extraction as privileged actions.
- Log all reveal, copy, download, export, share, and delete actions.
- Keep tenant context and user identity attached to every MCP tool call.
- Prefer structured results over prose so downstream agents can reason over the output safely.

Example safe workflow:

```text
User: Which secrets are overdue for rotation?
MCP: returns item metadata, health status, owner, age, and rotation recommendation.

User: Reveal this password.
MCP: requires the same MFA or unlock policy as the API before returning any secret value.
```

## Repository Layout

The preferred layout keeps shared behavior in the API and keeps MCP as a thin agent-facing layer.

```text
yfw-docvault/
  backend/
    router.py              # REST API routes
    service.py             # shared business logic
    models.py
    schemas.py
    auth.py
  mcp/
    server.py              # standalone MCP server
    tools.py               # tool definitions
    client.py              # calls DocVault API
  plugin/
    __init__.py            # register API routes with host app
    mcp.py                 # register DocVault tools with host MCP, when available
```

## Plugin Mode

In plugin mode, DocVault should use host platform services:

- Host authentication.
- Tenant database and tenant context.
- MFA and unlock flows.
- Encryption helpers.
- Audit trail.
- Plugin permission manifest.
- Main YFW MCP registry.

The main YFW MCP server should be the default agent entrypoint when DocVault is installed as a plugin. DocVault should contribute `docvault_*` tools to that registry rather than requiring a second MCP server for normal YFW deployments.

## Standalone Mode

In standalone mode, DocVault should provide local equivalents:

- Local authentication or API token support.
- DocVault-owned database.
- DocVault-owned audit records.
- Optional local MFA or unlock policy.
- Standalone MCP server for agents that connect directly to DocVault.

Standalone MCP should use the same tool names and response shapes as plugin MCP where practical.

## Implementation Order

1. Introduce a backend service layer so API routes and MCP wrappers share behavior.
2. Stabilize the document API for create, list, metadata, link, version, classify, and audit-package workflows.
3. Add standalone MCP tools that call the DocVault API through a small client.
4. Add plugin MCP registration so DocVault can contribute tools to the host YFW MCP server.
5. Add capability checks and audit events for sensitive MCP tools.
6. Integrate invoices, expenses, statements, portfolio, and mobile clients through the API.
7. Add higher-level agent workflows such as missing receipt detection, audit readiness, retention risk review, and document classification.

## Boundary

The long-term boundary should remain:

```text
API = product and service contract
MCP = AI agent contract
DocVault = vault and document management app
Core document service = shared platform primitive
```

This keeps DocVault flexible as a plugin or standalone product while giving other services and agents a consistent way to work with documents.
