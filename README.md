# DocVault

DocVault is a document and expiry manager for YourFinanceWORKS. It can run as a standalone app with its own Postgres database, or as an in-process plugin for `invoice_app` using the main app's tenant database.

## Features

- Credit card, SSL certificate, ID/health card, document, password, and private key tracking
- Expiry status badges for expired, expiring soon, and valid items
- AI-assisted card scan confirmation flow
- MFA-gated access to sensitive details in plugin mode
- Version-controlled document attachments with checksum history
- Google Drive and OneDrive document links with provider-aware validation
- Digital signature records for document approvals
- Retention policy automation with archive runs
- Audit-ready package generation for external auditors

See [DocVault Feature Roadmap](docs/feature-roadmap.md) for the planned password-manager and document-manager enhancements.

## Folder Layout

```text
yfw-docvault/
  backend/                 Standalone FastAPI app and shared plugin backend
  frontend/                Standalone Vite/React app and shared plugin UI
  plugin/ui/index.ts       Compatibility entry for invoice_app plugin discovery
  docker-compose.yml       Standalone app stack
  docker-compose.plugin.yml invoice_app plugin-mode overlay
  docker-compose.promote.yml promotion helper
  plugin.json              Plugin manifest
```

## Run Standalone

From the `yfw-docvault` directory:

```bash
docker compose up --build
```

Open:

```text
http://localhost:5174
```

Standalone mode starts:

- `db` - Postgres 16
- `backend` - FastAPI DocVault API
- `frontend` - Nginx-served React app

Standalone mode uses `DOCVAULT_DATABASE_URL` and the local `docvault` database.

Use standalone mode when you want DocVault isolated from `invoice_app`, such as for plugin development, demos, or testing the plugin by itself. This mode does not use the main repo's tenant database.

## Run As invoice_app Plugin

From the sibling `invoice_app` directory:

```bash
docker compose -f docker-compose.yml -f yfw-docvault/docker-compose.plugin.yml up --build
```

Plugin mode mounts this folder into:

```text
/app/plugins_dynamic/docvault
/app/src/plugins_dynamic/docvault
```

In this mode DocVault imports the host app's `core.*` database, auth, encryption, audit, and MFA helpers. Its tables are created in the same tenant database path as the rest of `invoice_app`.

Use plugin mode when you want DocVault to share the same database as this repo without copying files into the repo.

## Promote Into invoice_app

From the `invoice_app` directory:

```bash
python -B api/scripts/promote_plugin.py yfw-docvault --force
```

Or from the `yfw-docvault` directory:

```bash
docker compose -f docker-compose.promote.yml run --rm promote
```

The promotion script copies:

- `backend/*` to `invoice_app/api/plugins/docvault/`
- `frontend/src/*` to `invoice_app/ui/src/plugins/docvault/plugin/ui/`

By default, promoted backend files remain ignored by `invoice_app/.gitignore`. Use `--track-backend` only if you intentionally want to commit the promoted backend copy.

Use promotion when you want DocVault copied into `invoice_app` and loaded like an in-repo plugin. Promoted DocVault uses the same `invoice_app` tenant database because the copied backend runs inside the host API process and imports the host `core.*` database/session helpers.

## Which Mode Uses Which Database?

| Mode | Command | Database |
| --- | --- | --- |
| Standalone app | `docker compose up --build` from `yfw-docvault` | DocVault's own Postgres database |
| Dynamic plugin | `docker compose -f docker-compose.yml -f yfw-docvault/docker-compose.plugin.yml up --build` from `invoice_app` | `invoice_app` tenant database |
| Promoted plugin | `python -B api/scripts/promote_plugin.py yfw-docvault --force` from `invoice_app` | `invoice_app` tenant database |

If your goal is to use the same database as this repo, use dynamic plugin mode or promoted plugin mode. Do not use standalone mode for shared tenant data.

## Database Tables

DocVault uses these tables:

- `docvault_entries`
- `docvault_attachment_versions`
- `docvault_signatures`

Standalone mode creates these tables in its own Postgres database.

Plugin/promoted mode uses the `invoice_app` tenant database. Existing tenants may need the app's plugin table creation or migration path to run once after DocVault is installed.

## API Highlights

```text
GET    /api/v1/docvault
POST   /api/v1/docvault
PUT    /api/v1/docvault/{entry_id}
DELETE /api/v1/docvault/{entry_id}
POST   /api/v1/docvault/{entry_id}/unlock
POST   /api/v1/docvault/scan-card

GET    /api/v1/docvault/{entry_id}/attachments
POST   /api/v1/docvault/{entry_id}/attachments
POST   /api/v1/docvault/{entry_id}/cloud-link
GET    /api/v1/docvault/{entry_id}/signatures
POST   /api/v1/docvault/{entry_id}/signatures
POST   /api/v1/docvault/retention/run
POST   /api/v1/docvault/audit-package
POST   /api/v1/docvault/import/scan
POST   /api/v1/docvault/import/run
```

Plugin mode also supports importing existing host-app documents into DocVault.
The initial importer covers bank statements and is idempotent: scan/run creates
DocVault entries plus secure source locators for unlinked statement files and
statement attachments without copying file bytes.

## Notes

- Standalone mode uses a local single-user auth shim.
- Plugin mode uses the host app's user, tenant, encryption, audit, and MFA systems.
- Sensitive payloads and private document data are masked unless the entry is unlocked.
- Audit packages exclude file data by default.
