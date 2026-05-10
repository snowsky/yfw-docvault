# DocVault Feature Roadmap

This roadmap captures the plan to evolve DocVault from a secure document and expiry tracker into a richer vault experience inspired by mature password managers and document management systems.

## Product Direction

DocVault should remain a secure operational tool for credentials, identity records, certificates, and business documents. The next feature set should improve three areas:

- Password-manager workflows for creating, reviewing, rotating, and securely revealing secrets.
- Document-manager workflows for organizing, classifying, approving, versioning, and retaining files.
- Security dashboards that turn stored records into actionable risk signals.

## Current Foundation

DocVault already supports:

- Credit card, SSL certificate, ID/health card, document, password, and private key records.
- MFA-gated sensitive detail unlocks.
- Masked sensitive payloads in list responses.
- Expiry tracking and alert badges.
- Versioned document attachments with checksum history.
- Google Drive and OneDrive document links.
- Digital signature records.
- Retention archive runs.
- Audit package generation.
- Immutable records that can be created once and protected from later edits while still allowing intentional deletion.

## Phase 1: Vault Quality

Goal: make password and secret records useful enough for daily use.

Planned capabilities:

- Password generator with strong default settings.
- Password health scoring.
- Weak password detection.
- Reused password detection.
- Old or overdue rotation detection.
- Secret metadata fields such as username, login URL, and rotation interval.
- Copy-to-clipboard flows with audit events and later auto-clear behavior.
- Secret item subtypes such as login, API key, SSH key, database credential, recovery code, and secure note.

Implemented:

- Password generator in the secret entry form.
- Frontend password strength preview.
- Backend `secret_health` response metadata.
- Weak, reused, missing metadata, and rotation review signals.
- At-risk secret dashboard summary.
- Secret health badges on list rows and unlocked detail views.
- Creation-time immutable item option with backend enforcement against later edit, relink, replacement, and automated retention archival, while allowing intentional user deletion.

## Phase 2: Shared Vaults And Permissions

Goal: support team use cases without exposing sensitive material too broadly.

Planned capabilities:

- Vaults or folders as first-class containers.
- Per-vault roles for metadata view, secret reveal, edit, delete, export, and share.
- Shared vaults for teams or departments.
- Guest access for limited entries.
- Expiring secure share links for individual entries or documents.
- Access review dashboard showing who can see each vault or item.

Likely backend additions:

- `docvault_vaults`
- `docvault_vault_members`
- `docvault_share_links`
- Audit events for reveal, copy, export, and share actions.

## Phase 3: Document Manager Upgrade

Goal: make documents easier to classify, govern, and approve.

Planned capabilities:

- Folder, collection, or saved-view navigation.
- Rich metadata templates by document type.
- Classification labels such as confidential, finance, legal, HR, identity, tax, vendor, and audit.
- Approval workflow states such as requested, approved, rejected, and needs changes.
- File locking during approval.
- Activity timeline per document.
- Better version compare and restore flows.
- Metadata-first search, with OCR as a later enhancement.
- Retention policies by category, label, or document type.

Implemented:

- Classification label field for document entries.
- Approval status field for document entries.
- Document review dashboard counts for pending approvals and unclassified documents.
- Label and approval status badges on document rows.
- Explicit document workflow metadata in audit package entries.

## Phase 4: Security Dashboard

Goal: turn DocVault into a risk review surface, not only a storage surface.

Planned signals:

- Expiring cards, IDs, SSL certificates, and documents.
- Weak, reused, or old passwords.
- Secrets that have never been rotated.
- Documents missing owner, label, expiry, or retention policy.
- Items with broad sharing.
- Recently revealed or copied secrets.
- MFA enrollment status.
- Audit export readiness.

Implemented:

- Field-level copy buttons for unlocked secret usernames, login URLs, passwords, and private keys.
- Clipboard auto-clear after 30 seconds when browser permissions allow it.
- Dedicated backend copy audit events separate from unlock events.

## Phase 5: Advanced Integrations

Goal: add power-user and compliance features after the core workflows are stable.

Candidate capabilities:

- Passkey and WebAuthn item tracking.
- Emergency access or trusted recovery contact.
- Travel mode for temporarily hiding non-travel-safe vaults or items.
- Browser extension or autofill integration.
- Breach monitoring integration.
- OCR auto-extraction for IDs, cards, certificates, and invoices.
- AI-assisted document classification.
- External provider sync with Google Drive, OneDrive, SharePoint, or Dropbox.
- Compliance evidence reports for audits.

## Suggested Next Slice

The next practical implementation slice should be recent security activity in the dashboard.

Scope:

- Expose recent unlock and copy events from the audit trail.
- Show recently revealed/copied secrets without exposing secret values.
- Add filters for user, action type, and time window.
- Include security activity in audit package manifests.

This builds on the copy audit events and gives administrators a fast way to review sensitive access.
