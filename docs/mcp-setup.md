# DocVault MCP Server Setup & Configuration Guide

This guide describes how to run, configure, and test the Model Context Protocol (MCP) server integrated into DocVault. The MCP server allows external AI models (like Claude) to securely interact with your documents, check credential expiries, verify digital signatures, inspect audit histories, and run retention/auditor tasks.

---

## Prerequisites

1. **Python 3.12+**
2. **Node.js** (for running the MCP Inspector locally)
3. **DocVault Database**: Make sure the DocVault database is running (either standard standalone Postgres via docker, or a local Postgres server).

---

## Quick Start

### 1. Install Dependencies

Install the `mcp` SDK package in your virtual environment:

```bash
pip install -r backend/requirements.txt
```

*(Or manually install with `pip install mcp>=1.0.0`)*

### 2. Configure Environment Variables

The MCP server uses the same environment configuration as the FastAPI backend. By default, it connects to the local Postgres database. You can customize the connection by setting:

```bash
export DOCVAULT_DATABASE_URL="postgresql://docvault:docvault_pass@localhost:5432/docvault"
```

---

## Local Testing with MCP Inspector

You can test the MCP server locally in an interactive web browser UI using the official `@modelcontextprotocol/inspector` tool. This is highly recommended for developers to verify tool inputs, outputs, and schemas:

```bash
npx -y @modelcontextprotocol/inspector python3 backend/mcp_server.py
```

This command will:
1. Spin up the MCP server via `stdio` transport.
2. Launch a local web-based Inspector client in your browser (usually at `http://localhost:5173` or similar).
3. Let you manually trigger `list_entries`, `check_expiring_soon`, `create_entry`, and other tools.

---

## Claude Desktop Configuration

To use the DocVault MCP server inside Claude Desktop:

1. Open your Claude Desktop configuration file:
   - **MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

2. Add `docvault` under the `mcpServers` block:

```json
{
  "mcpServers": {
    "docvault": {
      "command": "python3",
      "args": [
        "/Users/hao/dev/github/machine_learning/hao_projects/yfw-docvault/backend/mcp_server.py"
      ],
      "env": {
        "DOCVAULT_DATABASE_URL": "postgresql://docvault:docvault_pass@localhost:5432/docvault"
      }
    }
  }
}
```

> [!NOTE]
> Make sure to adjust the absolute path to `mcp_server.py` and the `DOCVAULT_DATABASE_URL` connection parameters to match your local setup.

3. **Restart Claude Desktop**. You should see a plug icon indicating the `docvault` MCP server tools are successfully discovered and available.

---

## Exposed Tools

The DocVault MCP server exposes the following **12 professional tools** to AI agents:

| Tool Name | Parameters | Description |
| --- | --- | --- |
| `list_entries` | `category`, `tag`, `query` | Search and filter active DocVault entries. |
| `get_entry` | `entry_id` | Retrieve full details of a specific active DocVault entry. |
| `check_expiring_soon` | `days` | Identify documents, cards, or SSL certs expiring within the specified threshold. |
| `create_entry` | `category`, `title`, `owner_name`, `issuer`, `expiry_date`, `issue_date`, `notes`, `tags`, `sensitive_payload` | Create a new entry (document, card, password, etc.). |
| `update_entry` | `entry_id`, `title`, `owner_name`, `issuer`, `expiry_date`, `issue_date`, `notes`, `tags`, `sensitive_payload` | Update details of an existing DocVault entry. |
| `delete_entry` | `entry_id` | Soft delete / archive a DocVault entry. |
| `get_document_links` | `entry_id` | List references/links connecting a document to host-app modules. |
| `get_entry_history` | `entry_id` | Retrieve audit history and snapshots of changes. |
| `get_signatures` | `entry_id` | Retrieve approval and digital signature records. |
| `add_signature` | `entry_id`, `signer_name`, `signer_email`, `provider` | Log a digital approval signature. |
| `run_retention_policy` | `dry_run` | Scan and archive documents exceeding retention. |
| `generate_audit_package`| `include_file_data` | Generate an audit-ready compliance package. |
