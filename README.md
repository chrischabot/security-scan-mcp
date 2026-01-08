# Security Scan MCP Server

An MCP (Model Context Protocol) server that provides **CVE-driven security prompts** for code review.

## What This Does

The core feature: **Security review checklists derived from real CVEs**.

1. **Build phase**: Ingests thousands of CVEs from NVD, then uses Claude to categorize them into generic software types (web-server, database, mobile-app, etc.)
2. **Runtime**: Coding agents query "what security issues should I look for in a web server?" and get actionable prompts based on actual vulnerabilities that have occurred in that type of software

This means security guidance is:
- **Data-driven**: Based on real CVEs, not theoretical vulnerabilities
- **Type-specific**: Different checks for web servers vs databases vs mobile apps
- **Actionable**: Written for code review, not product-specific

## Installation

```bash
npm install
npm run build
```

## Setup

### Build the security prompts database

```bash
# 1. Ingest CVEs from NVD (can use NVD_API_KEY for faster rate)
npm run ingest

# 2. Build security prompts using Claude
ANTHROPIC_API_KEY=your-key npm run build-prompts
```

This analyzes all CVEs and creates a database of security check prompts organized by software type.

## Usage as MCP Server

Add to your Claude Code configuration:

```bash
claude mcp add security-scan -- node /path/to/security-scan-mcp/dist/index.js
```

Or add to `.claude.json`:

```json
{
  "mcpServers": {
    "security-scan": {
      "command": "node",
      "args": ["/path/to/security-scan-mcp/dist/index.js"]
    }
  }
}
```

## MCP Tools

### CVE-Driven Security Prompts

#### `list_software_types`
List all software types that have security prompts available.

Returns types like `web-server`, `database`, `api-server`, `mobile-app`, etc., along with:
- `code_signals`: How to identify this type in code (e.g., "HTTP handling", "SQL queries")
- `prompt_count`: Number of security checks available for this type

#### `get_security_prompts_for_type`
Get all security check prompts for a specific software type.

**Parameters:**
- `type_id` (string, required): e.g., "web-server", "database"
- `severity` (string, optional): Filter by critical/high/medium/low
- `format` (string, optional): "json" or "checklist"

**Returns:** Security checks like:
```json
{
  "title": "Header size validation",
  "check_prompt": "Verify that HTTP header sizes are validated before processing...",
  "severity": "high",
  "based_on_cves": ["CVE-2021-xxxx", "CVE-2022-yyyy"]
}
```

#### `search_security_prompts`
Full-text search across all security prompts.

**Parameters:**
- `query` (string, required): e.g., "SQL injection", "buffer overflow"
- `limit` (number, optional): Maximum results

### Agent Workflow

```
1. Agent starts working on a codebase

2. Agent calls list_software_types
   → Sees types: web-server, database, api-server...
   → Sees code_signals for each type

3. Agent recognizes: "This code has Express routes, HTTP handling"
   → Matches "web-server" type

4. Agent calls get_security_prompts_for_type("web-server")
   → Gets 20+ security checks derived from real CVEs
   → "Verify header sizes are validated..."
   → "Check for request smuggling vulnerabilities..."

5. Agent reviews code against each prompt
```

### CVE/CWE Database Tools

#### `search_cves`
Search the CVE database using full-text search.

#### `get_cwe_info`
Get detailed information about a specific CWE.

#### `get_cves_by_cwe`
Get CVEs related to a specific CWE.

#### `get_top_cwes`
Get the most dangerous CWEs for an application type.

#### `suggest_remediation`
Get language-specific remediation guidance for a vulnerability.

#### `get_database_stats`
Get statistics about the vulnerability database including CVE counts and security prompt counts.

### Pattern Scanning Tools

These tools perform static analysis on source files:

#### `scan_file`
Scan a single source file for security vulnerabilities.

#### `scan_directory`
Scan an entire codebase for vulnerabilities.

## How It Works

### Building Security Prompts

1. **CVE Ingestion**: Fetches CVEs from NVD API
2. **Analysis**: Sends CVEs to Claude in batches
3. **Categorization**: Claude identifies generic software type (web-server, database, etc.)
4. **Prompt Generation**: Claude extracts the vulnerability pattern and creates actionable check prompts
5. **Storage**: Saves to SQLite with full-text search

### Database Schema

```sql
-- Software types (web-server, database, etc.)
software_types (
  type_id TEXT,           -- e.g., "web-server"
  name TEXT,              -- e.g., "Web Servers"
  description TEXT,
  code_signals TEXT       -- JSON: how to identify this type in code
)

-- Security check prompts by type
security_prompts (
  type_id TEXT,           -- References software_types
  title TEXT,             -- e.g., "Header size validation"
  check_prompt TEXT,      -- The actual prompt for code review
  severity TEXT,          -- critical/high/medium/low
  based_on_cves TEXT      -- JSON: CVE IDs this was derived from
)
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Claude API key for building security prompts | For build-prompts |
| `NVD_API_KEY` | API key for NVD CVE access | Optional (rate limited without) |
| `SECURITY_SCAN_DATA_DIR` | Database location | Default: `~/.security-scan-mcp` |

## Development

```bash
npm run build         # Build TypeScript
npm run dev           # Run in development mode
npm run ingest        # Ingest CVEs from NVD
npm run build-prompts # Build security prompts (requires ANTHROPIC_API_KEY)
npm test              # Run tests
```

## License

MIT
