# Security Scan MCP Server

An MCP (Model Context Protocol) server that provides security vulnerability analysis capabilities for codebases. It integrates NVD CVE data, CWE taxonomy, and AST-based pattern matching to identify security weaknesses and provide actionable remediation guidance.

## Features

- **Multi-language support**: JavaScript, TypeScript, Python, Go, and Rust
- **AST-based analysis**: Uses Tree-sitter for accurate pattern matching
- **Taint analysis**: Tracks untrusted data flow from sources to sinks
- **CVE integration**: Correlates findings with real-world vulnerabilities from NVD
- **CWE taxonomy**: Organizes vulnerabilities using the CWE Top 25
- **Remediation guidance**: Provides language-specific fix suggestions

## Installation

```bash
npm install
npm run build
```

## Database Setup

Before first use, populate the CVE database:

```bash
# Seed CWE data only (fast)
npm run ingest seed

# Full ingestion (fetches CVEs from NVD - takes time)
npm run ingest
```

## Usage

### As an MCP Server

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

### Available Tools

#### `scan_file`
Scan a single source file for security vulnerabilities.

**Parameters:**
- `file_path` (string, required): Absolute path to the file
- `severity_threshold` (string, optional): Minimum severity - CRITICAL, HIGH, MEDIUM, LOW, INFO
- `include_cve_context` (boolean, optional): Include related CVEs
- `enable_taint_analysis` (boolean, optional): Enable taint tracking

#### `scan_directory`
Scan an entire codebase for vulnerabilities.

**Parameters:**
- `directory_path` (string, required): Path to the directory
- `severity_threshold` (string, optional): Minimum severity level
- `languages` (array, optional): Filter by languages
- `cwe_ids` (array, optional): Filter by specific CWE IDs
- `exclude_patterns` (array, optional): Glob patterns to exclude

#### `get_cwe_info`
Get detailed information about a specific CWE.

**Parameters:**
- `cwe_id` (number, required): The CWE ID (e.g., 79 for XSS)

#### `get_cves_by_cwe`
Get CVEs related to a specific CWE.

**Parameters:**
- `cwe_id` (number, required): The CWE ID
- `limit` (number, optional): Maximum results
- `severity` (string, optional): Filter by severity

#### `search_cves`
Search the CVE database using full-text search.

**Parameters:**
- `query` (string, required): Search keywords
- `limit` (number, optional): Maximum results

#### `get_top_cwes`
Get the most dangerous CWEs for an application type.

**Parameters:**
- `app_type` (string, optional): web, api, cli, desktop, mobile, library
- `limit` (number, optional): Number of results

#### `suggest_remediation`
Get remediation guidance for a vulnerability.

**Parameters:**
- `cwe_id` (number, required): The CWE ID
- `language` (string, required): Programming language

## Detected Vulnerability Types

The scanner detects the following vulnerability categories:

| CWE | Name | Severity |
|-----|------|----------|
| CWE-79 | Cross-Site Scripting (XSS) | HIGH |
| CWE-89 | SQL Injection | CRITICAL |
| CWE-78 | OS Command Injection | CRITICAL |
| CWE-22 | Path Traversal | HIGH |
| CWE-502 | Deserialization of Untrusted Data | CRITICAL |
| CWE-798 | Hardcoded Credentials | HIGH |
| CWE-94 | Code Injection | CRITICAL |
| CWE-918 | Server-Side Request Forgery (SSRF) | HIGH |
| CWE-434 | Unrestricted File Upload | HIGH |
| CWE-287 | Improper Authentication | HIGH |

## Architecture

```
src/
├── index.ts              # MCP server entry point
├── db/
│   ├── schema.ts         # SQLite schema with FTS5
│   └── database.ts       # Database operations
├── nvd/
│   └── client.ts         # NVD API 2.0 client
├── cwe/
│   └── taxonomy.ts       # CWE Top 25 taxonomy
├── parser/
│   └── tree-sitter-parser.ts  # AST parsing
├── patterns/
│   └── pattern-library.ts     # Detection patterns
├── analyzer/
│   ├── code-analyzer.ts       # Main analyzer
│   └── taint-analyzer.ts      # Taint analysis
└── scripts/
    └── ingest-cves.ts         # CVE ingestion script
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NVD_API_KEY` | API key for NVD access | None |
| `SECURITY_SCAN_DATA_DIR` | Database location | `~/.security-scan-mcp` |

## Development

```bash
# Run in development mode
npm run dev

# Run tests
npm test

# Lint
npm run lint
```

## License

MIT
