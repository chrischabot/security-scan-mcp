# Security Scan MCP Server

An MCP (Model Context Protocol) server that provides security vulnerability analysis for codebases. It combines:

1. **Pattern-based scanning**: AST analysis with Tree-sitter for known vulnerability patterns
2. **CVE-driven security prompts**: LLM-generated security checks derived from real CVEs, organized by software type

## Key Features

### CVE-Driven Security Prompts

The unique feature of this MCP is its ability to provide **security review checklists derived from real CVEs**:

1. **Build phase**: Analyzes thousands of CVEs using Claude to categorize them into generic software types (web-server, database, mobile-app, etc.)
2. **Runtime**: Agents can query "what security issues should I look for in a web server?" and get prompts based on actual vulnerabilities that have occurred

This means security guidance is:
- **Data-driven**: Based on real CVEs, not just theoretical vulnerabilities
- **Type-specific**: Different checks for web servers vs databases vs mobile apps
- **Actionable**: Prompts written for code review, not product-specific

### Pattern Scanning

- **Multi-language**: JavaScript, TypeScript, Python, Go, Rust
- **AST-based**: Uses Tree-sitter for accurate pattern matching
- **Taint analysis**: Tracks untrusted data flow from sources to sinks
- **CVE correlation**: Links findings to real-world vulnerabilities

## Installation

```bash
npm install
npm run build
```

## Setup

### 1. Seed the CWE database

```bash
npm run ingest seed
```

### 2. Build security prompts from CVEs (requires Claude API)

```bash
# First, ingest CVEs from NVD
npm run ingest

# Then, build security prompts using Claude
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

### Security Prompts (CVE-Driven)

#### `list_software_types`
List all software types that have security prompts available.

Returns types like `web-server`, `database`, `api-server`, `mobile-app`, etc., along with:
- `code_signals`: How to identify this type in code (e.g., "HTTP handling", "SQL queries")
- `prompt_count`: Number of security checks available for this type

**Agent workflow:**
1. Call `list_software_types` to see available types and their code signals
2. Match your codebase to the appropriate type(s)
3. Call `get_security_prompts_for_type` for relevant types

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

### Pattern Scanning

#### `scan_file`
Scan a single source file for security vulnerabilities.

**Parameters:**
- `file_path` (string, required): Absolute path to the file
- `severity_threshold` (string, optional): CRITICAL, HIGH, MEDIUM, LOW, INFO
- `include_cve_context` (boolean, optional): Include related CVEs
- `enable_taint_analysis` (boolean, optional): Enable taint tracking

#### `scan_directory`
Scan an entire codebase for vulnerabilities.

**Parameters:**
- `directory_path` (string, required): Path to the directory
- `severity_threshold` (string, optional): Minimum severity level
- `languages` (array, optional): Filter by languages
- `output_format` (string, optional): "json" or "sarif"

### CVE/CWE Lookup

#### `get_cwe_info`
Get detailed information about a specific CWE.

#### `get_cves_by_cwe`
Get CVEs related to a specific CWE.

#### `search_cves`
Search the CVE database using full-text search.

#### `get_top_cwes`
Get the most dangerous CWEs for an application type.

#### `suggest_remediation`
Get language-specific remediation guidance for a vulnerability.

#### `get_database_stats`
Get statistics about the vulnerability database including CVE counts and security prompt counts.

## Architecture

```
src/
├── index.ts                    # MCP server entry point
├── db/
│   ├── schema.ts               # SQLite schema (CVEs, CWEs, security_prompts)
│   └── database.ts             # Database operations
├── llm/
│   └── claude-client.ts        # Claude API client for CVE analysis
├── scripts/
│   ├── ingest-cves.ts          # CVE ingestion from NVD
│   └── build-security-prompts.ts  # Build prompts from CVEs
├── analyzer/
│   ├── code-analyzer.ts        # Pattern-based scanner
│   └── taint-analyzer.ts       # Taint analysis
├── parser/
│   └── tree-sitter-parser.ts   # AST parsing
└── patterns/
    └── pattern-library.ts      # Detection patterns
```

## Database Schema

### Security Prompts Tables

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
# Build
npm run build

# Run in development mode
npm run dev

# Ingest CVEs
npm run ingest

# Build security prompts (requires ANTHROPIC_API_KEY)
npm run build-prompts

# Run tests
npm test
```

## How It Works

### Building Security Prompts

1. **CVE Ingestion**: Fetches CVEs from NVD API
2. **Analysis**: Sends CVEs to Claude in batches
3. **Categorization**: Claude identifies software type (web-server, database, etc.)
4. **Pattern Extraction**: Claude extracts the security issue pattern
5. **Prompt Generation**: Creates actionable check prompts for code review
6. **Storage**: Saves to SQLite with full-text search

### Agent Usage Flow

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

## License

MIT
