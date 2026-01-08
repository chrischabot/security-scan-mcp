/**
 * SQLite Database Schema for CVE/CWE Storage
 * Uses FTS5 for full-text search on CVE descriptions and security prompts
 */

export const SCHEMA_SQL = `
-- Enable WAL mode for concurrent reads
PRAGMA journal_mode=WAL;
PRAGMA cache_size=-64000;
PRAGMA mmap_size=268435456;

-- CVE Table - stores vulnerability data from NVD
CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    published_date TEXT NOT NULL,
    modified_date TEXT NOT NULL,
    description TEXT NOT NULL,
    cvss_v3_score REAL,
    cvss_v3_severity TEXT CHECK(cvss_v3_severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    cvss_v3_vector TEXT,
    cvss_v2_score REAL,
    cvss_v2_severity TEXT,
    source_identifier TEXT,
    vuln_status TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- CWE Table - Common Weakness Enumeration taxonomy
CREATE TABLE IF NOT EXISTS cwes (
    cwe_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    abstraction TEXT CHECK(abstraction IN ('Pillar','Class','Base','Variant','Compound')),
    parent_cwe_id INTEGER,
    status TEXT,
    likelihood_of_exploit TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- CVE to CWE mapping (many-to-many)
CREATE TABLE IF NOT EXISTS cve_cwe_mappings (
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    cwe_id INTEGER NOT NULL REFERENCES cwes(cwe_id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, cwe_id)
);

-- Affected Products/CPE data
CREATE TABLE IF NOT EXISTS affected_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vendor TEXT,
    product TEXT,
    version_start TEXT,
    version_start_type TEXT,
    version_end TEXT,
    version_end_type TEXT,
    cpe_uri TEXT
);

-- Software types (web-server, database, mobile-app, etc.)
CREATE TABLE IF NOT EXISTS software_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    code_signals TEXT NOT NULL,  -- JSON array: how to identify this type in code
    created_at TEXT DEFAULT (datetime('now'))
);

-- Security check prompts by software type
CREATE TABLE IF NOT EXISTS security_prompts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type_id TEXT NOT NULL REFERENCES software_types(type_id) ON DELETE CASCADE,
    prompt_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    check_prompt TEXT NOT NULL,  -- The actual prompt for the LLM
    why_it_matters TEXT,
    severity TEXT CHECK(severity IN ('critical','high','medium','low')),
    based_on_cves TEXT,  -- JSON array of CVE IDs this was derived from
    created_at TEXT DEFAULT (datetime('now'))
);

-- FTS5 for searching security prompts
CREATE VIRTUAL TABLE IF NOT EXISTS security_prompts_fts USING fts5(
    prompt_id,
    title,
    check_prompt,
    content='security_prompts',
    content_rowid='id',
    tokenize='porter unicode61'
);

-- Triggers for security prompts FTS
CREATE TRIGGER IF NOT EXISTS security_prompts_ai AFTER INSERT ON security_prompts BEGIN
    INSERT INTO security_prompts_fts(rowid, prompt_id, title, check_prompt)
    VALUES (NEW.id, NEW.prompt_id, NEW.title, NEW.check_prompt);
END;

CREATE TRIGGER IF NOT EXISTS security_prompts_ad AFTER DELETE ON security_prompts BEGIN
    INSERT INTO security_prompts_fts(security_prompts_fts, rowid, prompt_id, title, check_prompt)
    VALUES('delete', OLD.id, OLD.prompt_id, OLD.title, OLD.check_prompt);
END;

-- FTS5 full-text search index for CVE descriptions
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
    cve_id,
    description,
    content='cves',
    content_rowid='id',
    tokenize='porter unicode61'
);

-- Triggers to keep FTS index synchronized
CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
    INSERT INTO cve_fts(rowid, cve_id, description) VALUES (NEW.id, NEW.cve_id, NEW.description);
END;

CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, cve_id, description) VALUES('delete', OLD.id, OLD.cve_id, OLD.description);
END;

CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, cve_id, description) VALUES('delete', OLD.id, OLD.cve_id, OLD.description);
    INSERT INTO cve_fts(rowid, cve_id, description) VALUES (NEW.id, NEW.cve_id, NEW.description);
END;

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_v3_severity);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(modified_date DESC);
CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe ON cve_cwe_mappings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_affected_products_cve ON affected_products(cve_id);
CREATE INDEX IF NOT EXISTS idx_affected_products_product ON affected_products(product);
CREATE INDEX IF NOT EXISTS idx_security_prompts_type ON security_prompts(type_id);
CREATE INDEX IF NOT EXISTS idx_security_prompts_severity ON security_prompts(severity);
`;

export const PRAGMA_SETTINGS = `
PRAGMA journal_mode=WAL;
PRAGMA cache_size=-64000;
PRAGMA mmap_size=268435456;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
`;
