/**
 * SQLite Database Schema for CVE/CWE Storage
 * Uses FTS5 for full-text search on CVE descriptions
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
    parent_cwe_id INTEGER,  -- Self-reference without FK constraint for flexible insertion
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

-- Detection patterns organized by CWE
CREATE TABLE IF NOT EXISTS detection_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT UNIQUE NOT NULL,
    cwe_id INTEGER REFERENCES cwes(cwe_id),
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    languages TEXT NOT NULL,  -- JSON array of languages
    pattern_type TEXT CHECK(pattern_type IN ('ast','taint','regex')),
    pattern_config TEXT NOT NULL,  -- JSON configuration
    remediation TEXT,
    reference_urls TEXT,  -- JSON array of URLs
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Scan results storage
CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    pattern_id TEXT REFERENCES detection_patterns(pattern_id),
    cwe_id INTEGER,
    severity TEXT,
    line_start INTEGER,
    line_end INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    matched_code TEXT,
    message TEXT,
    remediation TEXT,
    confidence TEXT CHECK(confidence IN ('HIGH','MEDIUM','LOW')),
    created_at TEXT DEFAULT (datetime('now'))
);

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
CREATE INDEX IF NOT EXISTS idx_patterns_cwe ON detection_patterns(cwe_id);
CREATE INDEX IF NOT EXISTS idx_patterns_severity ON detection_patterns(severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_file ON scan_findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON scan_findings(severity);
`;

export const PRAGMA_SETTINGS = `
PRAGMA journal_mode=WAL;
PRAGMA cache_size=-64000;
PRAGMA mmap_size=268435456;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
`;
