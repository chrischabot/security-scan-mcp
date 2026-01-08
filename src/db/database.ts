/**
 * SQLite Database Manager
 * Provides connection management and query execution
 */

import Database from 'better-sqlite3';
import { SCHEMA_SQL, PRAGMA_SETTINGS } from './schema.js';
import path from 'path';
import fs from 'fs';

export interface CVERecord {
    cve_id: string;
    published_date: string;
    modified_date: string;
    description: string;
    cvss_v3_score: number | null;
    cvss_v3_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null;
    cvss_v3_vector: string | null;
    cvss_v2_score: number | null;
    cvss_v2_severity: string | null;
    source_identifier: string | null;
    vuln_status: string | null;
}

export interface CWERecord {
    cwe_id: number;
    name: string;
    description: string | null;
    abstraction: 'Pillar' | 'Class' | 'Base' | 'Variant' | 'Compound' | null;
    parent_cwe_id: number | null;
    status: string | null;
    likelihood_of_exploit: string | null;
}

export interface DetectionPattern {
    pattern_id: string;
    cwe_id: number | null;
    name: string;
    description: string | null;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    languages: string[];
    pattern_type: 'ast' | 'taint' | 'regex';
    pattern_config: PatternConfig;
    remediation: string | null;
    references: string[];
    enabled: boolean;
}

export interface PatternConfig {
    query?: string;  // Tree-sitter query
    sources?: string[];
    sinks?: string[];
    sanitizers?: string[];
    regex?: string;
    message?: string;
}

export interface ScanFinding {
    scan_id: string;
    file_path: string;
    pattern_id: string;
    cwe_id: number | null;
    severity: string;
    line_start: number;
    line_end: number;
    column_start: number;
    column_end: number;
    matched_code: string;
    message: string;
    remediation: string | null;
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface SoftwareType {
    type_id: string;
    name: string;
    description: string | null;
    code_signals: string[];  // How to identify this type in code
}

export interface SecurityPrompt {
    prompt_id: string;
    type_id: string;
    title: string;
    check_prompt: string;
    why_it_matters: string | null;
    severity: 'critical' | 'high' | 'medium' | 'low';
    based_on_cves: string[];
}

export class SecurityDatabase {
    private db: Database.Database;
    private dbPath: string;

    constructor(dbPath?: string) {
        this.dbPath = dbPath || this.getDefaultDbPath();
        this.ensureDirectory();
        this.db = new Database(this.dbPath);
        this.initialize();
    }

    private getDefaultDbPath(): string {
        const dataDir = process.env.SECURITY_SCAN_DATA_DIR ||
            path.join(process.env.HOME || '/tmp', '.security-scan-mcp');
        return path.join(dataDir, 'vulnerabilities.db');
    }

    private ensureDirectory(): void {
        const dir = path.dirname(this.dbPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }

    private initialize(): void {
        // Apply pragma settings
        this.db.exec(PRAGMA_SETTINGS);
        // Create schema
        this.db.exec(SCHEMA_SQL);
    }

    // CVE Operations
    insertCVE(cve: CVERecord): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO cves (
                cve_id, published_date, modified_date, description,
                cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
                cvss_v2_score, cvss_v2_severity, source_identifier, vuln_status,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `);
        stmt.run(
            cve.cve_id, cve.published_date, cve.modified_date, cve.description,
            cve.cvss_v3_score, cve.cvss_v3_severity, cve.cvss_v3_vector,
            cve.cvss_v2_score, cve.cvss_v2_severity, cve.source_identifier, cve.vuln_status
        );
    }

    insertCVEBatch(cves: CVERecord[]): void {
        const insert = this.db.prepare(`
            INSERT OR REPLACE INTO cves (
                cve_id, published_date, modified_date, description,
                cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
                cvss_v2_score, cvss_v2_severity, source_identifier, vuln_status,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `);

        const insertMany = this.db.transaction((cves: CVERecord[]) => {
            for (const cve of cves) {
                insert.run(
                    cve.cve_id, cve.published_date, cve.modified_date, cve.description,
                    cve.cvss_v3_score, cve.cvss_v3_severity, cve.cvss_v3_vector,
                    cve.cvss_v2_score, cve.cvss_v2_severity, cve.source_identifier, cve.vuln_status
                );
            }
        });

        insertMany(cves);
    }

    getCVE(cveId: string): CVERecord | undefined {
        const stmt = this.db.prepare('SELECT * FROM cves WHERE cve_id = ?');
        return stmt.get(cveId) as CVERecord | undefined;
    }

    getCVEsByCWE(cweId: number, limit = 50): CVERecord[] {
        const stmt = this.db.prepare(`
            SELECT c.* FROM cves c
            JOIN cve_cwe_mappings m ON c.cve_id = m.cve_id
            WHERE m.cwe_id = ?
            ORDER BY c.cvss_v3_score DESC, c.published_date DESC
            LIMIT ?
        `);
        return stmt.all(cweId, limit) as CVERecord[];
    }

    getCVEsBySeverity(severity: string, limit = 100): CVERecord[] {
        const stmt = this.db.prepare(`
            SELECT * FROM cves
            WHERE cvss_v3_severity = ?
            ORDER BY published_date DESC
            LIMIT ?
        `);
        return stmt.all(severity, limit) as CVERecord[];
    }

    searchCVEs(query: string, limit = 50): CVERecord[] {
        const stmt = this.db.prepare(`
            SELECT c.*, bm25(cve_fts) as rank
            FROM cve_fts f
            JOIN cves c ON f.cve_id = c.cve_id
            WHERE cve_fts MATCH ?
            ORDER BY rank
            LIMIT ?
        `);
        return stmt.all(query, limit) as CVERecord[];
    }

    // CWE Operations
    insertCWE(cwe: CWERecord): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO cwes (
                cwe_id, name, description, abstraction,
                parent_cwe_id, status, likelihood_of_exploit
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
            cwe.cwe_id, cwe.name, cwe.description, cwe.abstraction,
            cwe.parent_cwe_id, cwe.status, cwe.likelihood_of_exploit
        );
    }

    getCWE(cweId: number): CWERecord | undefined {
        const stmt = this.db.prepare('SELECT * FROM cwes WHERE cwe_id = ?');
        return stmt.get(cweId) as CWERecord | undefined;
    }

    getCWEChildren(parentCweId: number): CWERecord[] {
        const stmt = this.db.prepare('SELECT * FROM cwes WHERE parent_cwe_id = ?');
        return stmt.all(parentCweId) as CWERecord[];
    }

    // CVE-CWE Mapping
    linkCVEToCWE(cveId: string, cweId: number): void {
        const stmt = this.db.prepare(`
            INSERT OR IGNORE INTO cve_cwe_mappings (cve_id, cwe_id) VALUES (?, ?)
        `);
        stmt.run(cveId, cweId);
    }

    getCWEsForCVE(cveId: string): CWERecord[] {
        const stmt = this.db.prepare(`
            SELECT cw.* FROM cwes cw
            JOIN cve_cwe_mappings m ON cw.cwe_id = m.cwe_id
            WHERE m.cve_id = ?
        `);
        return stmt.all(cveId) as CWERecord[];
    }

    // Detection Pattern Operations
    insertPattern(pattern: DetectionPattern): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO detection_patterns (
                pattern_id, cwe_id, name, description, severity,
                languages, pattern_type, pattern_config,
                remediation, reference_urls, enabled, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `);
        stmt.run(
            pattern.pattern_id, pattern.cwe_id, pattern.name, pattern.description,
            pattern.severity, JSON.stringify(pattern.languages), pattern.pattern_type,
            JSON.stringify(pattern.pattern_config), pattern.remediation,
            JSON.stringify(pattern.references), pattern.enabled ? 1 : 0
        );
    }

    getPattern(patternId: string): DetectionPattern | undefined {
        const stmt = this.db.prepare('SELECT * FROM detection_patterns WHERE pattern_id = ?');
        const row = stmt.get(patternId) as Record<string, unknown> | undefined;
        return row ? this.parsePatternRow(row) : undefined;
    }

    getPatternsByCWE(cweId: number): DetectionPattern[] {
        const stmt = this.db.prepare(`
            SELECT * FROM detection_patterns
            WHERE cwe_id = ? AND enabled = 1
        `);
        return (stmt.all(cweId) as Record<string, unknown>[]).map(row => this.parsePatternRow(row));
    }

    getPatternsByLanguage(language: string): DetectionPattern[] {
        const stmt = this.db.prepare(`
            SELECT * FROM detection_patterns
            WHERE enabled = 1 AND languages LIKE ?
        `);
        return (stmt.all(`%"${language}"%`) as Record<string, unknown>[]).map(row => this.parsePatternRow(row));
    }

    getAllPatterns(): DetectionPattern[] {
        const stmt = this.db.prepare('SELECT * FROM detection_patterns WHERE enabled = 1');
        return (stmt.all() as Record<string, unknown>[]).map(row => this.parsePatternRow(row));
    }

    private parsePatternRow(row: Record<string, unknown>): DetectionPattern {
        return {
            pattern_id: row.pattern_id as string,
            cwe_id: row.cwe_id as number | null,
            name: row.name as string,
            description: row.description as string | null,
            severity: row.severity as DetectionPattern['severity'],
            languages: JSON.parse(row.languages as string),
            pattern_type: row.pattern_type as DetectionPattern['pattern_type'],
            pattern_config: JSON.parse(row.pattern_config as string),
            remediation: row.remediation as string | null,
            references: JSON.parse(row.reference_urls as string || '[]'),
            enabled: row.enabled === 1
        };
    }

    // Scan Finding Operations
    insertFinding(finding: ScanFinding): void {
        const stmt = this.db.prepare(`
            INSERT INTO scan_findings (
                scan_id, file_path, pattern_id, cwe_id, severity,
                line_start, line_end, column_start, column_end,
                matched_code, message, remediation, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
            finding.scan_id, finding.file_path, finding.pattern_id, finding.cwe_id,
            finding.severity, finding.line_start, finding.line_end,
            finding.column_start, finding.column_end, finding.matched_code,
            finding.message, finding.remediation, finding.confidence
        );
    }

    insertFindingsBatch(findings: ScanFinding[]): void {
        const insert = this.db.prepare(`
            INSERT INTO scan_findings (
                scan_id, file_path, pattern_id, cwe_id, severity,
                line_start, line_end, column_start, column_end,
                matched_code, message, remediation, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        const insertMany = this.db.transaction((findings: ScanFinding[]) => {
            for (const f of findings) {
                insert.run(
                    f.scan_id, f.file_path, f.pattern_id, f.cwe_id,
                    f.severity, f.line_start, f.line_end,
                    f.column_start, f.column_end, f.matched_code,
                    f.message, f.remediation, f.confidence
                );
            }
        });

        insertMany(findings);
    }

    getFindingsByScan(scanId: string): ScanFinding[] {
        const stmt = this.db.prepare(`
            SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY severity, file_path, line_start
        `);
        return stmt.all(scanId) as ScanFinding[];
    }

    getFindingsByFile(filePath: string): ScanFinding[] {
        const stmt = this.db.prepare(`
            SELECT * FROM scan_findings WHERE file_path = ? ORDER BY line_start
        `);
        return stmt.all(filePath) as ScanFinding[];
    }

    // Statistics
    getStats(): {
        totalCVEs: number;
        totalCWEs: number;
        totalPatterns: number;
        cvesBySeverity: Record<string, number>;
    } {
        const cveCount = (this.db.prepare('SELECT COUNT(*) as count FROM cves').get() as { count: number }).count;
        const cweCount = (this.db.prepare('SELECT COUNT(*) as count FROM cwes').get() as { count: number }).count;
        const patternCount = (this.db.prepare('SELECT COUNT(*) as count FROM detection_patterns WHERE enabled = 1').get() as { count: number }).count;

        const severities = this.db.prepare(`
            SELECT cvss_v3_severity, COUNT(*) as count
            FROM cves
            WHERE cvss_v3_severity IS NOT NULL
            GROUP BY cvss_v3_severity
        `).all() as { cvss_v3_severity: string; count: number }[];

        const cvesBySeverity: Record<string, number> = {};
        for (const s of severities) {
            cvesBySeverity[s.cvss_v3_severity] = s.count;
        }

        return {
            totalCVEs: cveCount,
            totalCWEs: cweCount,
            totalPatterns: patternCount,
            cvesBySeverity
        };
    }

    // Software Type Operations
    insertSoftwareType(type: SoftwareType): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO software_types (type_id, name, description, code_signals)
            VALUES (?, ?, ?, ?)
        `);
        stmt.run(type.type_id, type.name, type.description, JSON.stringify(type.code_signals));
    }

    getSoftwareType(typeId: string): SoftwareType | undefined {
        const stmt = this.db.prepare('SELECT * FROM software_types WHERE type_id = ?');
        const row = stmt.get(typeId) as Record<string, unknown> | undefined;
        if (!row) return undefined;
        return {
            type_id: row.type_id as string,
            name: row.name as string,
            description: row.description as string | null,
            code_signals: JSON.parse(row.code_signals as string)
        };
    }

    getAllSoftwareTypes(): SoftwareType[] {
        const stmt = this.db.prepare('SELECT * FROM software_types ORDER BY name');
        return (stmt.all() as Record<string, unknown>[]).map(row => ({
            type_id: row.type_id as string,
            name: row.name as string,
            description: row.description as string | null,
            code_signals: JSON.parse(row.code_signals as string)
        }));
    }

    // Security Prompt Operations
    insertSecurityPrompt(prompt: SecurityPrompt): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO security_prompts
            (prompt_id, type_id, title, check_prompt, why_it_matters, severity, based_on_cves)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
            prompt.prompt_id, prompt.type_id, prompt.title, prompt.check_prompt,
            prompt.why_it_matters, prompt.severity, JSON.stringify(prompt.based_on_cves)
        );
    }

    insertSecurityPromptsBatch(prompts: SecurityPrompt[]): void {
        const insert = this.db.prepare(`
            INSERT OR REPLACE INTO security_prompts
            (prompt_id, type_id, title, check_prompt, why_it_matters, severity, based_on_cves)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        const insertMany = this.db.transaction((prompts: SecurityPrompt[]) => {
            for (const p of prompts) {
                insert.run(
                    p.prompt_id, p.type_id, p.title, p.check_prompt,
                    p.why_it_matters, p.severity, JSON.stringify(p.based_on_cves)
                );
            }
        });

        insertMany(prompts);
    }

    getSecurityPromptsByType(typeId: string): SecurityPrompt[] {
        const stmt = this.db.prepare(`
            SELECT * FROM security_prompts WHERE type_id = ? ORDER BY severity, title
        `);
        return (stmt.all(typeId) as Record<string, unknown>[]).map(row => ({
            prompt_id: row.prompt_id as string,
            type_id: row.type_id as string,
            title: row.title as string,
            check_prompt: row.check_prompt as string,
            why_it_matters: row.why_it_matters as string | null,
            severity: row.severity as SecurityPrompt['severity'],
            based_on_cves: JSON.parse(row.based_on_cves as string || '[]')
        }));
    }

    searchSecurityPrompts(query: string, limit = 50): SecurityPrompt[] {
        const stmt = this.db.prepare(`
            SELECT sp.* FROM security_prompts_fts f
            JOIN security_prompts sp ON f.prompt_id = sp.prompt_id
            WHERE security_prompts_fts MATCH ?
            LIMIT ?
        `);
        return (stmt.all(query, limit) as Record<string, unknown>[]).map(row => ({
            prompt_id: row.prompt_id as string,
            type_id: row.type_id as string,
            title: row.title as string,
            check_prompt: row.check_prompt as string,
            why_it_matters: row.why_it_matters as string | null,
            severity: row.severity as SecurityPrompt['severity'],
            based_on_cves: JSON.parse(row.based_on_cves as string || '[]')
        }));
    }

    getSecurityPromptsStats(): { totalTypes: number; totalPrompts: number; promptsByType: Record<string, number> } {
        const typeCount = (this.db.prepare('SELECT COUNT(*) as count FROM software_types').get() as { count: number }).count;
        const promptCount = (this.db.prepare('SELECT COUNT(*) as count FROM security_prompts').get() as { count: number }).count;

        const byType = this.db.prepare(`
            SELECT type_id, COUNT(*) as count FROM security_prompts GROUP BY type_id
        `).all() as { type_id: string; count: number }[];

        const promptsByType: Record<string, number> = {};
        for (const t of byType) {
            promptsByType[t.type_id] = t.count;
        }

        return { totalTypes: typeCount, totalPrompts: promptCount, promptsByType };
    }

    clearSecurityPrompts(): void {
        this.db.exec('DELETE FROM security_prompts');
        this.db.exec('DELETE FROM software_types');
    }

    // Maintenance
    optimize(): void {
        this.db.exec('PRAGMA optimize');
        this.db.exec('ANALYZE');
    }

    vacuum(): void {
        this.db.exec('VACUUM');
    }

    close(): void {
        this.db.close();
    }

    getDbPath(): string {
        return this.dbPath;
    }
}

// Singleton instance for the application
let dbInstance: SecurityDatabase | null = null;

export function getDatabase(dbPath?: string): SecurityDatabase {
    if (!dbInstance) {
        dbInstance = new SecurityDatabase(dbPath);
    }
    return dbInstance;
}

export function closeDatabase(): void {
    if (dbInstance) {
        dbInstance.close();
        dbInstance = null;
    }
}
