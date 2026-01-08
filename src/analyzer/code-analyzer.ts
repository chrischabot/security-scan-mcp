/**
 * Security Code Analyzer
 * Coordinates AST parsing, pattern matching, and taint analysis
 */

import fs from 'fs';
import path from 'path';
import { glob } from 'glob';
import {
    SupportedLanguage,
    parseFile,
    executeQuery,
    detectLanguage,
    hasSyntaxErrors,
    getSyntaxErrors,
    getNodeLocation,
    NodeLocation
} from '../parser/tree-sitter-parser.js';
import {
    SecurityPattern,
    getPatternsByLanguage,
    Severity,
    Confidence
} from '../patterns/pattern-library.js';
import { TaintAnalyzer, TaintFinding, createTaintAnalyzer } from './taint-analyzer.js';
import { getDatabase, SecurityDatabase, CVERecord } from '../db/database.js';
import { getCWE, CWEEntry } from '../cwe/taxonomy.js';

export interface ScanOptions {
    /** Minimum severity to report */
    severityThreshold?: Severity;
    /** Only scan specific languages */
    languages?: SupportedLanguage[];
    /** Only scan specific CWEs */
    cweIds?: number[];
    /** Include CVE context for findings */
    includeCVEContext?: boolean;
    /** Maximum CVEs per finding */
    maxCVEsPerFinding?: number;
    /** Glob patterns to exclude */
    excludePatterns?: string[];
    /** Enable taint analysis (slower but more accurate) */
    enableTaintAnalysis?: boolean;
}

export interface Finding {
    id: string;
    patternId: string;
    patternName: string;
    description: string;
    filePath: string;
    location: NodeLocation;
    severity: Severity;
    confidence: Confidence;
    cweId: number;
    cweName?: string;
    matchedCode: string;
    message: string;
    remediation: string;
    references: string[];
    relatedCVEs?: CVERecord[];
    taintInfo?: {
        source: string;
        sourceLocation: NodeLocation;
        propagationSteps: number;
    };
}

export interface ScanResult {
    scanId: string;
    startTime: Date;
    endTime: Date;
    durationMs: number;
    filesScanned: number;
    totalFindings: number;
    findingsBySeverity: Record<Severity, number>;
    findingsByCWE: Record<number, number>;
    findings: Finding[];
    errors: ScanError[];
}

export interface ScanError {
    filePath: string;
    error: string;
    type: 'parse' | 'analysis' | 'io';
}

const SEVERITY_ORDER: Record<Severity, number> = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0
};

export class CodeAnalyzer {
    private db: SecurityDatabase;
    private taintAnalyzers: Map<SupportedLanguage, TaintAnalyzer>;

    constructor(db?: SecurityDatabase) {
        this.db = db || getDatabase();
        this.taintAnalyzers = new Map();
    }

    /**
     * Scan a single file for vulnerabilities
     */
    async scanFile(
        filePath: string,
        options: ScanOptions = {}
    ): Promise<Finding[]> {
        const findings: Finding[] = [];

        // Detect language
        const language = detectLanguage(filePath);
        if (!language) {
            return findings;
        }

        // Check language filter
        if (options.languages && !options.languages.includes(language)) {
            return findings;
        }

        // Read file content
        let content: string;
        try {
            content = fs.readFileSync(filePath, 'utf-8');
        } catch (error) {
            throw new Error(`Failed to read file: ${filePath}`);
        }

        // Parse the file
        const parseResult = await parseFile(filePath, content, language);

        // Check for syntax errors
        if (hasSyntaxErrors(parseResult.tree)) {
            const errors = getSyntaxErrors(parseResult.tree);
            console.warn(`Syntax errors in ${filePath}: ${errors.length} errors`);
        }

        // Get applicable patterns
        let patterns = getPatternsByLanguage(language);

        // Filter by severity threshold
        if (options.severityThreshold) {
            const threshold = SEVERITY_ORDER[options.severityThreshold];
            patterns = patterns.filter(p => SEVERITY_ORDER[p.severity] >= threshold);
        }

        // Filter by CWE IDs
        if (options.cweIds && options.cweIds.length > 0) {
            patterns = patterns.filter(p => options.cweIds!.includes(p.cweId));
        }

        // Run AST pattern matching
        for (const pattern of patterns) {
            if (pattern.patternType === 'ast' && pattern.astQuery) {
                try {
                    const matches = await executeQuery(
                        parseResult.tree,
                        language,
                        pattern.astQuery
                    );

                    for (const match of matches) {
                        const finding = this.createFinding(
                            pattern,
                            filePath,
                            match.location,
                            match.text,
                            options
                        );
                        findings.push(finding);
                    }
                } catch (error) {
                    console.warn(`Query error for pattern ${pattern.id}: ${error}`);
                }
            }

            // Run regex pattern matching
            if (pattern.patternType === 'regex' && pattern.regexPattern) {
                const regex = new RegExp(pattern.regexPattern, 'gmi');
                let match;
                const lines = content.split('\n');

                while ((match = regex.exec(content)) !== null) {
                    const lineNumber = content.substring(0, match.index).split('\n').length;
                    const line = lines[lineNumber - 1] || '';
                    const column = match.index - content.lastIndexOf('\n', match.index - 1);

                    const location: NodeLocation = {
                        startLine: lineNumber,
                        startColumn: column,
                        endLine: lineNumber,
                        endColumn: column + match[0].length,
                        startIndex: match.index,
                        endIndex: match.index + match[0].length
                    };

                    const finding = this.createFinding(
                        pattern,
                        filePath,
                        location,
                        match[0],
                        options
                    );
                    findings.push(finding);
                }
            }

            // Run taint analysis
            if (pattern.patternType === 'taint' && pattern.taintConfig && options.enableTaintAnalysis !== false) {
                let analyzer = this.taintAnalyzers.get(language);
                if (!analyzer) {
                    analyzer = createTaintAnalyzer(language);
                    this.taintAnalyzers.set(language, analyzer);
                }

                const taintResult = analyzer.analyze(parseResult.tree, pattern.taintConfig);

                for (const taintFinding of taintResult.findings) {
                    if (!taintFinding.sanitized) {
                        const finding = this.createTaintFinding(
                            pattern,
                            filePath,
                            taintFinding,
                            options
                        );
                        findings.push(finding);
                    }
                }
            }
        }

        return findings;
    }

    /**
     * Scan a directory or codebase
     */
    async scanDirectory(
        dirPath: string,
        options: ScanOptions = {}
    ): Promise<ScanResult> {
        const startTime = new Date();
        const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const findings: Finding[] = [];
        const errors: ScanError[] = [];

        // Build glob patterns based on supported languages
        const extensions = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx', '.py', '.go', '.rs'];
        const pattern = `**/*{${extensions.join(',')}}`;

        // Get exclude patterns
        const defaultExcludes = [
            '**/node_modules/**',
            '**/vendor/**',
            '**/dist/**',
            '**/build/**',
            '**/.git/**',
            '**/coverage/**',
            '**/__pycache__/**',
            '**/target/**'  // Rust
        ];
        const excludePatterns = [...defaultExcludes, ...(options.excludePatterns || [])];

        // Find all files
        const files = await glob(pattern, {
            cwd: dirPath,
            absolute: true,
            ignore: excludePatterns
        });

        console.log(`Scanning ${files.length} files...`);

        // Scan each file
        for (const file of files) {
            try {
                const fileFindings = await this.scanFile(file, options);
                findings.push(...fileFindings);
            } catch (error) {
                errors.push({
                    filePath: file,
                    error: error instanceof Error ? error.message : String(error),
                    type: 'analysis'
                });
            }
        }

        const endTime = new Date();

        // Calculate statistics
        const findingsBySeverity: Record<Severity, number> = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            INFO: 0
        };

        const findingsByCWE: Record<number, number> = {};

        for (const finding of findings) {
            findingsBySeverity[finding.severity]++;
            findingsByCWE[finding.cweId] = (findingsByCWE[finding.cweId] || 0) + 1;
        }

        // Sort findings by severity
        findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

        return {
            scanId,
            startTime,
            endTime,
            durationMs: endTime.getTime() - startTime.getTime(),
            filesScanned: files.length,
            totalFindings: findings.length,
            findingsBySeverity,
            findingsByCWE,
            findings,
            errors
        };
    }

    /**
     * Create a finding from a pattern match
     */
    private createFinding(
        pattern: SecurityPattern,
        filePath: string,
        location: NodeLocation,
        matchedCode: string,
        options: ScanOptions
    ): Finding {
        const cwe = getCWE(pattern.cweId);
        const finding: Finding = {
            id: `${pattern.id}_${location.startLine}_${location.startColumn}`,
            patternId: pattern.id,
            patternName: pattern.name,
            description: pattern.description,
            filePath: path.relative(process.cwd(), filePath),
            location,
            severity: pattern.severity,
            confidence: pattern.confidence,
            cweId: pattern.cweId,
            cweName: cwe?.name,
            matchedCode: this.truncateCode(matchedCode, 200),
            message: pattern.message,
            remediation: pattern.remediation,
            references: pattern.references
        };

        // Add CVE context if requested
        if (options.includeCVEContext) {
            const maxCVEs = options.maxCVEsPerFinding || 5;
            finding.relatedCVEs = this.db.getCVEsByCWE(pattern.cweId, maxCVEs);
        }

        return finding;
    }

    /**
     * Create a finding from taint analysis
     */
    private createTaintFinding(
        pattern: SecurityPattern,
        filePath: string,
        taintFinding: TaintFinding,
        options: ScanOptions
    ): Finding {
        const cwe = getCWE(pattern.cweId);
        const finding: Finding = {
            id: `${pattern.id}_taint_${taintFinding.sinkLocation.startLine}`,
            patternId: pattern.id,
            patternName: pattern.name,
            description: pattern.description,
            filePath: path.relative(process.cwd(), filePath),
            location: taintFinding.sinkLocation,
            severity: pattern.severity,
            confidence: taintFinding.confidence,
            cweId: pattern.cweId,
            cweName: cwe?.name,
            matchedCode: this.truncateCode(taintFinding.sinkNode.text, 200),
            message: `${pattern.message}. Tainted data from ${taintFinding.taintedVar.taintSource} flows to ${taintFinding.sinkDescription}`,
            remediation: pattern.remediation,
            references: pattern.references,
            taintInfo: {
                source: taintFinding.taintedVar.taintSource,
                sourceLocation: taintFinding.taintedVar.sourceLocation,
                propagationSteps: taintFinding.taintedVar.propagationPath.length
            }
        };

        // Add CVE context if requested
        if (options.includeCVEContext) {
            const maxCVEs = options.maxCVEsPerFinding || 5;
            finding.relatedCVEs = this.db.getCVEsByCWE(pattern.cweId, maxCVEs);
        }

        return finding;
    }

    /**
     * Truncate code for display
     */
    private truncateCode(code: string, maxLength: number): string {
        if (code.length <= maxLength) return code;
        return code.substring(0, maxLength - 3) + '...';
    }

    /**
     * Get CVE context for a finding
     */
    getCVEContext(cweId: number, limit = 10): CVERecord[] {
        return this.db.getCVEsByCWE(cweId, limit);
    }

    /**
     * Search CVEs by keyword
     */
    searchCVEs(query: string, limit = 20): CVERecord[] {
        return this.db.searchCVEs(query, limit);
    }

    /**
     * Get CWE information
     */
    getCWEInfo(cweId: number): CWEEntry | undefined {
        return getCWE(cweId);
    }

    /**
     * Get database statistics
     */
    getStats(): {
        totalCVEs: number;
        totalCWEs: number;
        totalPatterns: number;
        cvesBySeverity: Record<string, number>;
    } {
        return this.db.getStats();
    }
}

/**
 * Format a finding for display
 */
export function formatFinding(finding: Finding): string {
    const lines = [
        `[${finding.severity}] ${finding.patternName}`,
        `  File: ${finding.filePath}:${finding.location.startLine}:${finding.location.startColumn}`,
        `  CWE: CWE-${finding.cweId} (${finding.cweName || 'Unknown'})`,
        `  Message: ${finding.message}`,
        `  Code: ${finding.matchedCode}`,
        `  Remediation: ${finding.remediation}`
    ];

    if (finding.taintInfo) {
        lines.push(`  Taint Source: ${finding.taintInfo.source} at line ${finding.taintInfo.sourceLocation.startLine}`);
    }

    if (finding.relatedCVEs && finding.relatedCVEs.length > 0) {
        lines.push(`  Related CVEs: ${finding.relatedCVEs.map(c => c.cve_id).join(', ')}`);
    }

    return lines.join('\n');
}

/**
 * Format scan results as a report
 */
export function formatScanReport(result: ScanResult): string {
    const lines = [
        '═══════════════════════════════════════════════════════',
        '          SECURITY SCAN REPORT',
        '═══════════════════════════════════════════════════════',
        `Scan ID: ${result.scanId}`,
        `Duration: ${result.durationMs}ms`,
        `Files Scanned: ${result.filesScanned}`,
        `Total Findings: ${result.totalFindings}`,
        '',
        'Findings by Severity:',
        `  CRITICAL: ${result.findingsBySeverity.CRITICAL}`,
        `  HIGH: ${result.findingsBySeverity.HIGH}`,
        `  MEDIUM: ${result.findingsBySeverity.MEDIUM}`,
        `  LOW: ${result.findingsBySeverity.LOW}`,
        `  INFO: ${result.findingsBySeverity.INFO}`,
        ''
    ];

    if (Object.keys(result.findingsByCWE).length > 0) {
        lines.push('Findings by CWE:');
        for (const [cweId, count] of Object.entries(result.findingsByCWE)) {
            const cwe = getCWE(parseInt(cweId));
            lines.push(`  CWE-${cweId}: ${count} (${cwe?.name || 'Unknown'})`);
        }
        lines.push('');
    }

    lines.push('═══════════════════════════════════════════════════════');
    lines.push('                    FINDINGS');
    lines.push('═══════════════════════════════════════════════════════');

    for (const finding of result.findings) {
        lines.push('');
        lines.push(formatFinding(finding));
    }

    if (result.errors.length > 0) {
        lines.push('');
        lines.push('═══════════════════════════════════════════════════════');
        lines.push('                    ERRORS');
        lines.push('═══════════════════════════════════════════════════════');

        for (const error of result.errors) {
            lines.push(`  ${error.filePath}: ${error.error} (${error.type})`);
        }
    }

    return lines.join('\n');
}

// Export factory
export function createCodeAnalyzer(db?: SecurityDatabase): CodeAnalyzer {
    return new CodeAnalyzer(db);
}
