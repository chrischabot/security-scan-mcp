#!/usr/bin/env node

/**
 * Security Vulnerability Analyzer MCP Server
 *
 * An MCP server that provides security vulnerability scanning capabilities
 * using NVD CVE data, CWE taxonomy, and AST-based pattern matching.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import fs from 'fs';

import { getDatabase, closeDatabase, SecurityDatabase } from './db/database.js';
import { createCodeAnalyzer, CodeAnalyzer, ScanResult, Finding } from './analyzer/code-analyzer.js';
import { getCWE, getCWEsForAppType, getCWEsSortedByDanger, AppType, CWEEntry } from './cwe/taxonomy.js';
import { SupportedLanguage } from './parser/tree-sitter-parser.js';
import { Severity } from './patterns/pattern-library.js';

// Initialize components
let db: SecurityDatabase;
let analyzer: CodeAnalyzer;

async function initializeComponents(): Promise<void> {
    db = getDatabase();
    analyzer = createCodeAnalyzer(db);
}

// Create MCP server
const server = new McpServer({
    name: 'security-scan-mcp',
    version: '1.0.0'
});

// =============================================================================
// Tool: scan_file
// =============================================================================
server.tool(
    'scan_file',
    'Scan a single source file for security vulnerabilities',
    {
        file_path: z.string().describe('Absolute path to the file to scan'),
        severity_threshold: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
            .optional()
            .default('MEDIUM')
            .describe('Minimum severity level to report'),
        include_cve_context: z.boolean()
            .optional()
            .default(true)
            .describe('Include related CVEs for each finding'),
        enable_taint_analysis: z.boolean()
            .optional()
            .default(true)
            .describe('Enable taint analysis for injection vulnerabilities'),
        enable_entropy_detection: z.boolean()
            .optional()
            .default(false)
            .describe('Enable high-entropy string detection for secrets'),
        include_secrets_patterns: z.boolean()
            .optional()
            .default(true)
            .describe('Include enhanced API key and secrets patterns')
    },
    async ({ file_path, severity_threshold, include_cve_context, enable_taint_analysis, enable_entropy_detection, include_secrets_patterns }) => {
        try {
            if (!fs.existsSync(file_path)) {
                return {
                    content: [{
                        type: 'text',
                        text: JSON.stringify({ error: `File not found: ${file_path}` })
                    }]
                };
            }

            const findings = await analyzer.scanFile(file_path, {
                severityThreshold: severity_threshold as Severity,
                includeCVEContext: include_cve_context,
                enableTaintAnalysis: enable_taint_analysis,
                enableEntropyDetection: enable_entropy_detection,
                includeSecretsPatterns: include_secrets_patterns
            });

            const result = {
                file: file_path,
                totalFindings: findings.length,
                findings: findings.map(f => formatFindingForOutput(f))
            };

            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify(result, null, 2)
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({
                        error: error instanceof Error ? error.message : String(error)
                    })
                }]
            };
        }
    }
);

// =============================================================================
// Tool: scan_directory
// =============================================================================
server.tool(
    'scan_directory',
    'Scan a directory or codebase for security vulnerabilities',
    {
        directory_path: z.string().describe('Path to the directory to scan'),
        severity_threshold: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
            .optional()
            .default('MEDIUM')
            .describe('Minimum severity level to report'),
        languages: z.array(z.enum(['javascript', 'typescript', 'tsx', 'python', 'go', 'rust']))
            .optional()
            .describe('Only scan specific languages'),
        cwe_ids: z.array(z.number())
            .optional()
            .describe('Only scan for specific CWE IDs'),
        include_cve_context: z.boolean()
            .optional()
            .default(false)
            .describe('Include related CVEs (slower)'),
        exclude_patterns: z.array(z.string())
            .optional()
            .describe('Glob patterns to exclude'),
        skip_test_files: z.boolean()
            .optional()
            .default(false)
            .describe('Skip test files (reduces false positives)'),
        skip_example_files: z.boolean()
            .optional()
            .default(false)
            .describe('Skip example/sample files'),
        enable_entropy_detection: z.boolean()
            .optional()
            .default(false)
            .describe('Enable high-entropy string detection for secrets'),
        include_secrets_patterns: z.boolean()
            .optional()
            .default(true)
            .describe('Include enhanced API key and secrets patterns'),
        output_format: z.enum(['json', 'sarif'])
            .optional()
            .default('json')
            .describe('Output format (json or sarif for GitHub/IDE integration)')
    },
    async ({ directory_path, severity_threshold, languages, cwe_ids, include_cve_context, exclude_patterns, skip_test_files, skip_example_files, enable_entropy_detection, include_secrets_patterns, output_format }) => {
        try {
            if (!fs.existsSync(directory_path)) {
                return {
                    content: [{
                        type: 'text',
                        text: JSON.stringify({ error: `Directory not found: ${directory_path}` })
                    }]
                };
            }

            const result = await analyzer.scanDirectory(directory_path, {
                severityThreshold: severity_threshold as Severity,
                languages: languages as SupportedLanguage[],
                cweIds: cwe_ids,
                includeCVEContext: include_cve_context,
                excludePatterns: exclude_patterns,
                skipTestFiles: skip_test_files,
                skipExampleFiles: skip_example_files,
                enableEntropyDetection: enable_entropy_detection,
                includeSecretsPatterns: include_secrets_patterns
            });

            // Output in requested format
            if (output_format === 'sarif') {
                const { toSarifString } = await import('./output/sarif.js');
                return {
                    content: [{
                        type: 'text',
                        text: toSarifString(result, directory_path)
                    }]
                };
            }

            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify(formatScanResultForOutput(result), null, 2)
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({
                        error: error instanceof Error ? error.message : String(error)
                    })
                }]
            };
        }
    }
);

// =============================================================================
// Tool: get_cwe_info
// =============================================================================
server.tool(
    'get_cwe_info',
    'Get detailed information about a specific CWE (Common Weakness Enumeration)',
    {
        cwe_id: z.number().describe('The CWE ID number (e.g., 79 for XSS)')
    },
    async ({ cwe_id }) => {
        const cwe = getCWE(cwe_id);

        if (!cwe) {
            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({ error: `CWE-${cwe_id} not found` })
                }]
            };
        }

        // Get related CVEs from database
        const relatedCVEs = db.getCVEsByCWE(cwe_id, 10);

        const result = {
            cwe_id: cwe.cwe_id,
            name: cwe.name,
            description: cwe.description,
            abstraction: cwe.abstraction,
            parent_cwe_id: cwe.parent_cwe_id,
            danger_score: cwe.dangerScore,
            exploit_likelihood: cwe.exploitLikelihood,
            technical_impact: cwe.technicalImpact,
            applicable_app_types: cwe.applicableAppTypes,
            related_cves: relatedCVEs.map(cve => ({
                cve_id: cve.cve_id,
                description: cve.description.substring(0, 200) + '...',
                severity: cve.cvss_v3_severity,
                score: cve.cvss_v3_score
            }))
        };

        return {
            content: [{
                type: 'text',
                text: JSON.stringify(result, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: get_cves_by_cwe
// =============================================================================
server.tool(
    'get_cves_by_cwe',
    'Get CVEs (Common Vulnerabilities and Exposures) related to a specific CWE',
    {
        cwe_id: z.number().describe('The CWE ID to look up CVEs for'),
        limit: z.number().optional().default(20).describe('Maximum number of CVEs to return'),
        severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional().describe('Filter by severity')
    },
    async ({ cwe_id, limit, severity }) => {
        let cves = db.getCVEsByCWE(cwe_id, limit);

        if (severity) {
            cves = cves.filter(c => c.cvss_v3_severity === severity);
        }

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    cwe_id,
                    total_cves: cves.length,
                    cves: cves.map(cve => ({
                        cve_id: cve.cve_id,
                        published: cve.published_date,
                        severity: cve.cvss_v3_severity,
                        score: cve.cvss_v3_score,
                        description: cve.description
                    }))
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: search_cves
// =============================================================================
server.tool(
    'search_cves',
    'Search CVE database using full-text search',
    {
        query: z.string().describe('Search query (keywords, product names, etc.)'),
        limit: z.number().optional().default(20).describe('Maximum results to return')
    },
    async ({ query, limit }) => {
        const cves = db.searchCVEs(query, limit);

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    query,
                    total_results: cves.length,
                    results: cves.map(cve => ({
                        cve_id: cve.cve_id,
                        published: cve.published_date,
                        severity: cve.cvss_v3_severity,
                        score: cve.cvss_v3_score,
                        description: cve.description
                    }))
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: get_top_cwes
// =============================================================================
server.tool(
    'get_top_cwes',
    'Get the most dangerous CWEs, optionally filtered by application type',
    {
        app_type: z.enum(['web', 'api', 'cli', 'desktop', 'mobile', 'library', 'general'])
            .optional()
            .describe('Filter CWEs by application type'),
        limit: z.number().optional().default(10).describe('Number of CWEs to return')
    },
    async ({ app_type, limit }) => {
        let cwes: CWEEntry[];

        if (app_type) {
            cwes = getCWEsForAppType(app_type as AppType);
        } else {
            cwes = getCWEsSortedByDanger();
        }

        cwes = cwes.slice(0, limit);

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    app_type: app_type || 'all',
                    cwes: cwes.map(cwe => ({
                        cwe_id: cwe.cwe_id,
                        name: cwe.name,
                        danger_score: cwe.dangerScore,
                        exploit_likelihood: cwe.exploitLikelihood,
                        description: cwe.description?.substring(0, 200)
                    }))
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: suggest_remediation
// =============================================================================
server.tool(
    'suggest_remediation',
    'Get remediation suggestions for a specific vulnerability type',
    {
        cwe_id: z.number().describe('The CWE ID for the vulnerability'),
        language: z.enum(['javascript', 'typescript', 'python', 'go', 'rust'])
            .describe('Programming language for code examples'),
        context: z.string().optional().describe('Optional context about the specific vulnerability instance')
    },
    async ({ cwe_id, language, context: _context }) => {
        const cwe = getCWE(cwe_id);

        if (!cwe) {
            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({ error: `CWE-${cwe_id} not found` })
                }]
            };
        }

        // Get remediation based on CWE
        const remediation = getRemediationForCWE(cwe_id, language);

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    cwe_id,
                    cwe_name: cwe.name,
                    general_guidance: remediation.general,
                    code_example: remediation.codeExample,
                    secure_alternative: remediation.secureAlternative,
                    references: remediation.references
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: list_software_types
// =============================================================================
server.tool(
    'list_software_types',
    'List all software types that have security prompts. Use this to see what types of applications have security checks available.',
    {},
    async () => {
        const types = db.getAllSoftwareTypes();
        const stats = db.getSecurityPromptsStats();

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    total_types: types.length,
                    total_prompts: stats.totalPrompts,
                    types: types.map(t => ({
                        type_id: t.type_id,
                        name: t.name,
                        description: t.description,
                        prompt_count: stats.promptsByType[t.type_id] || 0,
                        code_signals: t.code_signals
                    }))
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: identify_software_type
// =============================================================================
server.tool(
    'identify_software_type',
    'Given code or a description, identify what software type it is. Returns matching types with their code signals.',
    {
        code_sample: z.string().optional().describe('A sample of code to analyze'),
        description: z.string().optional().describe('Description of what the software does'),
        file_patterns: z.array(z.string()).optional().describe('File patterns in the codebase (e.g., "routes/*.ts", "handlers/*.go")')
    },
    async ({ code_sample, description, file_patterns }) => {
        const types = db.getAllSoftwareTypes();

        // Score each type based on matches
        const scores: Array<{ type: typeof types[0]; score: number; matches: string[] }> = [];

        for (const type of types) {
            let score = 0;
            const matches: string[] = [];

            for (const signal of type.code_signals) {
                const signalLower = signal.toLowerCase();

                if (code_sample && code_sample.toLowerCase().includes(signalLower)) {
                    score += 2;
                    matches.push(`Code contains: "${signal}"`);
                }

                if (description && description.toLowerCase().includes(signalLower)) {
                    score += 1;
                    matches.push(`Description mentions: "${signal}"`);
                }

                if (file_patterns) {
                    for (const pattern of file_patterns) {
                        if (pattern.toLowerCase().includes(signalLower)) {
                            score += 1;
                            matches.push(`File pattern matches: "${signal}"`);
                        }
                    }
                }
            }

            if (score > 0) {
                scores.push({ type, score, matches });
            }
        }

        // Sort by score descending
        scores.sort((a, b) => b.score - a.score);

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    identified_types: scores.slice(0, 5).map(s => ({
                        type_id: s.type.type_id,
                        name: s.type.name,
                        confidence_score: s.score,
                        matches: s.matches
                    })),
                    recommendation: scores.length > 0
                        ? `Most likely type: ${scores[0].type.name} (${scores[0].type.type_id})`
                        : 'No matching types found. Consider running build-security-prompts to populate the database.'
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: get_security_prompts_for_type
// =============================================================================
server.tool(
    'get_security_prompts_for_type',
    'Get all security check prompts for a specific software type. These prompts are derived from real CVEs and tell you what to look for when reviewing code of this type.',
    {
        type_id: z.string().describe('The software type ID (e.g., "web-server", "database", "api-server")'),
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Filter by severity'),
        format: z.enum(['json', 'checklist']).optional().default('json').describe('Output format')
    },
    async ({ type_id, severity, format }) => {
        const typeInfo = db.getSoftwareType(type_id);
        if (!typeInfo) {
            return {
                content: [{
                    type: 'text',
                    text: JSON.stringify({
                        error: `Software type "${type_id}" not found`,
                        available_types: db.getAllSoftwareTypes().map(t => t.type_id)
                    })
                }]
            };
        }

        let prompts = db.getSecurityPromptsByType(type_id);

        if (severity) {
            prompts = prompts.filter(p => p.severity === severity);
        }

        if (format === 'checklist') {
            const checklist = prompts.map((p, i) =>
                `## ${i + 1}. ${p.title} [${p.severity.toUpperCase()}]\n\n${p.check_prompt}\n\n${p.why_it_matters ? `**Why:** ${p.why_it_matters}\n\n` : ''}${p.based_on_cves.length > 0 ? `*Based on: ${p.based_on_cves.slice(0, 3).join(', ')}${p.based_on_cves.length > 3 ? '...' : ''}*` : ''}`
            ).join('\n\n---\n\n');

            return {
                content: [{
                    type: 'text',
                    text: `# Security Review Checklist: ${typeInfo.name}\n\n${typeInfo.description}\n\n**Code Signals:** ${typeInfo.code_signals.join(', ')}\n\n---\n\n${checklist}`
                }]
            };
        }

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    type_id: typeInfo.type_id,
                    type_name: typeInfo.name,
                    description: typeInfo.description,
                    code_signals: typeInfo.code_signals,
                    total_prompts: prompts.length,
                    prompts: prompts.map(p => ({
                        id: p.prompt_id,
                        title: p.title,
                        severity: p.severity,
                        check_prompt: p.check_prompt,
                        why_it_matters: p.why_it_matters,
                        based_on_cves: p.based_on_cves
                    }))
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: search_security_prompts
// =============================================================================
server.tool(
    'search_security_prompts',
    'Search security prompts across all types using full-text search',
    {
        query: z.string().describe('Search query (e.g., "SQL injection", "buffer overflow", "authentication")'),
        limit: z.number().optional().default(20).describe('Maximum results to return')
    },
    async ({ query, limit }) => {
        const prompts = db.searchSecurityPrompts(query, limit);

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    query,
                    total_results: prompts.length,
                    results: prompts.map(p => ({
                        id: p.prompt_id,
                        type_id: p.type_id,
                        title: p.title,
                        severity: p.severity,
                        check_prompt: p.check_prompt
                    }))
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Tool: get_database_stats
// =============================================================================
server.tool(
    'get_database_stats',
    'Get statistics about the vulnerability database',
    {},
    async () => {
        const stats = db.getStats();
        const promptStats = db.getSecurityPromptsStats();

        return {
            content: [{
                type: 'text',
                text: JSON.stringify({
                    total_cves: stats.totalCVEs,
                    total_cwes: stats.totalCWEs,
                    total_patterns: stats.totalPatterns,
                    cves_by_severity: stats.cvesBySeverity,
                    security_prompts: {
                        total_types: promptStats.totalTypes,
                        total_prompts: promptStats.totalPrompts,
                        prompts_by_type: promptStats.promptsByType
                    },
                    database_path: db.getDbPath()
                }, null, 2)
            }]
        };
    }
);

// =============================================================================
// Helper Functions
// =============================================================================

function formatFindingForOutput(finding: Finding): Record<string, unknown> {
    return {
        id: finding.id,
        severity: finding.severity,
        confidence: finding.confidence,
        pattern: finding.patternName,
        file: finding.filePath,
        location: `${finding.location.startLine}:${finding.location.startColumn}`,
        cwe: {
            id: finding.cweId,
            name: finding.cweName
        },
        message: finding.message,
        matched_code: finding.matchedCode,
        remediation: finding.remediation,
        taint_info: finding.taintInfo ? {
            source: finding.taintInfo.source,
            source_line: finding.taintInfo.sourceLocation.startLine,
            propagation_steps: finding.taintInfo.propagationSteps
        } : undefined,
        related_cves: finding.relatedCVEs?.map(c => ({
            id: c.cve_id,
            severity: c.cvss_v3_severity,
            score: c.cvss_v3_score
        }))
    };
}

function formatScanResultForOutput(result: ScanResult): Record<string, unknown> {
    return {
        scan_id: result.scanId,
        duration_ms: result.durationMs,
        files_scanned: result.filesScanned,
        total_findings: result.totalFindings,
        summary: {
            by_severity: result.findingsBySeverity,
            by_cwe: Object.entries(result.findingsByCWE).map(([cweId, count]) => {
                const cwe = getCWE(parseInt(cweId));
                return {
                    cwe_id: parseInt(cweId),
                    cwe_name: cwe?.name,
                    count
                };
            })
        },
        findings: result.findings.map(f => formatFindingForOutput(f)),
        errors: result.errors.length > 0 ? result.errors : undefined
    };
}

interface RemediationInfo {
    general: string;
    codeExample: string;
    secureAlternative: string;
    references: string[];
}

function getRemediationForCWE(cweId: number, language: string): RemediationInfo {
    const remediations: Record<number, Record<string, RemediationInfo>> = {
        79: {  // XSS
            javascript: {
                general: 'Sanitize all user input before rendering in HTML. Use Content Security Policy headers.',
                codeExample: `// Vulnerable
element.innerHTML = userInput;

// Secure
element.textContent = userInput;
// Or use DOMPurify for HTML
element.innerHTML = DOMPurify.sanitize(userInput);`,
                secureAlternative: 'Use textContent instead of innerHTML, or sanitize with DOMPurify',
                references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html']
            },
            python: {
                general: 'Use template engines with auto-escaping enabled. Sanitize user input.',
                codeExample: `# Vulnerable (Flask without escaping)
return f"<p>{user_input}</p>"

# Secure (Flask with escaping)
from markupsafe import escape
return f"<p>{escape(user_input)}</p>"`,
                secureAlternative: 'Use Jinja2 with autoescape=True, or use markupsafe.escape()',
                references: ['https://flask.palletsprojects.com/en/2.0.x/security/']
            },
            typescript: {
                general: 'Sanitize all user input before rendering. Use React\'s built-in XSS protection.',
                codeExample: `// Vulnerable
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Secure
<div>{userInput}</div>
// Or sanitize first
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />`,
                secureAlternative: 'Avoid dangerouslySetInnerHTML, or sanitize with DOMPurify first',
                references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html']
            },
            go: {
                general: 'Use html/template package which auto-escapes. Never use text/template for HTML.',
                codeExample: `// Vulnerable
fmt.Fprintf(w, "<p>%s</p>", userInput)

// Secure
import "html/template"
tmpl := template.Must(template.New("").Parse("<p>{{.}}</p>"))
tmpl.Execute(w, userInput)`,
                secureAlternative: 'Use html/template instead of text/template or fmt.Fprintf',
                references: ['https://pkg.go.dev/html/template']
            },
            rust: {
                general: 'Use templating libraries with auto-escaping like Tera or Askama.',
                codeExample: `// Use Tera or Askama templates which auto-escape by default
// Or manually escape with the html_escape crate`,
                secureAlternative: 'Use Tera, Askama, or similar templating engines with auto-escape',
                references: ['https://tera.netlify.app/docs/']
            }
        },
        89: {  // SQL Injection
            javascript: {
                general: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL.',
                codeExample: `// Vulnerable
db.query(\`SELECT * FROM users WHERE id = \${userId}\`);

// Secure
db.query('SELECT * FROM users WHERE id = ?', [userId]);`,
                secureAlternative: 'Use parameterized queries with placeholders (?, $1, etc.)',
                references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html']
            },
            python: {
                general: 'Use parameterized queries. Never use f-strings or .format() for SQL.',
                codeExample: `# Vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Secure
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`,
                secureAlternative: 'Use parameterized queries with cursor.execute(sql, params)',
                references: ['https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders']
            },
            typescript: {
                general: 'Use parameterized queries or an ORM with built-in sanitization.',
                codeExample: `// Vulnerable
await db.query(\`SELECT * FROM users WHERE id = \${userId}\`);

// Secure
await db.query('SELECT * FROM users WHERE id = $1', [userId]);`,
                secureAlternative: 'Use parameterized queries or Prisma/TypeORM with type-safe queries',
                references: ['https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access']
            },
            go: {
                general: 'Use prepared statements with placeholder arguments.',
                codeExample: `// Vulnerable
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId))

// Secure
db.Query("SELECT * FROM users WHERE id = $1", userId)`,
                secureAlternative: 'Use db.Query with placeholder arguments ($1, $2, etc.)',
                references: ['https://go.dev/doc/database/sql-injection']
            },
            rust: {
                general: 'Use query builders or prepared statements with sqlx or diesel.',
                codeExample: `// Vulnerable
sqlx::query(&format!("SELECT * FROM users WHERE id = {}", user_id))

// Secure
sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)`,
                secureAlternative: 'Use sqlx::query! macro or diesel query builder',
                references: ['https://docs.rs/sqlx/latest/sqlx/']
            }
        },
        78: {  // Command Injection
            javascript: {
                general: 'Avoid shell execution. Use execFile/spawn with argument arrays.',
                codeExample: `// Vulnerable
exec(\`ls \${userDir}\`);

// Secure
execFile('ls', [userDir]);`,
                secureAlternative: 'Use execFile or spawn with argument arrays instead of exec',
                references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html']
            },
            python: {
                general: 'Use subprocess with shell=False and a list of arguments.',
                codeExample: `# Vulnerable
subprocess.run(f"ls {user_dir}", shell=True)

# Secure
subprocess.run(["ls", user_dir], shell=False)`,
                secureAlternative: 'Use subprocess.run with a list and shell=False',
                references: ['https://docs.python.org/3/library/subprocess.html#security-considerations']
            },
            typescript: {
                general: 'Avoid shell execution. Use execFile/spawn with argument arrays.',
                codeExample: `// Vulnerable
exec(\`ls \${userDir}\`);

// Secure
execFile('ls', [userDir]);`,
                secureAlternative: 'Use execFile or spawn with argument arrays',
                references: ['https://nodejs.org/api/child_process.html#child_processexecfilefile-args-options-callback']
            },
            go: {
                general: 'Use exec.Command with separate arguments, avoid shell invocation.',
                codeExample: `// Vulnerable
exec.Command("sh", "-c", "ls " + userDir)

// Secure
exec.Command("ls", userDir)`,
                secureAlternative: 'Use exec.Command with separate arguments, never invoke shell',
                references: ['https://pkg.go.dev/os/exec']
            },
            rust: {
                general: 'Use std::process::Command with separate arguments.',
                codeExample: `// Vulnerable
Command::new("sh").arg("-c").arg(format!("ls {}", user_dir))

// Secure
Command::new("ls").arg(&user_dir)`,
                secureAlternative: 'Use Command::new with .arg() for each argument',
                references: ['https://doc.rust-lang.org/std/process/struct.Command.html']
            }
        }
    };

    const cweRemediations = remediations[cweId];
    if (cweRemediations && cweRemediations[language]) {
        return cweRemediations[language];
    }

    // Default remediation
    return {
        general: `Review the CWE-${cweId} documentation for remediation guidance.`,
        codeExample: 'See CWE documentation for language-specific examples.',
        secureAlternative: 'Consult security best practices for your framework.',
        references: [`https://cwe.mitre.org/data/definitions/${cweId}.html`]
    };
}

// =============================================================================
// Main Entry Point
// =============================================================================

async function main(): Promise<void> {
    try {
        // Initialize components
        await initializeComponents();
        console.error('Security Scan MCP Server initialized');

        // Connect to transport
        const transport = new StdioServerTransport();
        await server.connect(transport);

        console.error('Server connected via stdio');
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    closeDatabase();
    process.exit(0);
});

process.on('SIGTERM', () => {
    closeDatabase();
    process.exit(0);
});

// Start the server
main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
