#!/usr/bin/env node

/**
 * Security Scan MCP Server
 *
 * An MCP server that provides CVE-driven security prompts for code review.
 * The core feature is security checklists derived from real CVEs, categorized
 * by generic software type (web-server, database, mobile-app, etc.).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { getDatabase, closeDatabase, SecurityDatabase } from './db/database.js';
import { getCWE, getCWEsForAppType, getCWEsSortedByDanger, AppType, CWEEntry } from './cwe/taxonomy.js';

// Initialize components
let db: SecurityDatabase;

async function initializeComponents(): Promise<void> {
    db = getDatabase();
}

// Create MCP server
const server = new McpServer({
    name: 'security-scan-mcp',
    version: '1.0.0'
});

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
