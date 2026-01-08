#!/usr/bin/env node

/**
 * CLI for testing MCP functions directly
 *
 * Usage:
 *   npm run cli list-types
 *   npm run cli get-prompts <type_id> [--severity critical|high|medium|low] [--checklist]
 *   npm run cli search-prompts <query>
 *   npm run cli search-cves <query>
 *   npm run cli cwe <cwe_id>
 *   npm run cli stats
 */

import { getDatabase, closeDatabase } from './db/database.js';
import { getCWE, getCWEsForAppType, getCWEsSortedByDanger } from './cwe/taxonomy.js';

const db = getDatabase();

const commands: Record<string, (args: string[]) => void> = {
    'list-types': () => {
        const types = db.getAllSoftwareTypes();
        const stats = db.getSecurityPromptsStats();

        console.log(`\nSoftware Types (${types.length} total, ${stats.totalPrompts} prompts)\n`);

        if (types.length === 0) {
            console.log('No software types found. Run `npm run build-prompts` first.');
            return;
        }

        for (const t of types) {
            const count = stats.promptsByType[t.type_id] || 0;
            console.log(`  ${t.type_id} (${count} prompts)`);
            console.log(`    Name: ${t.name}`);
            console.log(`    Signals: ${t.code_signals.join(', ')}`);
            console.log();
        }
    },

    'get-prompts': (args) => {
        const typeId = args[0];
        if (!typeId) {
            console.error('Usage: npm run cli get-prompts <type_id> [--severity critical|high|medium|low] [--checklist]');
            process.exit(1);
        }

        const typeInfo = db.getSoftwareType(typeId);
        if (!typeInfo) {
            console.error(`Software type "${typeId}" not found.`);
            console.log('Available types:', db.getAllSoftwareTypes().map(t => t.type_id).join(', '));
            process.exit(1);
        }

        let prompts = db.getSecurityPromptsByType(typeId);

        // Check for severity filter
        const severityIdx = args.indexOf('--severity');
        if (severityIdx !== -1 && args[severityIdx + 1]) {
            const severity = args[severityIdx + 1];
            prompts = prompts.filter(p => p.severity === severity);
        }

        const isChecklist = args.includes('--checklist');

        if (isChecklist) {
            console.log(`\n# Security Review Checklist: ${typeInfo.name}\n`);
            console.log(`${typeInfo.description}\n`);
            console.log(`**Code Signals:** ${typeInfo.code_signals.join(', ')}\n`);
            console.log('---\n');

            prompts.forEach((p, i) => {
                console.log(`## ${i + 1}. ${p.title} [${p.severity.toUpperCase()}]\n`);
                console.log(p.check_prompt);
                if (p.why_it_matters) {
                    console.log(`\n**Why:** ${p.why_it_matters}`);
                }
                if (p.based_on_cves.length > 0) {
                    console.log(`\n*Based on: ${p.based_on_cves.slice(0, 3).join(', ')}${p.based_on_cves.length > 3 ? '...' : ''}*`);
                }
                console.log('\n---\n');
            });
        } else {
            console.log(`\nSecurity Prompts for ${typeInfo.name} (${prompts.length} prompts)\n`);
            console.log(JSON.stringify({
                type_id: typeInfo.type_id,
                type_name: typeInfo.name,
                description: typeInfo.description,
                code_signals: typeInfo.code_signals,
                prompts: prompts.map(p => ({
                    id: p.prompt_id,
                    title: p.title,
                    severity: p.severity,
                    check_prompt: p.check_prompt,
                    based_on_cves: p.based_on_cves
                }))
            }, null, 2));
        }
    },

    'search-prompts': (args) => {
        const query = args.join(' ');
        if (!query) {
            console.error('Usage: npm run cli search-prompts <query>');
            process.exit(1);
        }

        const prompts = db.searchSecurityPrompts(query, 20);

        console.log(`\nSearch results for "${query}" (${prompts.length} results)\n`);

        if (prompts.length === 0) {
            console.log('No prompts found.');
            return;
        }

        for (const p of prompts) {
            console.log(`  [${p.severity.toUpperCase()}] ${p.title}`);
            console.log(`    Type: ${p.type_id}`);
            console.log(`    ${p.check_prompt.substring(0, 100)}...`);
            console.log();
        }
    },

    'search-cves': (args) => {
        const query = args.join(' ');
        if (!query) {
            console.error('Usage: npm run cli search-cves <query>');
            process.exit(1);
        }

        const cves = db.searchCVEs(query, 20);

        console.log(`\nCVE search results for "${query}" (${cves.length} results)\n`);

        if (cves.length === 0) {
            console.log('No CVEs found.');
            return;
        }

        for (const cve of cves) {
            console.log(`  ${cve.cve_id} [${cve.cvss_v3_severity || 'N/A'}] (${cve.cvss_v3_score || 'N/A'})`);
            console.log(`    ${cve.description.substring(0, 120)}...`);
            console.log();
        }
    },

    'cwe': (args) => {
        const cweId = parseInt(args[0]);
        if (isNaN(cweId)) {
            console.error('Usage: npm run cli cwe <cwe_id>');
            process.exit(1);
        }

        const cwe = getCWE(cweId);
        if (!cwe) {
            console.error(`CWE-${cweId} not found.`);
            process.exit(1);
        }

        const relatedCVEs = db.getCVEsByCWE(cweId, 5);

        console.log(`\nCWE-${cwe.cwe_id}: ${cwe.name}\n`);
        console.log(`Description: ${cwe.description}`);
        console.log(`Abstraction: ${cwe.abstraction}`);
        console.log(`Danger Score: ${cwe.dangerScore}`);
        console.log(`Exploit Likelihood: ${cwe.exploitLikelihood}`);

        if (relatedCVEs.length > 0) {
            console.log(`\nRelated CVEs:`);
            for (const cve of relatedCVEs) {
                console.log(`  ${cve.cve_id} [${cve.cvss_v3_severity}]`);
            }
        }
    },

    'top-cwes': (args) => {
        const appType = args[0] as 'web' | 'api' | 'cli' | 'desktop' | 'mobile' | 'library' | 'general' | undefined;

        let cwes;
        if (appType) {
            cwes = getCWEsForAppType(appType);
        } else {
            cwes = getCWEsSortedByDanger();
        }

        cwes = cwes.slice(0, 10);

        console.log(`\nTop CWEs${appType ? ` for ${appType}` : ''}\n`);

        for (const cwe of cwes) {
            console.log(`  CWE-${cwe.cwe_id}: ${cwe.name}`);
            console.log(`    Danger: ${cwe.dangerScore}, Likelihood: ${cwe.exploitLikelihood}`);
        }
    },

    'stats': () => {
        const stats = db.getStats();
        const promptStats = db.getSecurityPromptsStats();

        console.log('\nDatabase Statistics\n');
        console.log(`  CVEs: ${stats.totalCVEs}`);
        console.log(`  CWEs: ${stats.totalCWEs}`);
        console.log(`  Software Types: ${promptStats.totalTypes}`);
        console.log(`  Security Prompts: ${promptStats.totalPrompts}`);

        if (Object.keys(stats.cvesBySeverity).length > 0) {
            console.log('\n  CVEs by Severity:');
            for (const [severity, count] of Object.entries(stats.cvesBySeverity)) {
                console.log(`    ${severity}: ${count}`);
            }
        }

        if (Object.keys(promptStats.promptsByType).length > 0) {
            console.log('\n  Prompts by Type:');
            for (const [type, count] of Object.entries(promptStats.promptsByType)) {
                console.log(`    ${type}: ${count}`);
            }
        }

        console.log(`\n  Database: ${db.getDbPath()}`);
    },

    'help': () => {
        console.log(`
Security Scan MCP CLI

Commands:
  list-types                          List all software types with prompts
  get-prompts <type_id> [options]     Get security prompts for a type
    --severity <level>                Filter by critical/high/medium/low
    --checklist                       Output as markdown checklist
  search-prompts <query>              Search security prompts
  search-cves <query>                 Search CVE database
  cwe <cwe_id>                        Get CWE information
  top-cwes [app_type]                 Get top CWEs (optionally by app type)
  stats                               Show database statistics
  help                                Show this help

Examples:
  npm run cli list-types
  npm run cli get-prompts web-server
  npm run cli get-prompts web-server --severity critical --checklist
  npm run cli search-prompts "SQL injection"
  npm run cli search-cves "apache"
  npm run cli cwe 79
  npm run cli top-cwes web
  npm run cli stats
`);
    }
};

// Main
const command = process.argv[2];
const args = process.argv.slice(3);

if (!command || !commands[command]) {
    if (command && command !== 'help') {
        console.error(`Unknown command: ${command}`);
    }
    commands.help();
    process.exit(command ? 1 : 0);
}

try {
    commands[command](args);
} finally {
    closeDatabase();
}
