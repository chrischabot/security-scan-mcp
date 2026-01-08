#!/usr/bin/env npx tsx
/**
 * Build Security Prompts Database
 *
 * Reads ALL CVEs, uses Claude to:
 * 1. Categorize each CVE into a generic software type (web-server, database, etc.)
 * 2. Extract the security issue pattern
 * 3. Build a database of security check prompts grouped by type
 *
 * Usage:
 *   ANTHROPIC_API_KEY=xxx npx tsx src/scripts/build-security-prompts.ts
 */

import { getDatabase, type SecurityPrompt, type SoftwareType } from '../db/database.js';
import { callClaudeJSON, isConfigured } from '../llm/claude-client.js';

interface CVEAnalysis {
    cve_id: string;
    software_type: string;      // e.g., "web-server", "database", "mobile-app"
    type_name: string;          // e.g., "Web Servers", "Database Systems"
    security_issue: string;     // Short description of the issue pattern
    check_prompt: string;       // Prompt to check for this issue
    severity: 'critical' | 'high' | 'medium' | 'low';
    code_signals: string[];     // How to identify this type of code
}

interface BatchAnalysisResult {
    analyses: CVEAnalysis[];
}

const BATCH_SIZE = 20;  // CVEs per Claude call
const DELAY_MS = 2000;  // Delay between calls to avoid rate limiting

async function main() {
    if (!isConfigured()) {
        console.error('ANTHROPIC_API_KEY environment variable required');
        process.exit(1);
    }

    console.log('=== Building Security Prompts Database ===\n');

    const db = getDatabase();
    const stats = db.getStats();
    console.log(`Database: ${stats.totalCVEs} CVEs, ${stats.totalCWEs} CWEs\n`);

    if (stats.totalCVEs === 0) {
        console.error('No CVEs in database. Run ingest script first.');
        process.exit(1);
    }

    // Get all CVEs
    console.log('Loading CVEs...');
    const allCVEs = getAllCVEs(db);
    console.log(`Loaded ${allCVEs.length} CVEs\n`);

    // Process in batches
    const typeMap = new Map<string, { name: string; description: string; codeSignals: Set<string> }>();
    const promptMap = new Map<string, SecurityPrompt>();
    let processedCount = 0;
    let errorCount = 0;

    console.log(`Processing in batches of ${BATCH_SIZE}...\n`);

    for (let i = 0; i < allCVEs.length; i += BATCH_SIZE) {
        const batch = allCVEs.slice(i, i + BATCH_SIZE);
        const batchNum = Math.floor(i / BATCH_SIZE) + 1;
        const totalBatches = Math.ceil(allCVEs.length / BATCH_SIZE);

        console.log(`Batch ${batchNum}/${totalBatches} (${batch.length} CVEs)...`);

        try {
            const results = await analyzeCVEBatch(batch);

            for (const analysis of results.analyses) {
                // Track software type
                if (!typeMap.has(analysis.software_type)) {
                    typeMap.set(analysis.software_type, {
                        name: analysis.type_name,
                        description: `Security checks for ${analysis.type_name.toLowerCase()}`,
                        codeSignals: new Set(analysis.code_signals)
                    });
                } else {
                    // Merge code signals
                    const existing = typeMap.get(analysis.software_type)!;
                    for (const signal of analysis.code_signals) {
                        existing.codeSignals.add(signal);
                    }
                }

                // Create prompt (dedupe by check_prompt content)
                const promptKey = `${analysis.software_type}:${analysis.security_issue}`;
                if (!promptMap.has(promptKey)) {
                    promptMap.set(promptKey, {
                        prompt_id: `${analysis.software_type}-${promptMap.size + 1}`,
                        type_id: analysis.software_type,
                        title: analysis.security_issue,
                        check_prompt: analysis.check_prompt,
                        why_it_matters: null,
                        severity: analysis.severity,
                        based_on_cves: [analysis.cve_id]
                    });
                } else {
                    // Add CVE to existing prompt
                    const existing = promptMap.get(promptKey)!;
                    if (!existing.based_on_cves.includes(analysis.cve_id)) {
                        existing.based_on_cves.push(analysis.cve_id);
                    }
                }

                processedCount++;
            }

            console.log(`  ✓ ${results.analyses.length} CVEs analyzed, ${typeMap.size} types, ${promptMap.size} prompts`);
        } catch (error) {
            console.error(`  ✗ Error: ${error}`);
            errorCount++;
        }

        // Rate limiting delay
        if (i + BATCH_SIZE < allCVEs.length) {
            await sleep(DELAY_MS);
        }
    }

    // Save to database
    console.log('\nSaving to database...');
    db.clearSecurityPrompts();

    // Insert software types
    for (const [typeId, typeInfo] of typeMap) {
        const softwareType: SoftwareType = {
            type_id: typeId,
            name: typeInfo.name,
            description: typeInfo.description,
            code_signals: Array.from(typeInfo.codeSignals)
        };
        db.insertSoftwareType(softwareType);
    }
    console.log(`  Inserted ${typeMap.size} software types`);

    // Insert prompts
    const prompts = Array.from(promptMap.values());
    db.insertSecurityPromptsBatch(prompts);
    console.log(`  Inserted ${prompts.length} security prompts`);

    // Summary
    console.log('\n=== Summary ===');
    console.log(`CVEs processed: ${processedCount}`);
    console.log(`Errors: ${errorCount}`);
    console.log(`Software types: ${typeMap.size}`);
    console.log(`Security prompts: ${prompts.length}`);

    console.log('\nTypes created:');
    for (const [typeId, typeInfo] of typeMap) {
        const count = prompts.filter(p => p.type_id === typeId).length;
        console.log(`  - ${typeInfo.name} (${typeId}): ${count} prompts`);
    }

    console.log('\nDone. Security prompts database is ready.');
}

function getAllCVEs(db: ReturnType<typeof getDatabase>): Array<{ cve_id: string; description: string; severity: string }> {
    // Search for common CVE terms to get all CVEs
    const terms = ['vulnerability', 'allows', 'attack', 'remote', 'execute', 'injection', 'overflow', 'bypass', 'denial'];
    const seen = new Set<string>();
    const result: Array<{ cve_id: string; description: string; severity: string }> = [];

    for (const term of terms) {
        const cves = db.searchCVEs(term, 10000);
        for (const cve of cves) {
            if (!seen.has(cve.cve_id)) {
                seen.add(cve.cve_id);
                result.push({
                    cve_id: cve.cve_id,
                    description: cve.description,
                    severity: cve.cvss_v3_severity || 'MEDIUM'
                });
            }
        }
    }

    return result;
}

async function analyzeCVEBatch(cves: Array<{ cve_id: string; description: string; severity: string }>): Promise<BatchAnalysisResult> {
    const cveList = cves.map(c => `[${c.cve_id}] (${c.severity}): ${c.description}`).join('\n\n');

    const prompt = `Analyze these CVEs and categorize each one.

For each CVE, determine:
1. **software_type**: Generic type ID (kebab-case) like: web-server, database, api-server, file-parser, image-processor, authentication-system, mobile-app, desktop-app, network-service, cryptographic-library, etc.
2. **type_name**: Human readable name like "Web Servers", "Database Systems"
3. **security_issue**: Short name for the vulnerability pattern (e.g., "Buffer overflow in header parsing", "SQL injection in search")
4. **check_prompt**: A prompt for a code reviewer to check for this issue. Write it generically so it applies to ANY code of this type, not just the specific product.
5. **severity**: critical/high/medium/low
6. **code_signals**: Array of things to look for in code to identify this type (e.g., ["HTTP handling", "request parsing", "socket listeners"])

CVEs to analyze:

${cveList}

Return JSON:
\`\`\`json
{
  "analyses": [
    {
      "cve_id": "CVE-XXXX-YYYY",
      "software_type": "web-server",
      "type_name": "Web Servers",
      "security_issue": "Header size validation",
      "check_prompt": "Verify that HTTP header sizes are validated before processing. Check for maximum header length limits and proper handling of oversized headers.",
      "severity": "high",
      "code_signals": ["HTTP handling", "header parsing", "request processing"]
    }
  ]
}
\`\`\``;

    const systemPrompt = `You are a security expert analyzing CVEs to build a database of security checks.
Focus on GENERIC software types (web-server, database) not specific products (Apache, MySQL).
The check_prompt should be useful for reviewing ANY code of that type.
Return valid JSON only.`;

    return callClaudeJSON<BatchAnalysisResult>(prompt, systemPrompt);
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

main().catch(console.error);
