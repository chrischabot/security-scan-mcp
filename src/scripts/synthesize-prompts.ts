#!/usr/bin/env npx tsx
/**
 * CVE Pattern Synthesis Script
 *
 * BUILD-TIME script that:
 * 1. Reads ALL CVEs from the database
 * 2. Extracts product/vendor names dynamically (no hardcoded categories)
 * 3. Clusters CVEs by product type that EMERGE from the data
 * 4. Generates prompts for an LLM to synthesize security checks
 * 5. Stores results for runtime use
 *
 * The categories are NOT predefined - they come from what's actually in the CVE data.
 */

import fs from 'fs';
import path from 'path';
import { getDatabase } from '../db/database.js';

interface CVEData {
    cveId: string;
    description: string;
    severity: string;
    score: number | null;
    cweId: number | null;
    products: string[];  // Extracted from description
    vendors: string[];   // Extracted from description
}

interface ProductCluster {
    name: string;
    normalizedName: string;
    cveCount: number;
    cves: CVEData[];
    relatedProducts: string[];  // Products often mentioned together
    commonPatterns: string[];   // Security issues that appear frequently
}

/**
 * Extract product and vendor names from CVE description
 * Uses patterns commonly found in CVE descriptions
 */
function extractProductsFromDescription(description: string): { products: string[], vendors: string[] } {
    const products: Set<string> = new Set();
    const vendors: Set<string> = new Set();

    // Common CVE description patterns:
    // "X in ProductName before version Y allows..."
    // "ProductName version X through Y has..."
    // "VendorName ProductName X.Y.Z..."
    // "A vulnerability in Vendor Product..."

    const patterns = [
        // "in ProductName before/through version"
        /(?:in|of)\s+([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z][A-Za-z0-9_.-]+)?)\s+(?:before|through|prior|up to|versions?)/gi,
        // "ProductName version X.Y"
        /([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z][A-Za-z0-9_.-]+)?)\s+(?:version\s+)?(\d+\.[\d.]+)/gi,
        // "vulnerability in ProductName"
        /vulnerability\s+in\s+([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z][A-Za-z0-9_.-]+)?)/gi,
        // "affects ProductName"
        /affects?\s+([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z][A-Za-z0-9_.-]+)?)/gi,
        // "ProductName allows/enables"
        /([A-Z][A-Za-z0-9_.-]+(?:\s+[A-Z][A-Za-z0-9_.-]+)?)\s+(?:allows?|enables?|permits?)/gi,
    ];

    for (const pattern of patterns) {
        const matches = description.matchAll(pattern);
        for (const match of matches) {
            const name = match[1]?.trim();
            if (name && name.length > 2 && name.length < 50) {
                // Filter out common false positives
                const lower = name.toLowerCase();
                if (!isCommonWord(lower)) {
                    products.add(name);
                }
            }
        }
    }

    // Extract vendor patterns like "Vendor's Product" or "Vendor Product"
    const vendorPatterns = [
        /([A-Z][a-z]+(?:[\s][A-Z][a-z]+)?)'s\s+/g,
        /(?:by|from)\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)?)/gi,
    ];

    for (const pattern of vendorPatterns) {
        const matches = description.matchAll(pattern);
        for (const match of matches) {
            const name = match[1]?.trim();
            if (name && name.length > 2 && name.length < 30 && !isCommonWord(name.toLowerCase())) {
                vendors.add(name);
            }
        }
    }

    return {
        products: Array.from(products),
        vendors: Array.from(vendors)
    };
}

/**
 * Common words that aren't product names
 */
function isCommonWord(word: string): boolean {
    const commonWords = new Set([
        'the', 'a', 'an', 'this', 'that', 'these', 'those',
        'remote', 'local', 'authenticated', 'unauthenticated',
        'attacker', 'attackers', 'user', 'users', 'admin', 'administrator',
        'server', 'client', 'system', 'application', 'software', 'program',
        'vulnerability', 'vulnerabilities', 'issue', 'issues', 'flaw', 'bug',
        'allows', 'allow', 'enables', 'enable', 'permits', 'permit',
        'certain', 'specific', 'multiple', 'various', 'some', 'any',
        'version', 'versions', 'release', 'releases', 'update', 'updates',
        'before', 'after', 'through', 'prior', 'between',
        'arbitrary', 'malicious', 'crafted', 'specially',
        'code', 'command', 'script', 'file', 'data', 'input', 'output',
        'execute', 'execution', 'inject', 'injection', 'overflow', 'bypass',
        'denial', 'service', 'information', 'disclosure', 'memory', 'buffer',
        'cross', 'site', 'request', 'forgery', 'scripting',
        'sql', 'xml', 'html', 'http', 'https', 'ftp', 'ssh', 'tcp', 'udp',
        'integer', 'stack', 'heap', 'null', 'pointer', 'string', 'array',
        'function', 'method', 'parameter', 'argument', 'value', 'variable',
        'access', 'control', 'permission', 'privilege', 'authentication',
        'authorization', 'session', 'cookie', 'token', 'password', 'credential',
        'read', 'write', 'delete', 'modify', 'create', 'upload', 'download',
        'path', 'directory', 'folder', 'url', 'uri', 'link', 'redirect',
        'error', 'exception', 'handling', 'validation', 'sanitization',
        'impact', 'severity', 'critical', 'high', 'medium', 'low',
        'cve', 'cwe', 'cvss', 'nvd', 'nist'
    ]);
    return commonWords.has(word.toLowerCase());
}

/**
 * Normalize product name for clustering
 */
function normalizeProductName(name: string): string {
    return name
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '')
        .replace(/\d+$/, '');  // Remove trailing version numbers
}

/**
 * Extract security patterns from CVE descriptions dynamically
 * Uses n-gram extraction to find common phrases, no hardcoded terms
 */
function extractSecurityPatterns(descriptions: string[]): string[] {
    const phraseCounts = new Map<string, number>();

    // Extract 2-gram and 3-gram phrases from descriptions
    for (const desc of descriptions) {
        const words = desc.toLowerCase()
            .replace(/[^a-z0-9\s-]/g, ' ')
            .split(/\s+/)
            .filter(w => w.length > 2);

        // 2-grams
        for (let i = 0; i < words.length - 1; i++) {
            const phrase = `${words[i]} ${words[i + 1]}`;
            if (!isBoringPhrase(phrase)) {
                phraseCounts.set(phrase, (phraseCounts.get(phrase) || 0) + 1);
            }
        }

        // 3-grams
        for (let i = 0; i < words.length - 2; i++) {
            const phrase = `${words[i]} ${words[i + 1]} ${words[i + 2]}`;
            if (!isBoringPhrase(phrase)) {
                phraseCounts.set(phrase, (phraseCounts.get(phrase) || 0) + 1);
            }
        }
    }

    // Return phrases that appear frequently (at least 5% of descriptions or 5 times)
    const threshold = Math.max(5, Math.floor(descriptions.length * 0.05));
    return Array.from(phraseCounts.entries())
        .filter(([_, count]) => count >= threshold)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([phrase, count]) => `${phrase} (${count})`);
}

/**
 * Filter out boring/common phrases that aren't security-relevant
 */
function isBoringPhrase(phrase: string): boolean {
    const boringStarts = ['the ', 'a ', 'an ', 'this ', 'that ', 'in the', 'to the', 'of the', 'and the'];
    const boringPhrases = ['allows remote', 'remote attacker', 'remote attackers', 'to execute', 'allows attacker'];

    for (const start of boringStarts) {
        if (phrase.startsWith(start)) return true;
    }
    for (const bp of boringPhrases) {
        if (phrase === bp) return true;
    }
    return false;
}

/**
 * Main: Read all CVEs and cluster by product
 */
async function main() {
    const args = process.argv.slice(2);
    const dryRun = args.includes('--dry-run');
    const minClusterSize = parseInt(args.find(a => a.startsWith('--min-size='))?.split('=')[1] || '10');

    console.log('=== CVE Pattern Synthesis ===\n');
    console.log('Reading CVEs and extracting product clusters dynamically...\n');

    const db = getDatabase();

    // Get ALL CVEs from the database - no hardcoded CWE list
    // First get all unique CWEs that have CVEs
    const stats = db.getStats();
    console.log(`Database contains ${stats.totalCVEs} CVEs across ${stats.totalCWEs} CWEs\n`);

    const allCVEs: CVEData[] = [];
    const seenCVEs = new Set<string>();
    const productCounts = new Map<string, number>();

    console.log('Step 1: Extracting CVEs and identifying products...');

    // Search for all CVEs using a broad query, or iterate through all CWEs in DB
    // We'll use searchCVEs with common terms to get everything
    const searchTerms = ['vulnerability', 'allows', 'attack', 'remote', 'execute', 'injection', 'overflow'];

    for (const term of searchTerms) {
        const cves = db.searchCVEs(term, 5000);

        for (const cve of cves) {
            if (seenCVEs.has(cve.cve_id)) continue;
            seenCVEs.add(cve.cve_id);

            const { products, vendors } = extractProductsFromDescription(cve.description);

            const cveData: CVEData = {
                cveId: cve.cve_id,
                description: cve.description,
                severity: cve.cvss_v3_severity || 'UNKNOWN',
                score: cve.cvss_v3_score,
                cweId: null,  // CWE association is in separate table
                products,
                vendors
            };

            allCVEs.push(cveData);

            // Count product occurrences
            for (const product of products) {
                const normalized = normalizeProductName(product);
                productCounts.set(normalized, (productCounts.get(normalized) || 0) + 1);
            }
        }
    }

    console.log(`  Found ${allCVEs.length} unique CVEs`);
    console.log(`  Identified ${productCounts.size} unique products\n`);

    // Step 2: Build clusters for products with enough CVEs
    console.log(`Step 2: Building clusters (min size: ${minClusterSize})...`);

    const clusters = new Map<string, ProductCluster>();

    // Find products with enough CVEs to form a cluster
    const significantProducts = Array.from(productCounts.entries())
        .filter(([_, count]) => count >= minClusterSize)
        .sort((a, b) => b[1] - a[1]);

    console.log(`  Found ${significantProducts.length} products with ${minClusterSize}+ CVEs\n`);

    for (const [normalizedName, _] of significantProducts) {
        // Find all CVEs mentioning this product
        const clusterCVEs = allCVEs.filter(cve =>
            cve.products.some(p => normalizeProductName(p) === normalizedName)
        );

        if (clusterCVEs.length >= minClusterSize) {
            // Find the most common non-normalized name
            const nameCounts = new Map<string, number>();
            for (const cve of clusterCVEs) {
                for (const p of cve.products) {
                    if (normalizeProductName(p) === normalizedName) {
                        nameCounts.set(p, (nameCounts.get(p) || 0) + 1);
                    }
                }
            }
            const displayName = Array.from(nameCounts.entries())
                .sort((a, b) => b[1] - a[1])[0]?.[0] || normalizedName;

            // Find related products (often mentioned together)
            const relatedCounts = new Map<string, number>();
            for (const cve of clusterCVEs) {
                for (const p of cve.products) {
                    const pNorm = normalizeProductName(p);
                    if (pNorm !== normalizedName) {
                        relatedCounts.set(p, (relatedCounts.get(p) || 0) + 1);
                    }
                }
            }
            const relatedProducts = Array.from(relatedCounts.entries())
                .filter(([_, count]) => count >= 3)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([name]) => name);

            // Extract common security patterns
            const commonPatterns = extractSecurityPatterns(clusterCVEs.map(c => c.description));

            clusters.set(normalizedName, {
                name: displayName,
                normalizedName,
                cveCount: clusterCVEs.length,
                cves: clusterCVEs,
                relatedProducts,
                commonPatterns
            });
        }
    }

    // Step 3: Print summary and generate synthesis prompts
    console.log('Step 3: Generated clusters:\n');

    const sortedClusters = Array.from(clusters.values())
        .sort((a, b) => b.cveCount - a.cveCount);

    for (const cluster of sortedClusters.slice(0, 30)) {
        console.log(`  ${cluster.name}: ${cluster.cveCount} CVEs`);
        if (cluster.commonPatterns.length > 0) {
            console.log(`    Patterns: ${cluster.commonPatterns.slice(0, 3).join(', ')}`);
        }
        if (cluster.relatedProducts.length > 0) {
            console.log(`    Related: ${cluster.relatedProducts.slice(0, 3).join(', ')}`);
        }
    }

    // Step 4: Generate synthesis prompts
    console.log('\n\nStep 4: Generating LLM synthesis prompts...\n');

    const synthesisPrompts: Array<{
        productName: string;
        cveCount: number;
        prompt: string;
    }> = [];

    for (const cluster of sortedClusters) {
        const prompt = generateSynthesisPrompt(cluster);
        synthesisPrompts.push({
            productName: cluster.name,
            cveCount: cluster.cveCount,
            prompt
        });
    }

    // Step 5: Save output
    const outputDir = 'data';
    const outputPath = path.join(outputDir, 'cve-clusters.json');

    const outputData = {
        generatedAt: new Date().toISOString(),
        totalCVEs: allCVEs.length,
        totalClusters: clusters.size,
        clusters: sortedClusters.map(c => ({
            name: c.name,
            normalizedName: c.normalizedName,
            cveCount: c.cveCount,
            commonPatterns: c.commonPatterns,
            relatedProducts: c.relatedProducts,
            sampleCVEs: c.cves.slice(0, 5).map(cve => ({
                id: cve.cveId,
                severity: cve.severity,
                description: cve.description.substring(0, 200) + '...'
            }))
        })),
        synthesisPrompts
    };

    if (dryRun) {
        console.log('[DRY RUN] Would save to:', outputPath);
        console.log('\nSample synthesis prompt:');
        console.log('---');
        if (synthesisPrompts[0]) {
            console.log(synthesisPrompts[0].prompt.substring(0, 1500) + '...');
        }
    } else {
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        fs.writeFileSync(outputPath, JSON.stringify(outputData, null, 2));
        console.log(`Saved clusters to: ${outputPath}`);

        // Save individual prompts
        const promptsDir = path.join(outputDir, 'synthesis-prompts');
        if (!fs.existsSync(promptsDir)) {
            fs.mkdirSync(promptsDir, { recursive: true });
        }

        for (const sp of synthesisPrompts) {
            const safeFilename = sp.productName.toLowerCase().replace(/[^a-z0-9]+/g, '-');
            const promptFile = path.join(promptsDir, `${safeFilename}.md`);
            fs.writeFileSync(promptFile, sp.prompt);
        }
        console.log(`Saved ${synthesisPrompts.length} prompts to: ${promptsDir}/`);
    }

    console.log('\n=== Next Steps ===');
    console.log('1. Review the clusters in data/cve-clusters.json');
    console.log('2. Run each prompt in data/synthesis-prompts/ through an LLM');
    console.log('3. The LLM will synthesize security checks from the CVE patterns');
    console.log('4. Save the LLM outputs to data/security-checks/');
}

/**
 * Generate the LLM prompt for synthesizing security checks from a cluster
 */
function generateSynthesisPrompt(cluster: ProductCluster): string {
    const sampleCVEs = cluster.cves
        .slice(0, 40)
        .map(cve => `[${cve.cveId}] (${cve.severity}${cve.score ? `, ${cve.score}` : ''}): ${cve.description}`)
        .join('\n\n');

    return `# Security Check Synthesis: ${cluster.name}

You are a security expert analyzing ${cluster.cveCount} real CVEs affecting **${cluster.name}** to create actionable security review prompts.

## Overview
- **Product**: ${cluster.name}
- **Total CVEs analyzed**: ${cluster.cveCount}
- **Common vulnerability patterns**: ${cluster.commonPatterns.join(', ') || 'Various'}
- **Related products**: ${cluster.relatedProducts.join(', ') || 'None identified'}

## CVE Examples (${Math.min(40, cluster.cves.length)} of ${cluster.cveCount})

${sampleCVEs}

---

## Your Task

Analyze these real-world vulnerabilities and synthesize security check prompts.

For EACH distinct vulnerability pattern you observe across multiple CVEs, create a security check:

1. **Title**: Short descriptive name
2. **Check Prompt**: Natural language instruction for what to look for in code (2-3 sentences)
3. **Why It Matters**: What can go wrong (reference specific CVEs as evidence)
4. **Severity**: critical/high/medium/low
5. **Category**: Type of vulnerability (e.g., buffer-overflow, injection, auth-bypass)

Focus on patterns that appear in MULTIPLE CVEs - those are the checks worth creating.

## Expected Output Format

\`\`\`json
{
  "productType": "${cluster.name}",
  "securityChecks": [
    {
      "id": "unique-id",
      "title": "Descriptive Title",
      "checkPrompt": "When reviewing ${cluster.name} code, verify that... Look for... Ensure that...",
      "whyItMatters": "Based on CVE-XXXX and CVE-YYYY, failing to do this leads to...",
      "severity": "high",
      "category": "buffer-overflow",
      "basedOnCVEs": ["CVE-XXXX", "CVE-YYYY", "CVE-ZZZZ"]
    }
  ],
  "generalPrinciples": [
    "Cross-cutting security principle derived from these CVEs"
  ]
}
\`\`\`

Generate as many checks as the CVE data supports - don't force patterns that aren't there, but don't miss patterns that appear multiple times.`;
}

main().catch(console.error);
