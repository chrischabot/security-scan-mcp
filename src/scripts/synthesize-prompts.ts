#!/usr/bin/env npx tsx
/**
 * CVE Pattern Synthesis Script (Two-Phase LLM Process)
 *
 * This script uses LLMs in TWO phases:
 *
 * PHASE 1: CATEGORIZATION
 * - Read all CVEs, extract product names (Apache, nginx, WordPress, etc.)
 * - Generate prompts for LLM to categorize products into generic types
 *   "What type of software is Apache?" → "web server"
 * - Merge products into higher-level categories (web servers, databases, etc.)
 *
 * PHASE 2: SYNTHESIS
 * - For each category (not product!), gather ALL related CVEs
 * - Generate prompts for LLM to synthesize security checks
 * - Output: "When reviewing web server code, check for X, Y, Z..."
 *
 * The key insight: We don't want "Apache" prompts - we want "web server" prompts
 * that apply to ANY web server code being reviewed.
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
 * Main entry point - handles both phases
 */
async function main() {
    const args = process.argv.slice(2);
    const phase = args.find(a => a.startsWith('--phase='))?.split('=')[1] || '1';
    const dryRun = args.includes('--dry-run');
    const minProductCVEs = parseInt(args.find(a => a.startsWith('--min-cves='))?.split('=')[1] || '5');
    const categoriesFile = args.find(a => a.startsWith('--categories='))?.split('=')[1];

    if (phase === '1') {
        await runPhase1(dryRun, minProductCVEs);
    } else if (phase === '2') {
        if (!categoriesFile) {
            console.error('Phase 2 requires --categories=<file> with LLM-generated categorizations');
            process.exit(1);
        }
        await runPhase2(categoriesFile, dryRun);
    } else {
        console.error('Unknown phase. Use --phase=1 or --phase=2');
        process.exit(1);
    }
}

/**
 * PHASE 1: Extract products and generate categorization prompts
 *
 * Output: Prompts for LLM to categorize each product into a generic type
 */
async function runPhase1(dryRun: boolean, minProductCVEs: number) {
    console.log('=== PHASE 1: Product Extraction & Categorization Prompts ===\n');

    const db = getDatabase();
    const stats = db.getStats();
    console.log(`Database contains ${stats.totalCVEs} CVEs across ${stats.totalCWEs} CWEs\n`);

    const allCVEs: CVEData[] = [];
    const seenCVEs = new Set<string>();
    const productToCVEs = new Map<string, CVEData[]>();

    console.log('Step 1: Extracting CVEs and identifying products...');

    // Get all CVEs
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
                cweId: null,
                products,
                vendors
            };

            allCVEs.push(cveData);

            // Group CVEs by product
            for (const product of products) {
                const normalized = normalizeProductName(product);
                if (!productToCVEs.has(normalized)) {
                    productToCVEs.set(normalized, []);
                }
                productToCVEs.get(normalized)!.push(cveData);
            }
        }
    }

    console.log(`  Found ${allCVEs.length} unique CVEs`);
    console.log(`  Identified ${productToCVEs.size} unique products\n`);

    // Filter to products with enough CVEs
    const significantProducts = Array.from(productToCVEs.entries())
        .filter(([_, cves]) => cves.length >= minProductCVEs)
        .sort((a, b) => b[1].length - a[1].length);

    console.log(`  ${significantProducts.length} products have ${minProductCVEs}+ CVEs\n`);

    // Generate categorization prompt for LLM
    console.log('Step 2: Generating categorization prompt for LLM...\n');

    const categorizationPrompt = generateCategorizationPrompt(significantProducts);

    // Save outputs
    const outputDir = 'data';
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    // Save product data for phase 2
    const productData = {
        generatedAt: new Date().toISOString(),
        totalCVEs: allCVEs.length,
        products: significantProducts.map(([name, cves]) => ({
            normalizedName: name,
            displayName: findDisplayName(name, cves),
            cveCount: cves.length,
            sampleDescriptions: cves.slice(0, 3).map(c => c.description.substring(0, 200))
        }))
    };

    if (dryRun) {
        console.log('[DRY RUN] Would save product data and categorization prompt\n');
        console.log('=== CATEGORIZATION PROMPT FOR LLM ===\n');
        console.log(categorizationPrompt.substring(0, 3000) + '...\n');
    } else {
        fs.writeFileSync(path.join(outputDir, 'phase1-products.json'), JSON.stringify(productData, null, 2));
        fs.writeFileSync(path.join(outputDir, 'phase1-categorization-prompt.md'), categorizationPrompt);
        console.log('Saved: data/phase1-products.json');
        console.log('Saved: data/phase1-categorization-prompt.md');
    }

    console.log('\n=== NEXT STEPS ===');
    console.log('1. Run the prompt in data/phase1-categorization-prompt.md through an LLM');
    console.log('2. Save the LLM output (JSON) to data/phase1-categories.json');
    console.log('3. Run: npx tsx src/scripts/synthesize-prompts.ts --phase=2 --categories=data/phase1-categories.json');
}

/**
 * Find the most common display name for a normalized product name
 */
function findDisplayName(normalized: string, cves: CVEData[]): string {
    const nameCounts = new Map<string, number>();
    for (const cve of cves) {
        for (const p of cve.products) {
            if (normalizeProductName(p) === normalized) {
                nameCounts.set(p, (nameCounts.get(p) || 0) + 1);
            }
        }
    }
    return Array.from(nameCounts.entries())
        .sort((a, b) => b[1] - a[1])[0]?.[0] || normalized;
}

/**
 * Generate the LLM prompt for categorizing products into generic types
 */
function generateCategorizationPrompt(products: Array<[string, CVEData[]]>): string {
    const productList = products.map(([name, cves]) => {
        const displayName = findDisplayName(name, cves);
        const samples = cves.slice(0, 2).map(c =>
            `  - "${c.description.substring(0, 150)}..."`
        ).join('\n');
        return `### ${displayName} (${cves.length} CVEs)\n${samples}`;
    }).join('\n\n');

    return `# Product Categorization Task

You are categorizing software products mentioned in CVE vulnerability reports into GENERIC categories that would be useful for code review.

## Important Guidelines

1. **Think about code review**: The goal is to create categories like "web servers" or "database clients" that a code reviewer could identify, NOT specific product names like "Apache" or "MySQL"

2. **Be generic**: "Apache" → "web server", "MySQL" → "database", "OpenSSL" → "cryptographic library"

3. **Consider what code does**: A reviewer looking at code can identify "this is a web server" or "this handles file uploads" but cannot identify "this is Apache specifically"

4. **Merge similar things**: nginx, Apache, IIS → all "web server"

5. **Create useful categories** that cover ALL types of software, including:

   **Server/Backend:**
   - Web servers (HTTP request handling)
   - Database systems (SQL, data storage)
   - API servers (REST, GraphQL endpoints)
   - Authentication services (login, sessions, OAuth)
   - Network services (DNS, mail, FTP, SSH)
   - Message queues (pub/sub, async processing)

   **Desktop Applications:**
   - Image/graphics editors (Photoshop-like, rendering)
   - Document processors (PDF, Office documents)
   - Media players (video, audio playback)
   - IDEs/dev tools (code editors, debuggers)
   - Archive utilities (compression, extraction)

   **Mobile/Client:**
   - Mobile apps (iOS, Android native)
   - Browser extensions
   - Desktop clients (Electron, native)

   **Financial/Business:**
   - Banking/payment systems (transactions, accounts)
   - E-commerce platforms (checkout, inventory)
   - ERP systems (enterprise resource planning)
   - Trading platforms (financial data, orders)

   **Specialized:**
   - IoT/embedded devices (firmware, sensors)
   - Industrial control (SCADA, PLCs)
   - Medical software (health data, devices)
   - Gaming engines (rendering, networking)
   - Cryptographic libraries (encryption, signing)

   **Data Processing:**
   - File parsers (XML, JSON, binary formats)
   - Media processing (image, video, audio codecs)
   - Data serialization (protocol buffers, encoding)
   - ETL pipelines (data transformation)

   - etc. (discover more from the data!)

## Products to Categorize

${productList}

## Expected Output Format

Return a JSON object mapping each product to its generic category:

\`\`\`json
{
  "categories": {
    "web-server": {
      "name": "Web Servers",
      "description": "Software that handles HTTP requests and serves web content",
      "products": ["apache", "nginx", "iis", "tomcat"],
      "codeSignals": ["HTTP handling", "request parsing", "header processing", "URL routing"]
    },
    "database": {
      "name": "Database Systems",
      "description": "Data storage and query systems",
      "products": ["mysql", "postgresql", "mongodb"],
      "codeSignals": ["SQL queries", "data persistence", "connection pooling", "query parsing"]
    }
  }
}
\`\`\`

The "codeSignals" field should list things a code reviewer could look for to identify this type of software.

Now categorize ALL the products listed above:`;
}

/**
 * PHASE 2: Generate security prompts per CATEGORY (not per product)
 */
async function runPhase2(categoriesFile: string, dryRun: boolean) {
    console.log('=== PHASE 2: Category-Based Security Prompt Synthesis ===\n');

    // Load categorizations from LLM output
    if (!fs.existsSync(categoriesFile)) {
        console.error(`Categories file not found: ${categoriesFile}`);
        process.exit(1);
    }

    const categorizations = JSON.parse(fs.readFileSync(categoriesFile, 'utf-8'));

    // Load product data from phase 1
    const productDataFile = 'data/phase1-products.json';
    if (!fs.existsSync(productDataFile)) {
        console.error('Phase 1 data not found. Run phase 1 first.');
        process.exit(1);
    }

    // Load for validation (actual CVE retrieval happens below from DB)
    JSON.parse(fs.readFileSync(productDataFile, 'utf-8'));

    // Re-load CVEs and group by CATEGORY
    console.log('Step 1: Grouping CVEs by category...\n');

    const db = getDatabase();
    const categoryToCVEs = new Map<string, CVEData[]>();

    // Build product → category mapping
    const productToCategory = new Map<string, string>();
    for (const [categoryId, categoryInfo] of Object.entries(categorizations.categories || {})) {
        const info = categoryInfo as { products?: string[] };
        for (const product of info.products || []) {
            productToCategory.set(normalizeProductName(product), categoryId);
        }
    }

    // Fetch CVEs and assign to categories
    const seenCVEs = new Set<string>();
    const searchTerms = ['vulnerability', 'allows', 'attack', 'remote', 'execute', 'injection', 'overflow'];

    for (const term of searchTerms) {
        const cves = db.searchCVEs(term, 5000);

        for (const cve of cves) {
            if (seenCVEs.has(cve.cve_id)) continue;
            seenCVEs.add(cve.cve_id);

            const { products } = extractProductsFromDescription(cve.description);

            const cveData: CVEData = {
                cveId: cve.cve_id,
                description: cve.description,
                severity: cve.cvss_v3_severity || 'UNKNOWN',
                score: cve.cvss_v3_score,
                cweId: null,
                products,
                vendors: []
            };

            // Assign to categories
            for (const product of products) {
                const normalized = normalizeProductName(product);
                const category = productToCategory.get(normalized);
                if (category) {
                    if (!categoryToCVEs.has(category)) {
                        categoryToCVEs.set(category, []);
                    }
                    categoryToCVEs.get(category)!.push(cveData);
                }
            }
        }
    }

    console.log('Categories with CVEs:');
    for (const [cat, cves] of categoryToCVEs.entries()) {
        const info = (categorizations.categories as Record<string, { name?: string }>)[cat];
        console.log(`  ${info?.name || cat}: ${cves.length} CVEs`);
    }
    console.log('');

    // Generate synthesis prompts per category
    console.log('Step 2: Generating security synthesis prompts...\n');

    const synthesisPrompts: Array<{
        categoryId: string;
        categoryName: string;
        cveCount: number;
        prompt: string;
    }> = [];

    for (const [categoryId, cves] of categoryToCVEs.entries()) {
        const categoryInfo = (categorizations.categories as Record<string, {
            name?: string;
            description?: string;
            codeSignals?: string[];
        }>)[categoryId];

        if (!categoryInfo) continue;

        const prompt = generateCategorySynthesisPrompt(
            categoryId,
            categoryInfo.name || categoryId,
            categoryInfo.description || '',
            categoryInfo.codeSignals || [],
            cves
        );

        synthesisPrompts.push({
            categoryId,
            categoryName: categoryInfo.name || categoryId,
            cveCount: cves.length,
            prompt
        });
    }

    // Save outputs
    const outputDir = 'data';
    const promptsDir = path.join(outputDir, 'phase2-synthesis-prompts');

    if (dryRun) {
        console.log('[DRY RUN] Would save synthesis prompts\n');
        if (synthesisPrompts[0]) {
            console.log('=== SAMPLE SYNTHESIS PROMPT ===\n');
            console.log(synthesisPrompts[0].prompt.substring(0, 2000) + '...\n');
        }
    } else {
        if (!fs.existsSync(promptsDir)) {
            fs.mkdirSync(promptsDir, { recursive: true });
        }

        for (const sp of synthesisPrompts) {
            const filename = `${sp.categoryId}.md`;
            fs.writeFileSync(path.join(promptsDir, filename), sp.prompt);
        }

        // Save summary
        const summary = {
            generatedAt: new Date().toISOString(),
            categories: synthesisPrompts.map(sp => ({
                id: sp.categoryId,
                name: sp.categoryName,
                cveCount: sp.cveCount
            }))
        };
        fs.writeFileSync(path.join(outputDir, 'phase2-summary.json'), JSON.stringify(summary, null, 2));

        console.log(`Saved ${synthesisPrompts.length} synthesis prompts to: ${promptsDir}/`);
    }

    console.log('\n=== NEXT STEPS ===');
    console.log('1. Run each prompt in data/phase2-synthesis-prompts/ through an LLM');
    console.log('2. The LLM will generate security checks for each category');
    console.log('3. Save outputs to data/security-checks/<category>.json');
    console.log('4. The MCP server will load these at runtime');
}

/**
 * Generate synthesis prompt for a CATEGORY (not a product)
 */
function generateCategorySynthesisPrompt(
    categoryId: string,
    categoryName: string,
    description: string,
    codeSignals: string[],
    cves: CVEData[]
): string {
    // Deduplicate CVEs and take a good sample
    const uniqueCVEs = Array.from(new Map(cves.map(c => [c.cveId, c])).values());
    const sampleCVEs = uniqueCVEs
        .sort((a, b) => (b.score || 0) - (a.score || 0))  // Prioritize higher severity
        .slice(0, 50);

    const cveList = sampleCVEs
        .map(cve => `[${cve.cveId}] (${cve.severity}): ${cve.description}`)
        .join('\n\n');

    const patterns = extractSecurityPatterns(uniqueCVEs.map(c => c.description));

    return `# Security Check Synthesis: ${categoryName}

You are creating security review prompts for **${categoryName}** - ${description}

## How to Identify This Type of Code

A code reviewer can identify ${categoryName.toLowerCase()} code by looking for:
${codeSignals.map(s => `- ${s}`).join('\n')}

## Common Vulnerability Patterns Found (${uniqueCVEs.length} CVEs analyzed)

${patterns.join(', ')}

## Real CVE Examples (${sampleCVEs.length} shown)

${cveList}

---

## Your Task

Create security check prompts that apply to ANY ${categoryName.toLowerCase()} code, not just specific products.

For each vulnerability pattern you observe across multiple CVEs, create a check:

1. **Title**: Short name (e.g., "Request Header Size Validation")
2. **Check Prompt**: What to look for - written so it applies to ANY ${categoryName.toLowerCase()}
   - GOOD: "Verify that HTTP header sizes are validated before processing"
   - BAD: "Check Apache's LimitRequestFieldSize setting"
3. **Why It Matters**: What can go wrong (reference CVE IDs)
4. **Severity**: critical/high/medium/low
5. **Code Signals**: What patterns in code indicate this check is relevant

## Output Format

\`\`\`json
{
  "category": "${categoryId}",
  "categoryName": "${categoryName}",
  "securityChecks": [
    {
      "id": "${categoryId}-001",
      "title": "Descriptive Title",
      "checkPrompt": "When reviewing ${categoryName.toLowerCase()} code, verify that... Look for... Ensure that...",
      "whyItMatters": "CVE-XXXX and CVE-YYYY show that failing to do this leads to...",
      "severity": "high",
      "codeSignals": ["function names", "patterns", "imports that indicate this check applies"]
    }
  ],
  "generalPrinciples": [
    "Universal principle for ${categoryName.toLowerCase()} security"
  ]
}
\`\`\`

Generate checks that would help someone reviewing ANY ${categoryName.toLowerCase()} code, regardless of which specific product or framework they're using.`;
}

main().catch(console.error);
