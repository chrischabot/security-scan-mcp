#!/usr/bin/env node

/**
 * CVE Ingestion Script
 * Fetches CVE data from NVD API and populates the database
 */

import 'dotenv/config';

import { createNVDClient } from '../nvd/client.js';
import { getDatabase, SecurityDatabase, CVERecord } from '../db/database.js';
import { CWE_TOP_25, CWE_HIERARCHY } from '../cwe/taxonomy.js';

// Default API key (can be overridden via environment variable)
const DEFAULT_API_KEY = '463fbd5b-6769-40ac-9323-17fa8ee244d5';

interface IngestOptions {
    apiKey?: string;
    yearsBack?: number;
    severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    cweIds?: number[];
    dryRun?: boolean;
}

async function ingestCVEs(options: IngestOptions = {}): Promise<void> {
    const apiKey = options.apiKey || process.env.NVD_API_KEY || DEFAULT_API_KEY;
    const yearsBack = options.yearsBack || 5;
    const severity = options.severity;

    console.log('═══════════════════════════════════════════════════════');
    console.log('           CVE Ingestion Script');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`API Key: ${apiKey ? '***' + apiKey.slice(-4) : 'None (using rate-limited access)'}`);
    console.log(`Years to fetch: ${yearsBack}`);
    console.log(`Severity filter: ${severity || 'All HIGH and CRITICAL'}`);
    console.log('');

    // Initialize database
    const db = getDatabase();
    console.log(`Database path: ${db.getDbPath()}`);

    // Seed CWE data first
    console.log('\n📚 Seeding CWE taxonomy data...');
    seedCWEData(db);

    // Initialize NVD client
    const client = createNVDClient({ apiKey });

    // Calculate date range
    const endDate = new Date();
    const startDate = new Date();
    startDate.setFullYear(startDate.getFullYear() - yearsBack);

    console.log(`\n📥 Fetching CVEs from ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}`);

    if (options.dryRun) {
        console.log('DRY RUN - No data will be saved');
        return;
    }

    let totalFetched = 0;
    let totalInserted = 0;
    let batchBuffer: CVERecord[] = [];
    const BATCH_SIZE = 100;

    // Fetch HIGH severity CVEs
    console.log('\n🔴 Fetching HIGH severity CVEs...');
    for await (const parsed of client.fetchCVEsByDateRange(startDate, endDate, 'HIGH')) {
        totalFetched++;
        batchBuffer.push(parsed.cve);

        // Link CVE to CWEs
        for (const cweId of parsed.cweIds) {
            db.linkCVEToCWE(parsed.cve.cve_id, cweId);
        }

        if (batchBuffer.length >= BATCH_SIZE) {
            db.insertCVEBatch(batchBuffer);
            totalInserted += batchBuffer.length;
            console.log(`  Inserted ${totalInserted} CVEs...`);
            batchBuffer = [];
        }
    }

    // Fetch CRITICAL severity CVEs
    console.log('\n🔥 Fetching CRITICAL severity CVEs...');
    for await (const parsed of client.fetchCVEsByDateRange(startDate, endDate, 'CRITICAL')) {
        totalFetched++;
        batchBuffer.push(parsed.cve);

        // Link CVE to CWEs
        for (const cweId of parsed.cweIds) {
            db.linkCVEToCWE(parsed.cve.cve_id, cweId);
        }

        if (batchBuffer.length >= BATCH_SIZE) {
            db.insertCVEBatch(batchBuffer);
            totalInserted += batchBuffer.length;
            console.log(`  Inserted ${totalInserted} CVEs...`);
            batchBuffer = [];
        }
    }

    // Insert remaining buffer
    if (batchBuffer.length > 0) {
        db.insertCVEBatch(batchBuffer);
        totalInserted += batchBuffer.length;
    }

    // Optimize database
    console.log('\n⚡ Optimizing database...');
    db.optimize();

    // Print statistics
    const stats = db.getStats();
    console.log('\n═══════════════════════════════════════════════════════');
    console.log('           Ingestion Complete');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`Total CVEs fetched: ${totalFetched}`);
    console.log(`Total CVEs in database: ${stats.totalCVEs}`);
    console.log(`CVEs by severity:`);
    console.log(`  CRITICAL: ${stats.cvesBySeverity['CRITICAL'] || 0}`);
    console.log(`  HIGH: ${stats.cvesBySeverity['HIGH'] || 0}`);
    console.log(`  MEDIUM: ${stats.cvesBySeverity['MEDIUM'] || 0}`);
    console.log(`  LOW: ${stats.cvesBySeverity['LOW'] || 0}`);
    console.log('');

    db.close();
}

function seedCWEData(db: SecurityDatabase): void {
    const allCWEs = [...CWE_TOP_25, ...CWE_HIERARCHY];
    let inserted = 0;

    // Sort CWEs so that parents (those without parent_cwe_id or with lower abstraction level)
    // are inserted first. Pillars first, then Classes, then Bases, then Variants.
    const abstractionOrder: Record<string, number> = {
        'Pillar': 0,
        'Class': 1,
        'Base': 2,
        'Variant': 3,
        'Compound': 4
    };

    const sortedCWEs = [...allCWEs].sort((a, b) => {
        const aOrder = abstractionOrder[a.abstraction || 'Variant'] ?? 5;
        const bOrder = abstractionOrder[b.abstraction || 'Variant'] ?? 5;
        return aOrder - bOrder;
    });

    // First pass: insert all CWEs without parent references
    for (const cwe of sortedCWEs) {
        db.insertCWE({
            cwe_id: cwe.cwe_id,
            name: cwe.name,
            description: cwe.description || null,
            abstraction: cwe.abstraction || null,
            parent_cwe_id: null,  // Insert without parent first
            status: cwe.status || null,
            likelihood_of_exploit: cwe.likelihood_of_exploit || null
        });
        inserted++;
    }

    // Second pass: update with parent references
    for (const cwe of sortedCWEs) {
        if (cwe.parent_cwe_id) {
            db.insertCWE({
                cwe_id: cwe.cwe_id,
                name: cwe.name,
                description: cwe.description || null,
                abstraction: cwe.abstraction || null,
                parent_cwe_id: cwe.parent_cwe_id,
                status: cwe.status || null,
                likelihood_of_exploit: cwe.likelihood_of_exploit || null
            });
        }
    }

    console.log(`  Inserted ${inserted} CWE entries`);
}

/**
 * Fetch CVEs for specific CWEs (e.g., Top 25)
 */
async function ingestCVEsByCWE(cweIds: number[], options: IngestOptions = {}): Promise<void> {
    const apiKey = options.apiKey || process.env.NVD_API_KEY || DEFAULT_API_KEY;

    console.log('═══════════════════════════════════════════════════════');
    console.log('           CVE Ingestion by CWE');
    console.log('═══════════════════════════════════════════════════════');
    console.log(`CWEs to fetch: ${cweIds.join(', ')}`);

    const db = getDatabase();
    const client = createNVDClient({ apiKey });

    // Seed CWE data first
    seedCWEData(db);

    let totalInserted = 0;

    for (const cweId of cweIds) {
        console.log(`\n📥 Fetching CVEs for CWE-${cweId}...`);

        const batchBuffer: CVERecord[] = [];

        for await (const parsed of client.fetchCVEsByCWE(cweId, 'HIGH')) {
            batchBuffer.push(parsed.cve);

            for (const linkedCweId of parsed.cweIds) {
                db.linkCVEToCWE(parsed.cve.cve_id, linkedCweId);
            }

            if (batchBuffer.length >= 100) {
                db.insertCVEBatch(batchBuffer);
                totalInserted += batchBuffer.length;
                batchBuffer.length = 0;
            }
        }

        if (batchBuffer.length > 0) {
            db.insertCVEBatch(batchBuffer);
            totalInserted += batchBuffer.length;
        }

        console.log(`  Total CVEs for CWE-${cweId}: ${db.getCVEsByCWE(cweId, 1000).length}`);
    }

    db.optimize();

    console.log(`\n✅ Total CVEs inserted: ${totalInserted}`);
    db.close();
}

/**
 * Incremental update - fetch recently modified CVEs
 */
async function updateCVEs(options: IngestOptions = {}): Promise<void> {
    const apiKey = options.apiKey || process.env.NVD_API_KEY || DEFAULT_API_KEY;

    console.log('═══════════════════════════════════════════════════════');
    console.log('           Incremental CVE Update');
    console.log('═══════════════════════════════════════════════════════');

    const db = getDatabase();
    const client = createNVDClient({ apiKey });

    // Fetch CVEs modified in the last 7 days
    const since = new Date();
    since.setDate(since.getDate() - 7);

    console.log(`Fetching CVEs modified since ${since.toISOString().split('T')[0]}...`);

    let updated = 0;

    for await (const parsed of client.fetchModifiedCVEs(since)) {
        if (parsed.cve.cvss_v3_severity === 'HIGH' || parsed.cve.cvss_v3_severity === 'CRITICAL') {
            db.insertCVE(parsed.cve);
            for (const cweId of parsed.cweIds) {
                db.linkCVEToCWE(parsed.cve.cve_id, cweId);
            }
            updated++;
        }
    }

    console.log(`\n✅ Updated ${updated} CVEs`);
    db.close();
}

// CLI handling
const args = process.argv.slice(2);
const command = args[0] || 'ingest';

switch (command) {
    case 'ingest':
        const years = parseInt(args[1] || '5', 10);
        ingestCVEs({ yearsBack: years }).catch(console.error);
        break;

    case 'update':
        updateCVEs().catch(console.error);
        break;

    case 'top25':
        // Ingest CVEs for CWE Top 25
        const top25Ids = CWE_TOP_25.map(c => c.cwe_id);
        ingestCVEsByCWE(top25Ids).catch(console.error);
        break;

    case 'seed':
        // Just seed CWE data without fetching CVEs
        const db = getDatabase();
        seedCWEData(db);
        console.log('CWE data seeded successfully');
        db.close();
        break;

    default:
        console.log(`
Usage: npx tsx src/scripts/ingest-cves.ts [command] [options]

Commands:
  ingest [years]  - Fetch HIGH/CRITICAL CVEs from the last N years (default: 5)
  update          - Incremental update - fetch CVEs modified in last 7 days
  top25           - Fetch CVEs for CWE Top 25 vulnerabilities
  seed            - Seed CWE taxonomy data without fetching CVEs

Examples:
  npx tsx src/scripts/ingest-cves.ts ingest 3    # Fetch 3 years of CVEs
  npx tsx src/scripts/ingest-cves.ts update      # Update recent modifications
  npx tsx src/scripts/ingest-cves.ts top25       # Fetch for Top 25 CWEs
`);
}
