#!/usr/bin/env npx tsx

import { createCodeAnalyzer, formatScanReport } from './src/analyzer/code-analyzer.js';

async function main() {
    const targetDir = process.argv[2] || './test-project';
    const severityThreshold = (process.argv[3] || 'MEDIUM') as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

    const analyzer = createCodeAnalyzer();
    console.log(`Scanning ${targetDir}...\n`);

    const result = await analyzer.scanDirectory(targetDir, {
        severityThreshold,
        enableTaintAnalysis: true
    });

    console.log(formatScanReport(result));
}

main().catch(console.error);
