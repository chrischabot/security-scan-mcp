#!/usr/bin/env npx tsx

import { createCodeAnalyzer, formatScanReport } from './src/analyzer/code-analyzer.js';

async function main() {
    const analyzer = createCodeAnalyzer();
    console.log('Scanning test-project directory...\n');

    const result = await analyzer.scanDirectory('./test-project', {
        severityThreshold: 'LOW',
        enableTaintAnalysis: true
    });

    console.log(formatScanReport(result));
}

main().catch(console.error);
