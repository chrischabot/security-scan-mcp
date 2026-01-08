/**
 * SARIF (Static Analysis Results Interchange Format) Output
 *
 * SARIF 2.1.0 compliant output for integration with:
 * - GitHub Code Scanning
 * - VS Code SARIF Viewer
 * - Azure DevOps
 * - Other SARIF-compatible tools
 */

import { ScanResult, Finding } from '../analyzer/code-analyzer.js';
import crypto from 'crypto';

// SARIF 2.1.0 Schema Types
export interface SarifLog {
    $schema: string;
    version: string;
    runs: SarifRun[];
}

export interface SarifRun {
    tool: SarifTool;
    results: SarifResult[];
    invocations?: SarifInvocation[];
}

export interface SarifTool {
    driver: SarifToolComponent;
}

export interface SarifToolComponent {
    name: string;
    version: string;
    informationUri?: string;
    rules: SarifReportingDescriptor[];
}

export interface SarifReportingDescriptor {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription?: { text: string };
    helpUri?: string;
    help?: { text: string; markdown?: string };
    defaultConfiguration?: {
        level: 'none' | 'note' | 'warning' | 'error';
    };
    properties?: {
        tags?: string[];
        'security-severity'?: string;
        precision?: 'very-high' | 'high' | 'medium' | 'low';
    };
}

export interface SarifResult {
    ruleId: string;
    ruleIndex?: number;
    level: 'none' | 'note' | 'warning' | 'error';
    message: { text: string };
    locations: SarifLocation[];
    partialFingerprints?: Record<string, string>;
    fingerprints?: Record<string, string>;
    codeFlows?: SarifCodeFlow[];
    relatedLocations?: SarifLocation[];
    properties?: Record<string, unknown>;
}

export interface SarifLocation {
    physicalLocation: {
        artifactLocation: {
            uri: string;
            uriBaseId?: string;
        };
        region: {
            startLine: number;
            startColumn?: number;
            endLine?: number;
            endColumn?: number;
            snippet?: { text: string };
        };
    };
    message?: { text: string };
}

export interface SarifCodeFlow {
    threadFlows: SarifThreadFlow[];
}

export interface SarifThreadFlow {
    locations: SarifThreadFlowLocation[];
}

export interface SarifThreadFlowLocation {
    location: SarifLocation;
    kinds?: string[];
    nestingLevel?: number;
}

export interface SarifInvocation {
    executionSuccessful: boolean;
    startTimeUtc?: string;
    endTimeUtc?: string;
    workingDirectory?: { uri: string };
}

/**
 * Convert severity to SARIF level
 */
function severityToLevel(severity: string): 'error' | 'warning' | 'note' {
    switch (severity) {
        case 'CRITICAL':
        case 'HIGH':
            return 'error';
        case 'MEDIUM':
            return 'warning';
        case 'LOW':
        case 'INFO':
        default:
            return 'note';
    }
}

/**
 * Convert severity to security-severity score (0.0-10.0)
 */
function severityToScore(severity: string): string {
    switch (severity) {
        case 'CRITICAL':
            return '9.0';
        case 'HIGH':
            return '7.0';
        case 'MEDIUM':
            return '5.0';
        case 'LOW':
            return '3.0';
        case 'INFO':
        default:
            return '1.0';
    }
}

/**
 * Generate a fingerprint for deduplication
 */
function generateFingerprint(finding: Finding): string {
    const content = `${finding.patternId}:${finding.filePath}:${finding.location.startLine}:${finding.matchedCode}`;
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
}

/**
 * Generate a partial fingerprint based on pattern + code
 */
function generatePartialFingerprint(finding: Finding): string {
    // Partial fingerprint ignores location, useful for tracking issues that move
    const content = `${finding.patternId}:${finding.matchedCode.trim()}`;
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
}

/**
 * Convert scan results to SARIF format
 */
export function toSarif(result: ScanResult, baseUri?: string): SarifLog {
    // Collect unique rules from findings
    const rulesMap = new Map<string, SarifReportingDescriptor>();

    for (const finding of result.findings) {
        if (!rulesMap.has(finding.patternId)) {
            rulesMap.set(finding.patternId, {
                id: finding.patternId,
                name: finding.patternName,
                shortDescription: { text: finding.message },
                fullDescription: { text: finding.description },
                helpUri: finding.references[0],
                help: {
                    text: finding.remediation,
                    markdown: `## Remediation\n\n${finding.remediation}\n\n## CWE\n\n[CWE-${finding.cweId}](https://cwe.mitre.org/data/definitions/${finding.cweId}.html): ${finding.cweName || 'Unknown'}`
                },
                defaultConfiguration: {
                    level: severityToLevel(finding.severity)
                },
                properties: {
                    tags: [
                        'security',
                        `CWE-${finding.cweId}`,
                        `external/cwe/cwe-${finding.cweId}`
                    ],
                    'security-severity': severityToScore(finding.severity),
                    precision: finding.confidence === 'HIGH' ? 'high' : finding.confidence === 'MEDIUM' ? 'medium' : 'low'
                }
            });
        }
    }

    const rules = Array.from(rulesMap.values());
    const ruleIndexMap = new Map(rules.map((r, i) => [r.id, i]));

    // Convert findings to SARIF results
    const results: SarifResult[] = result.findings.map(finding => {
        const sarifResult: SarifResult = {
            ruleId: finding.patternId,
            ruleIndex: ruleIndexMap.get(finding.patternId),
            level: severityToLevel(finding.severity),
            message: {
                text: `${finding.message}\n\nCWE-${finding.cweId}: ${finding.cweName || 'Unknown'}`
            },
            locations: [{
                physicalLocation: {
                    artifactLocation: {
                        uri: finding.filePath,
                        uriBaseId: baseUri ? '%SRCROOT%' : undefined
                    },
                    region: {
                        startLine: finding.location.startLine,
                        startColumn: finding.location.startColumn,
                        endLine: finding.location.endLine,
                        endColumn: finding.location.endColumn,
                        snippet: { text: finding.matchedCode }
                    }
                }
            }],
            fingerprints: {
                'primaryLocationLineHash': generateFingerprint(finding)
            },
            partialFingerprints: {
                'primaryLocationLineHash/v1': generatePartialFingerprint(finding)
            },
            properties: {
                confidence: finding.confidence,
                cweId: finding.cweId
            }
        };

        // Add taint flow information if available
        if (finding.taintInfo) {
            sarifResult.codeFlows = [{
                threadFlows: [{
                    locations: [
                        {
                            location: {
                                physicalLocation: {
                                    artifactLocation: { uri: finding.filePath },
                                    region: {
                                        startLine: finding.taintInfo.sourceLocation.startLine,
                                        startColumn: finding.taintInfo.sourceLocation.startColumn
                                    }
                                },
                                message: { text: `Taint source: ${finding.taintInfo.source}` }
                            },
                            kinds: ['source']
                        },
                        {
                            location: {
                                physicalLocation: {
                                    artifactLocation: { uri: finding.filePath },
                                    region: {
                                        startLine: finding.location.startLine,
                                        startColumn: finding.location.startColumn
                                    }
                                },
                                message: { text: 'Taint sink' }
                            },
                            kinds: ['sink']
                        }
                    ]
                }]
            }];
        }

        return sarifResult;
    });

    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'security-scan-mcp',
                    version: '1.0.0',
                    informationUri: 'https://github.com/chrischabot/security-scan-mcp',
                    rules
                }
            },
            results,
            invocations: [{
                executionSuccessful: result.errors.length === 0,
                startTimeUtc: result.startTime.toISOString(),
                endTimeUtc: result.endTime.toISOString()
            }]
        }]
    };
}

/**
 * Export scan results as SARIF JSON string
 */
export function toSarifString(result: ScanResult, baseUri?: string): string {
    return JSON.stringify(toSarif(result, baseUri), null, 2);
}
