/**
 * NVD API 2.0 Client
 * Fetches CVE data with proper rate limiting and pagination
 */

import { CVERecord } from '../db/database.js';

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// Rate limits: 5 requests per 30 seconds without API key, 50 with key
const RATE_LIMIT_DELAY_NO_KEY = 6000;  // 6 seconds between requests
const RATE_LIMIT_DELAY_WITH_KEY = 600; // 0.6 seconds between requests
const MAX_DATE_RANGE_DAYS = 120;
const DEFAULT_RESULTS_PER_PAGE = 2000;

export interface NVDClientOptions {
    apiKey?: string;
    rateLimitDelay?: number;
}

export interface NVDQueryParams {
    cvssV3Severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    cweId?: string;
    pubStartDate?: Date;
    pubEndDate?: Date;
    lastModStartDate?: Date;
    lastModEndDate?: Date;
    keywordSearch?: string;
    startIndex?: number;
    resultsPerPage?: number;
}

interface NVDResponse {
    resultsPerPage: number;
    startIndex: number;
    totalResults: number;
    format: string;
    version: string;
    timestamp: string;
    vulnerabilities: NVDVulnerability[];
}

interface NVDVulnerability {
    cve: {
        id: string;
        sourceIdentifier: string;
        published: string;
        lastModified: string;
        vulnStatus: string;
        descriptions: Array<{ lang: string; value: string }>;
        metrics?: {
            cvssMetricV31?: Array<{
                cvssData: {
                    version: string;
                    vectorString: string;
                    baseScore: number;
                    baseSeverity: string;
                };
            }>;
            cvssMetricV2?: Array<{
                cvssData: {
                    version: string;
                    vectorString: string;
                    baseScore: number;
                };
                baseSeverity: string;
            }>;
        };
        weaknesses?: Array<{
            source: string;
            type: string;
            description: Array<{ lang: string; value: string }>;
        }>;
        configurations?: Array<{
            nodes: Array<{
                cpeMatch: Array<{
                    vulnerable: boolean;
                    criteria: string;
                    versionStartIncluding?: string;
                    versionStartExcluding?: string;
                    versionEndIncluding?: string;
                    versionEndExcluding?: string;
                }>;
            }>;
        }>;
    };
}

export interface ParsedCVE {
    cve: CVERecord;
    cweIds: number[];
    affectedProducts: Array<{
        vendor?: string;
        product?: string;
        versionStart?: string;
        versionStartType?: string;
        versionEnd?: string;
        versionEndType?: string;
        cpeUri: string;
    }>;
}

export class NVDClient {
    private apiKey?: string;
    private rateLimitDelay: number;
    private lastRequestTime = 0;

    constructor(options: NVDClientOptions = {}) {
        this.apiKey = options.apiKey || process.env.NVD_API_KEY;
        this.rateLimitDelay = options.rateLimitDelay ||
            (this.apiKey ? RATE_LIMIT_DELAY_WITH_KEY : RATE_LIMIT_DELAY_NO_KEY);
    }

    private async waitForRateLimit(): Promise<void> {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        if (timeSinceLastRequest < this.rateLimitDelay) {
            await this.sleep(this.rateLimitDelay - timeSinceLastRequest);
        }
        this.lastRequestTime = Date.now();
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private formatDate(date: Date): string {
        return date.toISOString().replace('Z', '');
    }

    private buildUrl(params: NVDQueryParams): string {
        const url = new URL(NVD_API_BASE);

        if (params.cvssV3Severity) {
            url.searchParams.set('cvssV3Severity', params.cvssV3Severity);
        }
        if (params.cweId) {
            url.searchParams.set('cweId', params.cweId);
        }
        if (params.pubStartDate) {
            url.searchParams.set('pubStartDate', this.formatDate(params.pubStartDate));
        }
        if (params.pubEndDate) {
            url.searchParams.set('pubEndDate', this.formatDate(params.pubEndDate));
        }
        if (params.lastModStartDate) {
            url.searchParams.set('lastModStartDate', this.formatDate(params.lastModStartDate));
        }
        if (params.lastModEndDate) {
            url.searchParams.set('lastModEndDate', this.formatDate(params.lastModEndDate));
        }
        if (params.keywordSearch) {
            url.searchParams.set('keywordSearch', params.keywordSearch);
        }
        if (params.startIndex !== undefined) {
            url.searchParams.set('startIndex', params.startIndex.toString());
        }
        if (params.resultsPerPage) {
            url.searchParams.set('resultsPerPage', params.resultsPerPage.toString());
        }

        return url.toString();
    }

    private async fetchWithRetry(url: string, retries = 3): Promise<NVDResponse> {
        const headers: Record<string, string> = {
            'Accept': 'application/json'
        };
        if (this.apiKey) {
            headers['apiKey'] = this.apiKey;
        }

        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                await this.waitForRateLimit();

                const response = await fetch(url, { headers });

                if (response.status === 429) {
                    // Rate limited, wait longer
                    const retryAfter = parseInt(response.headers.get('Retry-After') || '30', 10);
                    console.warn(`Rate limited, waiting ${retryAfter} seconds...`);
                    await this.sleep(retryAfter * 1000);
                    continue;
                }

                if (!response.ok) {
                    throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
                }

                return await response.json() as NVDResponse;
            } catch (error) {
                if (attempt === retries) {
                    throw error;
                }
                const backoffTime = Math.pow(2, attempt) * 1000;
                console.warn(`Request failed, retrying in ${backoffTime}ms...`, error);
                await this.sleep(backoffTime);
            }
        }

        throw new Error('Max retries exceeded');
    }

    private parseCVE(vuln: NVDVulnerability): ParsedCVE {
        const cve = vuln.cve;

        // Get English description
        const description = cve.descriptions.find(d => d.lang === 'en')?.value ||
            cve.descriptions[0]?.value || '';

        // Parse CVSS v3.1 metrics
        const cvssV31 = cve.metrics?.cvssMetricV31?.[0];
        const cvssV2 = cve.metrics?.cvssMetricV2?.[0];

        // Extract CWE IDs
        const cweIds: number[] = [];
        if (cve.weaknesses) {
            for (const weakness of cve.weaknesses) {
                for (const desc of weakness.description) {
                    const match = desc.value.match(/CWE-(\d+)/);
                    if (match) {
                        cweIds.push(parseInt(match[1], 10));
                    }
                }
            }
        }

        // Extract affected products from CPE configurations
        const affectedProducts: ParsedCVE['affectedProducts'] = [];
        if (cve.configurations) {
            for (const config of cve.configurations) {
                for (const node of config.nodes) {
                    for (const cpeMatch of node.cpeMatch) {
                        if (cpeMatch.vulnerable) {
                            const cpeParts = cpeMatch.criteria.split(':');
                            affectedProducts.push({
                                vendor: cpeParts[3] !== '*' ? cpeParts[3] : undefined,
                                product: cpeParts[4] !== '*' ? cpeParts[4] : undefined,
                                versionStart: cpeMatch.versionStartIncluding || cpeMatch.versionStartExcluding,
                                versionStartType: cpeMatch.versionStartIncluding ? 'including' : (cpeMatch.versionStartExcluding ? 'excluding' : undefined),
                                versionEnd: cpeMatch.versionEndIncluding || cpeMatch.versionEndExcluding,
                                versionEndType: cpeMatch.versionEndIncluding ? 'including' : (cpeMatch.versionEndExcluding ? 'excluding' : undefined),
                                cpeUri: cpeMatch.criteria
                            });
                        }
                    }
                }
            }
        }

        return {
            cve: {
                cve_id: cve.id,
                published_date: cve.published,
                modified_date: cve.lastModified,
                description,
                cvss_v3_score: cvssV31?.cvssData.baseScore || null,
                cvss_v3_severity: (cvssV31?.cvssData.baseSeverity as CVERecord['cvss_v3_severity']) || null,
                cvss_v3_vector: cvssV31?.cvssData.vectorString || null,
                cvss_v2_score: cvssV2?.cvssData.baseScore || null,
                cvss_v2_severity: cvssV2?.baseSeverity || null,
                source_identifier: cve.sourceIdentifier || null,
                vuln_status: cve.vulnStatus || null
            },
            cweIds,
            affectedProducts
        };
    }

    /**
     * Query CVEs with pagination handling
     */
    async *queryCVEs(params: NVDQueryParams): AsyncGenerator<ParsedCVE> {
        let startIndex = params.startIndex || 0;
        const resultsPerPage = params.resultsPerPage || DEFAULT_RESULTS_PER_PAGE;
        let totalResults = Infinity;

        while (startIndex < totalResults) {
            const url = this.buildUrl({
                ...params,
                startIndex,
                resultsPerPage
            });

            console.log(`Fetching CVEs from index ${startIndex}...`);
            const response = await this.fetchWithRetry(url);

            totalResults = response.totalResults;
            console.log(`Total results: ${totalResults}, fetched: ${response.vulnerabilities.length}`);

            for (const vuln of response.vulnerabilities) {
                yield this.parseCVE(vuln);
            }

            startIndex += response.resultsPerPage;
        }
    }

    /**
     * Fetch CVEs in date chunks (NVD has 120-day max range)
     */
    async *fetchCVEsByDateRange(
        startDate: Date,
        endDate: Date,
        severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    ): AsyncGenerator<ParsedCVE> {
        const chunkSize = MAX_DATE_RANGE_DAYS * 24 * 60 * 60 * 1000; // 120 days in ms

        let currentStart = new Date(startDate);

        while (currentStart < endDate) {
            const currentEnd = new Date(Math.min(
                currentStart.getTime() + chunkSize,
                endDate.getTime()
            ));

            console.log(`Fetching CVEs from ${currentStart.toISOString()} to ${currentEnd.toISOString()}`);

            const params: NVDQueryParams = {
                pubStartDate: currentStart,
                pubEndDate: currentEnd
            };

            if (severity) {
                params.cvssV3Severity = severity;
            }

            yield* this.queryCVEs(params);

            currentStart = new Date(currentEnd.getTime() + 1);
        }
    }

    /**
     * Fetch recently modified CVEs (for incremental updates)
     */
    async *fetchModifiedCVEs(
        since: Date,
        until?: Date
    ): AsyncGenerator<ParsedCVE> {
        yield* this.queryCVEs({
            lastModStartDate: since,
            lastModEndDate: until || new Date()
        });
    }

    /**
     * Fetch CVEs by specific CWE
     */
    async *fetchCVEsByCWE(
        cweId: number,
        severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    ): AsyncGenerator<ParsedCVE> {
        const params: NVDQueryParams = {
            cweId: `CWE-${cweId}`
        };

        if (severity) {
            params.cvssV3Severity = severity;
        }

        yield* this.queryCVEs(params);
    }

    /**
     * Search CVEs by keyword
     */
    async *searchCVEs(keyword: string): AsyncGenerator<ParsedCVE> {
        yield* this.queryCVEs({ keywordSearch: keyword });
    }
}

// Export factory function
export function createNVDClient(options?: NVDClientOptions): NVDClient {
    return new NVDClient(options);
}
