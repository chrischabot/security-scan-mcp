/**
 * CWE Taxonomy System
 * Provides hierarchical organization of Common Weakness Enumeration
 */

import { CWERecord } from '../db/database.js';

export type CWEAbstraction = 'Pillar' | 'Class' | 'Base' | 'Variant' | 'Compound';
export type AppType = 'web' | 'api' | 'cli' | 'desktop' | 'mobile' | 'library' | 'general';

export interface CWEEntry extends CWERecord {
    dangerScore?: number;
    exploitLikelihood?: 'High' | 'Medium' | 'Low';
    technicalImpact?: string;
    relatedCWEs?: number[];
    applicableAppTypes?: AppType[];
}

/**
 * CWE Top 25 Most Dangerous Software Weaknesses (2024)
 * Based on frequency of occurrence and severity of exploitation
 */
export const CWE_TOP_25: CWEEntry[] = [
    {
        cwe_id: 79,
        name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
        description: 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.',
        abstraction: 'Base',
        parent_cwe_id: 74,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 56.92,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute unauthorized code or commands, read application data',
        applicableAppTypes: ['web', 'api']
    },
    {
        cwe_id: 787,
        name: 'Out-of-bounds Write',
        description: 'The software writes data past the end, or before the beginning, of the intended buffer.',
        abstraction: 'Base',
        parent_cwe_id: 119,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 45.20,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute unauthorized code, modify memory, DoS',
        applicableAppTypes: ['desktop', 'cli', 'library']
    },
    {
        cwe_id: 89,
        name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
        description: 'The software constructs all or part of an SQL command using externally-influenced input.',
        abstraction: 'Base',
        parent_cwe_id: 74,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 35.88,
        exploitLikelihood: 'High',
        technicalImpact: 'Read/modify/delete database content, execute admin operations',
        applicableAppTypes: ['web', 'api', 'desktop']
    },
    {
        cwe_id: 352,
        name: 'Cross-Site Request Forgery (CSRF)',
        description: 'The web application does not verify that a request was intentionally made by the user.',
        abstraction: 'Compound',
        parent_cwe_id: 345,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 19.57,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Modify application data, gain privileges',
        applicableAppTypes: ['web']
    },
    {
        cwe_id: 78,
        name: 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)',
        description: 'The software constructs all or part of an OS command using externally-influenced input.',
        abstraction: 'Base',
        parent_cwe_id: 74,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 18.69,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute arbitrary commands on the host',
        applicableAppTypes: ['web', 'api', 'cli', 'desktop']
    },
    {
        cwe_id: 22,
        name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
        description: 'The software uses external input to construct a pathname but does not properly neutralize sequences.',
        abstraction: 'Base',
        parent_cwe_id: 706,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 16.44,
        exploitLikelihood: 'High',
        technicalImpact: 'Read/write arbitrary files',
        applicableAppTypes: ['web', 'api', 'cli', 'desktop']
    },
    {
        cwe_id: 125,
        name: 'Out-of-bounds Read',
        description: 'The software reads data past the end, or before the beginning, of the intended buffer.',
        abstraction: 'Base',
        parent_cwe_id: 119,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 15.50,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Read sensitive memory, crash application',
        applicableAppTypes: ['desktop', 'cli', 'library']
    },
    {
        cwe_id: 20,
        name: 'Improper Input Validation',
        description: 'The product does not validate or incorrectly validates input.',
        abstraction: 'Class',
        parent_cwe_id: 707,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 13.61,
        exploitLikelihood: 'High',
        technicalImpact: 'Various - depends on how input is used',
        applicableAppTypes: ['web', 'api', 'cli', 'desktop', 'mobile', 'library', 'general']
    },
    {
        cwe_id: 416,
        name: 'Use After Free',
        description: 'Referencing memory after it has been freed can cause a program to crash or execute code.',
        abstraction: 'Variant',
        parent_cwe_id: 825,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 12.92,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute arbitrary code, crash application',
        applicableAppTypes: ['desktop', 'cli', 'library']
    },
    {
        cwe_id: 862,
        name: 'Missing Authorization',
        description: 'The software does not perform an authorization check when an actor attempts to access a resource.',
        abstraction: 'Class',
        parent_cwe_id: 285,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 12.24,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Access unauthorized functionality or data',
        applicableAppTypes: ['web', 'api', 'desktop', 'mobile']
    },
    {
        cwe_id: 476,
        name: 'NULL Pointer Dereference',
        description: 'A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid.',
        abstraction: 'Base',
        parent_cwe_id: 710,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 11.68,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Crash, DoS',
        applicableAppTypes: ['desktop', 'cli', 'library']
    },
    {
        cwe_id: 287,
        name: 'Improper Authentication',
        description: 'The software does not prove that an actor is who it claims to be.',
        abstraction: 'Class',
        parent_cwe_id: 284,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 10.37,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Gain unauthorized access',
        applicableAppTypes: ['web', 'api', 'desktop', 'mobile']
    },
    {
        cwe_id: 190,
        name: 'Integer Overflow or Wraparound',
        description: 'The software performs a calculation that can produce an integer overflow or wraparound.',
        abstraction: 'Base',
        parent_cwe_id: 682,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 9.53,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Execute arbitrary code, crash',
        applicableAppTypes: ['desktop', 'cli', 'library']
    },
    {
        cwe_id: 502,
        name: 'Deserialization of Untrusted Data',
        description: 'The application deserializes untrusted data without sufficiently verifying validity.',
        abstraction: 'Base',
        parent_cwe_id: 913,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 9.52,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute arbitrary code, bypass security controls',
        applicableAppTypes: ['web', 'api', 'desktop']
    },
    {
        cwe_id: 77,
        name: 'Improper Neutralization of Special Elements used in a Command (Command Injection)',
        description: 'The software constructs a command using externally-influenced input.',
        abstraction: 'Class',
        parent_cwe_id: 74,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 9.11,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute arbitrary commands',
        applicableAppTypes: ['web', 'api', 'cli', 'desktop']
    },
    {
        cwe_id: 119,
        name: 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
        description: 'The software performs operations on a buffer but can read/write outside intended boundaries.',
        abstraction: 'Class',
        parent_cwe_id: 118,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 8.52,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute code, read/modify memory',
        applicableAppTypes: ['desktop', 'cli', 'library']
    },
    {
        cwe_id: 798,
        name: 'Use of Hard-coded Credentials',
        description: 'The software contains hard-coded credentials for authentication.',
        abstraction: 'Base',
        parent_cwe_id: 344,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 8.17,
        exploitLikelihood: 'High',
        technicalImpact: 'Gain unauthorized access',
        applicableAppTypes: ['web', 'api', 'cli', 'desktop', 'mobile', 'library', 'general']
    },
    {
        cwe_id: 306,
        name: 'Missing Authentication for Critical Function',
        description: 'The software does not perform authentication for functionality requiring identity.',
        abstraction: 'Base',
        parent_cwe_id: 287,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 7.93,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Access critical functionality',
        applicableAppTypes: ['web', 'api']
    },
    {
        cwe_id: 269,
        name: 'Improper Privilege Management',
        description: 'The software does not properly manage privileges, allowing unintended access.',
        abstraction: 'Class',
        parent_cwe_id: 284,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 7.14,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Gain elevated privileges',
        applicableAppTypes: ['web', 'api', 'cli', 'desktop']
    },
    {
        cwe_id: 94,
        name: 'Improper Control of Generation of Code (Code Injection)',
        description: 'The software constructs code segments using externally-influenced input.',
        abstraction: 'Class',
        parent_cwe_id: 74,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 6.91,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute arbitrary code',
        applicableAppTypes: ['web', 'api', 'desktop']
    },
    {
        cwe_id: 863,
        name: 'Incorrect Authorization',
        description: 'The software performs an authorization check but does not correctly verify authorization.',
        abstraction: 'Class',
        parent_cwe_id: 285,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 6.82,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Access unauthorized resources',
        applicableAppTypes: ['web', 'api', 'desktop', 'mobile']
    },
    {
        cwe_id: 434,
        name: 'Unrestricted Upload of File with Dangerous Type',
        description: 'The software allows upload of dangerous file types that can be processed by the server.',
        abstraction: 'Base',
        parent_cwe_id: 669,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 6.56,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute arbitrary code on server',
        applicableAppTypes: ['web', 'api']
    },
    {
        cwe_id: 639,
        name: 'Authorization Bypass Through User-Controlled Key (IDOR/BOLA)',
        description: 'The system uses user-controlled key to access resources but does not verify ownership.',
        abstraction: 'Base',
        parent_cwe_id: 284,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 6.40,
        exploitLikelihood: 'High',
        technicalImpact: 'Access other users data',
        applicableAppTypes: ['web', 'api']
    },
    {
        cwe_id: 918,
        name: 'Server-Side Request Forgery (SSRF)',
        description: 'The server receives a URL and makes a request without validating the destination.',
        abstraction: 'Base',
        parent_cwe_id: 441,
        status: 'Stable',
        likelihood_of_exploit: 'Medium',
        dangerScore: 6.27,
        exploitLikelihood: 'Medium',
        technicalImpact: 'Access internal resources, data exfiltration',
        applicableAppTypes: ['web', 'api']
    },
    {
        cwe_id: 88,
        name: 'Improper Neutralization of Argument Delimiters in a Command (Argument Injection)',
        description: 'The software constructs a string for a command but does not neutralize delimiters.',
        abstraction: 'Base',
        parent_cwe_id: 77,
        status: 'Stable',
        likelihood_of_exploit: 'High',
        dangerScore: 6.13,
        exploitLikelihood: 'High',
        technicalImpact: 'Execute unintended commands',
        applicableAppTypes: ['cli', 'desktop']
    }
];

/**
 * Parent CWEs (Pillars and Classes) for hierarchical organization
 */
export const CWE_HIERARCHY: CWEEntry[] = [
    // Pillars
    {
        cwe_id: 707,
        name: 'Improper Neutralization',
        description: 'The software does not neutralize or incorrectly neutralizes input before output.',
        abstraction: 'Pillar',
        parent_cwe_id: null,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 664,
        name: 'Improper Control of a Resource Through its Lifetime',
        description: 'The software does not maintain or incorrectly maintains control over a resource.',
        abstraction: 'Pillar',
        parent_cwe_id: null,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 682,
        name: 'Incorrect Calculation',
        description: 'The software performs a calculation that generates incorrect results.',
        abstraction: 'Pillar',
        parent_cwe_id: null,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 284,
        name: 'Improper Access Control',
        description: 'The software does not restrict access to resources properly.',
        abstraction: 'Pillar',
        parent_cwe_id: null,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    // Classes
    {
        cwe_id: 74,
        name: 'Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)',
        description: 'The software constructs output using input but does not neutralize special elements.',
        abstraction: 'Class',
        parent_cwe_id: 707,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 118,
        name: 'Incorrect Access of Indexable Resource (Range Error)',
        description: 'The software does not properly restrict access to an indexable resource.',
        abstraction: 'Class',
        parent_cwe_id: 664,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 285,
        name: 'Improper Authorization',
        description: 'The software does not perform or incorrectly performs authorization.',
        abstraction: 'Class',
        parent_cwe_id: 284,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 706,
        name: 'Use of Incorrectly-Resolved Name or Reference',
        description: 'The software uses a name or reference to access a resource but does not validate.',
        abstraction: 'Class',
        parent_cwe_id: 664,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 710,
        name: 'Improper Adherence to Coding Standards',
        description: 'The software does not follow certain coding rules for development.',
        abstraction: 'Class',
        parent_cwe_id: null,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 825,
        name: 'Expired Pointer Dereference',
        description: 'The program dereferences a pointer that contains a location for memory that was previously valid.',
        abstraction: 'Base',
        parent_cwe_id: 119,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 913,
        name: 'Improper Control of Dynamically-Managed Code Resources',
        description: 'The software does not properly control dynamically-managed code resources.',
        abstraction: 'Class',
        parent_cwe_id: 664,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 344,
        name: 'Use of Invariant Value in Dynamically Changing Context',
        description: 'The software uses a value that should be constant but changes over time.',
        abstraction: 'Base',
        parent_cwe_id: 330,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 345,
        name: 'Insufficient Verification of Data Authenticity',
        description: 'The software does not sufficiently verify the origin or authenticity of data.',
        abstraction: 'Class',
        parent_cwe_id: 693,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 669,
        name: 'Incorrect Resource Transfer Between Spheres',
        description: 'The software does not properly transfer a resource to another sphere.',
        abstraction: 'Class',
        parent_cwe_id: 664,
        status: 'Stable',
        likelihood_of_exploit: null
    },
    {
        cwe_id: 441,
        name: 'Unintended Proxy or Intermediary (Confused Deputy)',
        description: 'The software receives a request and performs the request on behalf of the sender.',
        abstraction: 'Class',
        parent_cwe_id: 610,
        status: 'Stable',
        likelihood_of_exploit: null
    }
];

/**
 * Get relevant CWEs for a specific application type
 */
export function getCWEsForAppType(appType: AppType): CWEEntry[] {
    return CWE_TOP_25.filter(cwe =>
        cwe.applicableAppTypes?.includes(appType) ||
        cwe.applicableAppTypes?.includes('general')
    );
}

/**
 * Get CWEs by abstraction level
 */
export function getCWEsByAbstraction(abstraction: CWEAbstraction): CWEEntry[] {
    return [...CWE_TOP_25, ...CWE_HIERARCHY].filter(cwe => cwe.abstraction === abstraction);
}

/**
 * Get parent CWE chain for a given CWE
 */
export function getCWEAncestors(cweId: number): CWEEntry[] {
    const allCWEs = [...CWE_TOP_25, ...CWE_HIERARCHY];
    const ancestors: CWEEntry[] = [];

    let current = allCWEs.find(c => c.cwe_id === cweId);
    while (current?.parent_cwe_id) {
        const parent = allCWEs.find(c => c.cwe_id === current!.parent_cwe_id);
        if (parent) {
            ancestors.push(parent);
            current = parent;
        } else {
            break;
        }
    }

    return ancestors;
}

/**
 * Get child CWEs for a given parent
 */
export function getCWEChildren(parentCweId: number): CWEEntry[] {
    return [...CWE_TOP_25, ...CWE_HIERARCHY].filter(cwe => cwe.parent_cwe_id === parentCweId);
}

/**
 * Get CWE by ID
 */
export function getCWE(cweId: number): CWEEntry | undefined {
    return [...CWE_TOP_25, ...CWE_HIERARCHY].find(cwe => cwe.cwe_id === cweId);
}

/**
 * Get all CWEs sorted by danger score
 */
export function getCWEsSortedByDanger(): CWEEntry[] {
    return [...CWE_TOP_25].sort((a, b) => (b.dangerScore || 0) - (a.dangerScore || 0));
}

/**
 * Language-specific dangerous patterns mapped to CWEs
 */
export const LANGUAGE_CWE_PATTERNS: Record<string, number[]> = {
    javascript: [79, 89, 78, 94, 22, 502, 918, 798],
    typescript: [79, 89, 78, 94, 22, 502, 918, 798],
    python: [89, 78, 94, 22, 502, 918, 798, 20],
    go: [89, 78, 22, 798, 20, 190],
    rust: [787, 125, 416, 476, 190, 119]
};

/**
 * Get priority CWEs for a language
 */
export function getPriorityCWEsForLanguage(language: string): CWEEntry[] {
    const cweIds = LANGUAGE_CWE_PATTERNS[language.toLowerCase()] || [];
    return cweIds.map(id => getCWE(id)).filter((cwe): cwe is CWEEntry => cwe !== undefined);
}
