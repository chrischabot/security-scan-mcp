/**
 * LLM Security Prompts Generator
 *
 * Generates natural language security analysis prompts from CVE/CWE data.
 * These prompts enable LLMs to perform flexible, semantic security analysis
 * that goes beyond rigid pattern matching.
 */

import { getDatabase } from '../db/database.js';
import { getCWE, CWE_TOP_25 } from '../cwe/taxonomy.js';

/**
 * Security check prompt for LLM-based analysis
 */
export interface SecurityCheckPrompt {
    id: string;
    category: string;
    cweId: number;
    cweName: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

    /** Natural language description of what to look for */
    checkDescription: string;

    /** Specific things the LLM should examine */
    lookFor: string[];

    /** Examples of vulnerable patterns (from real CVEs) */
    vulnerablePatterns: string[];

    /** What secure code should look like */
    securePatterns: string[];

    /** Edge cases and subtle issues to consider */
    edgeCases: string[];

    /** Questions the LLM should ask about the code */
    analysisQuestions: string[];

    /** Real-world CVE examples for context */
    realWorldExamples: Array<{
        cveId: string;
        description: string;
    }>;
}

/**
 * Category groupings for vulnerability types
 */
const VULNERABILITY_CATEGORIES: Record<string, {
    name: string;
    cweIds: number[];
    description: string;
}> = {
    'injection': {
        name: 'Injection Vulnerabilities',
        cweIds: [89, 78, 77, 94, 917],
        description: 'Vulnerabilities where untrusted data is sent to an interpreter as part of a command or query'
    },
    'xss': {
        name: 'Cross-Site Scripting (XSS)',
        cweIds: [79],
        description: 'Vulnerabilities where untrusted data is included in web pages without proper validation or escaping'
    },
    'authentication': {
        name: 'Authentication & Session Issues',
        cweIds: [287, 384, 306, 798],
        description: 'Weaknesses in authentication mechanisms, session management, or credential handling'
    },
    'access-control': {
        name: 'Access Control & Authorization',
        cweIds: [862, 863, 22, 434],
        description: 'Issues with permission checks, path traversal, and unauthorized access'
    },
    'cryptography': {
        name: 'Cryptographic Issues',
        cweIds: [327, 328, 330, 916],
        description: 'Weak cryptographic algorithms, improper key management, or insufficient randomness'
    },
    'data-exposure': {
        name: 'Sensitive Data Exposure',
        cweIds: [200, 312, 319, 532],
        description: 'Unintended exposure of sensitive information through logs, errors, or insecure transmission'
    },
    'deserialization': {
        name: 'Deserialization & Type Safety',
        cweIds: [502, 915],
        description: 'Unsafe deserialization of untrusted data or mass assignment vulnerabilities'
    },
    'ssrf-xxe': {
        name: 'SSRF & XML External Entities',
        cweIds: [918, 611],
        description: 'Server-side request forgery and XML external entity injection'
    }
};

/**
 * Generate detailed check instructions for a CWE
 */
function generateCheckInstructions(cweId: number): {
    lookFor: string[];
    securePatterns: string[];
    edgeCases: string[];
    analysisQuestions: string[];
} {
    const instructions: Record<number, {
        lookFor: string[];
        securePatterns: string[];
        edgeCases: string[];
        analysisQuestions: string[];
    }> = {
        // SQL Injection
        89: {
            lookFor: [
                'String concatenation or template literals used to build SQL queries',
                'User input directly embedded in SQL strings',
                'Dynamic table or column names from user input',
                'ORDER BY or LIMIT clauses with user-controlled values',
                'Raw SQL queries in ORM frameworks (e.g., raw(), execute())',
                'Stored procedures called with unsanitized parameters'
            ],
            securePatterns: [
                'Parameterized queries with placeholders (?, $1, :param)',
                'ORM query builders with bound parameters',
                'Prepared statements',
                'Input validation with allowlists for dynamic identifiers'
            ],
            edgeCases: [
                'LIKE clauses need special escaping for % and _ characters',
                'IN clauses with dynamic number of parameters',
                'JSON/JSONB queries in PostgreSQL',
                'Full-text search queries',
                'Second-order injection through stored data'
            ],
            analysisQuestions: [
                'Is any user input used in SQL query construction?',
                'Are all query parameters properly bound/escaped?',
                'Could an attacker control table/column names?',
                'Is there any string interpolation in database queries?'
            ]
        },

        // Command Injection
        78: {
            lookFor: [
                'exec(), system(), popen(), spawn() with shell=true',
                'Backtick or $() command substitution with user input',
                'User input in command arguments without proper escaping',
                'Shell metacharacters in user-controlled strings',
                'Environment variables set from user input'
            ],
            securePatterns: [
                'execFile() or spawn() with argument arrays (no shell)',
                'Allowlist validation of command arguments',
                'Using library functions instead of shell commands',
                'Proper escaping with shell-quote or similar'
            ],
            edgeCases: [
                'Argument injection even without shell (e.g., git commands)',
                'Path arguments with spaces or special characters',
                'Environment variable injection',
                'Indirect command execution through interpreters'
            ],
            analysisQuestions: [
                'Is shell=true or equivalent being used?',
                'Could user input appear in any command string?',
                'Are command arguments properly isolated?',
                'Could special characters in filenames cause issues?'
            ]
        },

        // XSS
        79: {
            lookFor: [
                'innerHTML, outerHTML, document.write() with user data',
                'dangerouslySetInnerHTML in React without sanitization',
                'Template engines with autoescape disabled',
                'JavaScript event handlers with user-controlled values',
                'URL parameters reflected in page content',
                'User input in script tags or style attributes'
            ],
            securePatterns: [
                'textContent instead of innerHTML',
                'DOMPurify or similar sanitization libraries',
                'Template engines with autoescaping enabled',
                'Content Security Policy headers',
                'Encoding output based on context (HTML, JS, URL, CSS)'
            ],
            edgeCases: [
                'DOM clobbering through id/name attributes',
                'Mutation XSS through sanitizer bypasses',
                'SVG and MathML injection',
                'JavaScript URLs in href/src attributes',
                'CSS injection leading to data exfiltration'
            ],
            analysisQuestions: [
                'Is any user input rendered as HTML?',
                'Are all outputs properly encoded for their context?',
                'Could user data appear in JavaScript code?',
                'Is Content Security Policy properly configured?'
            ]
        },

        // Path Traversal
        22: {
            lookFor: [
                'File paths constructed with user input',
                '../ or ..\\\ sequences in path handling',
                'Absolute paths from user input',
                'Archive extraction without path validation',
                'Symbolic link following in sensitive directories'
            ],
            securePatterns: [
                'path.resolve() with base directory validation',
                'Canonicalization before comparison',
                'Allowlist of permitted files/directories',
                'Chroot or sandbox for file operations'
            ],
            edgeCases: [
                'URL-encoded path traversal (%2e%2e%2f)',
                'Unicode normalization attacks',
                'Null byte injection in some languages',
                'Case sensitivity differences across filesystems',
                'Windows-specific paths (C:, UNC paths)'
            ],
            analysisQuestions: [
                'Can user input influence file paths?',
                'Is the final path validated against a base directory?',
                'Are symbolic links properly handled?',
                'Could encoded characters bypass validation?'
            ]
        },

        // Hardcoded Credentials
        798: {
            lookFor: [
                'API keys, tokens, or passwords in source code',
                'Connection strings with embedded credentials',
                'Private keys or certificates in code',
                'Default passwords that are not changed',
                'Credentials in configuration files committed to VCS',
                'High-entropy strings that look like secrets'
            ],
            securePatterns: [
                'Environment variables for secrets',
                'Secret management services (Vault, AWS Secrets Manager)',
                'Configuration files excluded from version control',
                'Key rotation and revocation procedures'
            ],
            edgeCases: [
                'Test credentials that work in production',
                'Credentials in error messages or logs',
                'Encoded or obfuscated (but not encrypted) secrets',
                'Secrets in client-side code/mobile apps',
                'Backup files containing credentials'
            ],
            analysisQuestions: [
                'Are there any string literals that look like secrets?',
                'Are configuration values loaded from environment?',
                'Could any test credentials work in production?',
                'Are secrets properly excluded from version control?'
            ]
        },

        // Insecure Deserialization
        502: {
            lookFor: [
                'pickle.loads(), yaml.load(), unserialize() with user data',
                'JSON.parse() of untrusted data with prototype access',
                'Java ObjectInputStream with untrusted input',
                'XML deserialization without type restrictions',
                'Custom deserializers that instantiate arbitrary classes'
            ],
            securePatterns: [
                'JSON with strict parsing (no prototype pollution)',
                'Allowlist of permitted types for deserialization',
                'yaml.safe_load() instead of yaml.load()',
                'Signature verification before deserialization',
                'Using data formats that don\'t allow code execution'
            ],
            edgeCases: [
                'Nested objects that trigger gadget chains',
                'Type confusion in polymorphic deserialization',
                'Prototype pollution through __proto__ or constructor',
                'Memory exhaustion through deeply nested objects'
            ],
            analysisQuestions: [
                'Is any untrusted data being deserialized?',
                'Are there restrictions on what types can be instantiated?',
                'Could deserialization trigger side effects?',
                'Is the serialization format inherently dangerous?'
            ]
        },

        // SSRF
        918: {
            lookFor: [
                'HTTP requests with user-controlled URLs',
                'URL parsing and reconstruction',
                'Webhook URLs from user input',
                'Image/file fetching from user-provided URLs',
                'DNS rebinding vulnerabilities'
            ],
            securePatterns: [
                'Allowlist of permitted domains/IPs',
                'URL parsing with strict validation',
                'Blocking requests to internal networks (10.x, 192.168.x, 127.x)',
                'Disabling redirects or validating redirect targets'
            ],
            edgeCases: [
                'IPv6 addresses bypassing IPv4 filters',
                'DNS rebinding attacks',
                'URL parser inconsistencies',
                'Redirects to internal resources',
                'Cloud metadata endpoints (169.254.169.254)'
            ],
            analysisQuestions: [
                'Can users control any part of outgoing URLs?',
                'Are internal network ranges blocked?',
                'How are redirects handled?',
                'Could URL parsing differences lead to bypasses?'
            ]
        },

        // Broken Authentication
        287: {
            lookFor: [
                'Password comparison using == instead of constant-time compare',
                'Session tokens with predictable values',
                'Missing rate limiting on authentication endpoints',
                'Credentials sent over unencrypted connections',
                'Remember me tokens without proper security'
            ],
            securePatterns: [
                'Constant-time password comparison',
                'Cryptographically secure session tokens',
                'Rate limiting and account lockout',
                'Multi-factor authentication',
                'Secure cookie attributes (HttpOnly, Secure, SameSite)'
            ],
            edgeCases: [
                'Timing attacks on authentication',
                'Session fixation vulnerabilities',
                'Password reset token reuse',
                'Concurrent session handling',
                'Authentication bypass through parameter pollution'
            ],
            analysisQuestions: [
                'Is password comparison timing-safe?',
                'How are session tokens generated?',
                'Is there protection against brute force?',
                'Are all authentication states properly validated?'
            ]
        }
    };

    return instructions[cweId] || {
        lookFor: ['Review code for security issues related to this vulnerability type'],
        securePatterns: ['Follow security best practices'],
        edgeCases: ['Consider edge cases and unusual inputs'],
        analysisQuestions: ['Is this code handling untrusted input safely?']
    };
}

/**
 * Extract relevant CVE examples for a CWE
 */
function getCVEExamples(cweId: number, limit = 3): Array<{cveId: string; description: string}> {
    const db = getDatabase();
    const cves = db.getCVEsByCWE(cweId, limit);

    return cves.map(cve => ({
        cveId: cve.cve_id,
        description: cve.description.length > 300
            ? cve.description.substring(0, 300) + '...'
            : cve.description
    }));
}

/**
 * Generate vulnerability patterns from CVE descriptions
 */
function extractVulnerablePatterns(cweId: number): string[] {
    const db = getDatabase();
    const cves = db.getCVEsByCWE(cweId, 10);

    // Extract common vulnerability patterns from CVE descriptions
    const patterns: string[] = [];
    const commonPhrases = [
        /allows? (?:remote )?attackers? to ([^.]+)/gi,
        /via (?:a |the )?([^.]+)/gi,
        /through (?:a |the )?([^.]+)/gi,
        /by (?:sending |providing |using )([^.]+)/gi
    ];

    for (const cve of cves) {
        for (const regex of commonPhrases) {
            const matches = cve.description.matchAll(regex);
            for (const match of matches) {
                const pattern = match[1].trim();
                if (pattern.length > 10 && pattern.length < 100 && !patterns.includes(pattern)) {
                    patterns.push(pattern);
                    if (patterns.length >= 5) break;
                }
            }
            if (patterns.length >= 5) break;
        }
    }

    return patterns;
}

/**
 * Generate a security check prompt for a specific CWE
 */
export function generateSecurityPrompt(cweId: number): SecurityCheckPrompt | null {
    const cwe = getCWE(cweId);
    if (!cwe) return null;

    const instructions = generateCheckInstructions(cweId);
    const cveExamples = getCVEExamples(cweId);
    const vulnerablePatterns = extractVulnerablePatterns(cweId);

    // Determine severity based on CWE danger score
    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
    const dangerScore = cwe.dangerScore ?? 5;
    if (dangerScore >= 9) severity = 'CRITICAL';
    else if (dangerScore >= 7) severity = 'HIGH';
    else if (dangerScore >= 4) severity = 'MEDIUM';
    else severity = 'LOW';

    // Find category
    let category = 'general';
    for (const [, catInfo] of Object.entries(VULNERABILITY_CATEGORIES)) {
        if (catInfo.cweIds.includes(cweId)) {
            category = catInfo.name;
            break;
        }
    }

    return {
        id: `security-check-cwe-${cweId}`,
        category,
        cweId,
        cweName: cwe.name,
        severity,
        checkDescription: cwe.description || `Check for ${cwe.name} vulnerabilities`,
        lookFor: instructions.lookFor,
        vulnerablePatterns,
        securePatterns: instructions.securePatterns,
        edgeCases: instructions.edgeCases,
        analysisQuestions: instructions.analysisQuestions,
        realWorldExamples: cveExamples
    };
}

/**
 * Generate prompts for all CWEs in a category
 */
export function getPromptsByCategory(categoryId: string): SecurityCheckPrompt[] {
    const category = VULNERABILITY_CATEGORIES[categoryId];
    if (!category) return [];

    const prompts: SecurityCheckPrompt[] = [];
    for (const cweId of category.cweIds) {
        const prompt = generateSecurityPrompt(cweId);
        if (prompt) prompts.push(prompt);
    }

    return prompts;
}

/**
 * Generate all security check prompts
 */
export function getAllSecurityPrompts(): SecurityCheckPrompt[] {
    const prompts: SecurityCheckPrompt[] = [];

    for (const cwe of CWE_TOP_25) {
        const prompt = generateSecurityPrompt(cwe.cwe_id);
        if (prompt) prompts.push(prompt);
    }

    return prompts;
}

/**
 * Get available categories
 */
export function getCategories(): Array<{id: string; name: string; description: string; cweCount: number}> {
    return Object.entries(VULNERABILITY_CATEGORIES).map(([id, info]) => ({
        id,
        name: info.name,
        description: info.description,
        cweCount: info.cweIds.length
    }));
}

/**
 * Format a security prompt as a human-readable instruction for an LLM
 */
export function formatPromptForLLM(prompt: SecurityCheckPrompt): string {
    const lines: string[] = [];

    lines.push(`## Security Check: ${prompt.cweName} (CWE-${prompt.cweId})`);
    lines.push(`**Severity:** ${prompt.severity}`);
    lines.push(`**Category:** ${prompt.category}`);
    lines.push('');
    lines.push(`### Description`);
    lines.push(prompt.checkDescription);
    lines.push('');

    lines.push(`### What to Look For`);
    for (const item of prompt.lookFor) {
        lines.push(`- ${item}`);
    }
    lines.push('');

    if (prompt.vulnerablePatterns.length > 0) {
        lines.push(`### Common Vulnerable Patterns (from real CVEs)`);
        for (const pattern of prompt.vulnerablePatterns) {
            lines.push(`- ${pattern}`);
        }
        lines.push('');
    }

    lines.push(`### Secure Alternatives`);
    for (const pattern of prompt.securePatterns) {
        lines.push(`- ${pattern}`);
    }
    lines.push('');

    lines.push(`### Edge Cases to Consider`);
    for (const edge of prompt.edgeCases) {
        lines.push(`- ${edge}`);
    }
    lines.push('');

    lines.push(`### Analysis Questions`);
    for (const question of prompt.analysisQuestions) {
        lines.push(`- ${question}`);
    }
    lines.push('');

    if (prompt.realWorldExamples.length > 0) {
        lines.push(`### Real-World Examples`);
        for (const example of prompt.realWorldExamples) {
            lines.push(`- **${example.cveId}**: ${example.description}`);
        }
    }

    return lines.join('\n');
}

/**
 * Generate a comprehensive security review prompt for code analysis
 */
export function generateCodeReviewPrompt(
    code: string,
    language: string,
    categories?: string[]
): string {
    const lines: string[] = [];

    lines.push('# Security Code Review Instructions');
    lines.push('');
    lines.push('You are performing a security code review. Analyze the following code for security vulnerabilities.');
    lines.push('');
    lines.push('## Code to Review');
    lines.push('```' + language);
    lines.push(code);
    lines.push('```');
    lines.push('');
    lines.push('## Security Checks to Perform');
    lines.push('');

    // Get relevant prompts
    let prompts: SecurityCheckPrompt[];
    if (categories && categories.length > 0) {
        prompts = categories.flatMap(cat => getPromptsByCategory(cat));
    } else {
        prompts = getAllSecurityPrompts();
    }

    // Add relevant checks based on language
    const relevantPrompts = filterPromptsByLanguage(prompts, language);

    for (const prompt of relevantPrompts) {
        lines.push(formatPromptForLLM(prompt));
        lines.push('---');
        lines.push('');
    }

    lines.push('## Response Format');
    lines.push('');
    lines.push('For each vulnerability found, provide:');
    lines.push('1. **Location**: Line number(s) and code snippet');
    lines.push('2. **Vulnerability Type**: CWE ID and name');
    lines.push('3. **Severity**: CRITICAL, HIGH, MEDIUM, or LOW');
    lines.push('4. **Description**: What the vulnerability is and why it\'s dangerous');
    lines.push('5. **Remediation**: Specific fix with code example');
    lines.push('');
    lines.push('If no vulnerabilities are found, explain what security measures are in place.');

    return lines.join('\n');
}

/**
 * Filter prompts relevant to a programming language
 */
function filterPromptsByLanguage(prompts: SecurityCheckPrompt[], language: string): SecurityCheckPrompt[] {
    // Language-specific vulnerability relevance
    const languageRelevance: Record<string, number[]> = {
        javascript: [79, 89, 78, 94, 22, 798, 502, 918, 287],
        typescript: [79, 89, 78, 94, 22, 798, 502, 918, 287],
        python: [89, 78, 94, 22, 798, 502, 918, 287],
        go: [89, 78, 22, 798, 918, 287],
        rust: [89, 78, 22, 798, 918],
        java: [89, 78, 79, 22, 798, 502, 918, 287],
        php: [89, 78, 79, 94, 22, 798, 502, 918, 287]
    };

    const relevant = languageRelevance[language.toLowerCase()];
    if (!relevant) return prompts;

    return prompts.filter(p => relevant.includes(p.cweId));
}

/**
 * Generate a focused prompt for a specific vulnerability check
 */
export function generateFocusedPrompt(cweId: number, code: string, language: string): string | null {
    const prompt = generateSecurityPrompt(cweId);
    if (!prompt) return null;

    const lines: string[] = [];

    lines.push(`# Focused Security Check: ${prompt.cweName}`);
    lines.push('');
    lines.push(`Analyze this ${language} code specifically for **${prompt.cweName}** (CWE-${cweId}) vulnerabilities.`);
    lines.push('');
    lines.push('## Code');
    lines.push('```' + language);
    lines.push(code);
    lines.push('```');
    lines.push('');
    lines.push(formatPromptForLLM(prompt));
    lines.push('');
    lines.push('## Your Analysis');
    lines.push('');
    lines.push('Provide a detailed analysis focusing specifically on this vulnerability type.');
    lines.push('Include line numbers, specific code concerns, and remediation suggestions.');

    return lines.join('\n');
}
