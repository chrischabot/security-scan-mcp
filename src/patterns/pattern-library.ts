/**
 * Security Detection Pattern Library
 * Semgrep-style patterns organized by CWE for vulnerability detection
 */

import { SupportedLanguage } from '../parser/tree-sitter-parser.js';

export type PatternType = 'ast' | 'taint' | 'regex';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

export interface SecurityPattern {
    id: string;
    name: string;
    description: string;
    cweId: number;
    severity: Severity;
    confidence: Confidence;
    languages: SupportedLanguage[];
    patternType: PatternType;

    // AST pattern using Tree-sitter query syntax
    astQuery?: string;

    // Taint mode configuration
    taintConfig?: TaintConfig;

    // Regex pattern (fallback)
    regexPattern?: string;

    // Message shown when pattern matches
    message: string;

    // Remediation guidance
    remediation: string;

    // References (URLs)
    references: string[];

    // Additional metadata
    tags?: string[];
}

export interface TaintConfig {
    sources: SourceSinkDef[];
    sinks: SourceSinkDef[];
    sanitizers?: SourceSinkDef[];
    propagators?: SourceSinkDef[];
}

export interface SourceSinkDef {
    // Tree-sitter query to match
    query?: string;
    // Simple function name match
    functionName?: string;
    // Object.method pattern
    methodPattern?: string;
    // Argument index for taint (0-based, -1 for return value)
    argIndex?: number;
}

/**
 * Complete pattern library organized by CWE
 */
export const SECURITY_PATTERNS: SecurityPattern[] = [
    // =============================================================================
    // CWE-79: Cross-Site Scripting (XSS)
    // =============================================================================
    {
        id: 'js-xss-innerhtml',
        name: 'XSS via innerHTML',
        description: 'Direct assignment to innerHTML with potentially untrusted data',
        cweId: 79,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript', 'tsx'],
        patternType: 'ast',
        astQuery: `
            (assignment_expression
                left: (member_expression
                    property: (property_identifier) @prop)
                right: (_) @value
                (#eq? @prop "innerHTML"))
        `,
        message: 'innerHTML assignment can lead to XSS if the value contains user input',
        remediation: 'Use textContent for text, or sanitize HTML with DOMPurify before assignment',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        ],
        tags: ['xss', 'dom']
    },
    {
        id: 'js-xss-document-write',
        name: 'XSS via document.write',
        description: 'Usage of document.write which can inject arbitrary HTML',
        cweId: 79,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript', 'tsx'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: (member_expression
                    object: (identifier) @obj
                    property: (property_identifier) @method)
                (#eq? @obj "document")
                (#any-of? @method "write" "writeln"))
        `,
        message: 'document.write can lead to XSS vulnerabilities',
        remediation: 'Use DOM manipulation methods like createElement and appendChild',
        references: ['https://developer.mozilla.org/en-US/docs/Web/API/Document/write'],
        tags: ['xss', 'dom', 'deprecated']
    },
    {
        id: 'js-xss-dangerously-set-html',
        name: 'XSS via React dangerouslySetInnerHTML',
        description: 'Usage of dangerouslySetInnerHTML in React components',
        cweId: 79,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript', 'tsx'],
        patternType: 'ast',
        astQuery: `
            (jsx_attribute
                (property_identifier) @attr
                (#eq? @attr "dangerouslySetInnerHTML"))
        `,
        message: 'dangerouslySetInnerHTML can lead to XSS if not properly sanitized',
        remediation: 'Sanitize the HTML content with DOMPurify before using dangerouslySetInnerHTML',
        references: ['https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'],
        tags: ['xss', 'react']
    },

    // =============================================================================
    // CWE-89: SQL Injection
    // =============================================================================
    {
        id: 'js-sqli-template-literal',
        name: 'SQL Injection via template literal',
        description: 'SQL query constructed with template literal interpolation',
        cweId: 89,
        severity: 'CRITICAL',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript'],
        patternType: 'taint',
        taintConfig: {
            sources: [
                { methodPattern: 'req.body.*' },
                { methodPattern: 'req.query.*' },
                { methodPattern: 'req.params.*' },
                { functionName: 'prompt' }
            ],
            sinks: [
                { methodPattern: '*.query', argIndex: 0 },
                { methodPattern: '*.execute', argIndex: 0 },
                { methodPattern: 'db.run', argIndex: 0 }
            ],
            sanitizers: [
                { methodPattern: '*.escape' },
                { functionName: 'escapeString' }
            ]
        },
        astQuery: `
            (call_expression
                function: (member_expression
                    property: (property_identifier) @method)
                arguments: (arguments
                    (template_string) @query)
                (#any-of? @method "query" "execute" "raw"))
        `,
        message: 'SQL query using template literals may be vulnerable to SQL injection',
        remediation: 'Use parameterized queries or prepared statements instead of string interpolation',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ],
        tags: ['sqli', 'database']
    },
    {
        id: 'py-sqli-format-string',
        name: 'SQL Injection via format string',
        description: 'SQL query constructed with f-string or format()',
        cweId: 89,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['python'],
        patternType: 'ast',
        astQuery: `
            (call
                function: (attribute
                    attribute: (identifier) @method)
                arguments: (argument_list
                    (string) @query)
                (#any-of? @method "execute" "executemany"))
        `,
        message: 'SQL query may be vulnerable to injection via string formatting',
        remediation: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        references: ['https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders'],
        tags: ['sqli', 'database', 'python']
    },
    {
        id: 'go-sqli-sprintf',
        name: 'SQL Injection via fmt.Sprintf',
        description: 'SQL query constructed with fmt.Sprintf',
        cweId: 89,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['go'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: (selector_expression
                    operand: (identifier) @pkg
                    field: (field_identifier) @method)
                (#eq? @pkg "fmt")
                (#eq? @method "Sprintf"))
        `,
        message: 'SQL query built with fmt.Sprintf is vulnerable to SQL injection',
        remediation: 'Use parameterized queries with db.Query(query, args...)',
        references: ['https://go.dev/doc/database/sql-injection'],
        tags: ['sqli', 'database', 'go']
    },

    // =============================================================================
    // CWE-78: OS Command Injection
    // =============================================================================
    {
        id: 'js-cmdi-exec',
        name: 'Command Injection via exec',
        description: 'Shell command execution with child_process.exec',
        cweId: 78,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: [
                    (identifier) @func
                    (member_expression
                        property: (property_identifier) @func)
                ]
                (#any-of? @func "exec" "execSync"))
        `,
        message: 'Using exec/execSync with user input can lead to command injection',
        remediation: 'Use execFile/spawn with argument arrays instead of shell commands',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
        ],
        tags: ['cmdi', 'shell']
    },
    {
        id: 'py-cmdi-shell-true',
        name: 'Command Injection via shell=True',
        description: 'subprocess call with shell=True',
        cweId: 78,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['python'],
        patternType: 'ast',
        astQuery: `
            (call
                function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @method)
                arguments: (argument_list
                    (keyword_argument
                        name: (identifier) @kwarg
                        value: (true)))
                (#eq? @module "subprocess")
                (#eq? @kwarg "shell"))
        `,
        message: 'subprocess with shell=True is vulnerable to command injection',
        remediation: 'Use subprocess.run with a list of arguments and shell=False',
        references: ['https://docs.python.org/3/library/subprocess.html#security-considerations'],
        tags: ['cmdi', 'shell', 'python']
    },
    {
        id: 'py-cmdi-os-system',
        name: 'Command Injection via os.system',
        description: 'Usage of os.system which is vulnerable to command injection',
        cweId: 78,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['python'],
        patternType: 'ast',
        astQuery: `
            (call
                function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @method)
                (#eq? @module "os")
                (#eq? @method "system"))
        `,
        message: 'os.system is vulnerable to command injection',
        remediation: 'Use subprocess.run with a list of arguments instead',
        references: ['https://docs.python.org/3/library/os.html#os.system'],
        tags: ['cmdi', 'shell', 'python', 'deprecated']
    },

    // =============================================================================
    // CWE-22: Path Traversal
    // =============================================================================
    {
        id: 'js-path-traversal',
        name: 'Path Traversal via user input',
        description: 'File path constructed with user input without sanitization',
        cweId: 22,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript'],
        patternType: 'taint',
        taintConfig: {
            sources: [
                { methodPattern: 'req.body.*' },
                { methodPattern: 'req.query.*' },
                { methodPattern: 'req.params.*' }
            ],
            sinks: [
                { functionName: 'readFile', argIndex: 0 },
                { functionName: 'readFileSync', argIndex: 0 },
                { functionName: 'writeFile', argIndex: 0 },
                { functionName: 'writeFileSync', argIndex: 0 },
                { methodPattern: 'fs.createReadStream', argIndex: 0 }
            ],
            sanitizers: [
                { methodPattern: 'path.basename' },
                { methodPattern: 'path.normalize' }
            ]
        },
        message: 'File path may be vulnerable to path traversal attacks',
        remediation: 'Validate and sanitize file paths, use path.basename to extract filename, check against allowed directories',
        references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'
        ],
        tags: ['path-traversal', 'file-access']
    },
    {
        id: 'py-path-traversal-open',
        name: 'Path Traversal via open()',
        description: 'File opened with user-controlled path',
        cweId: 22,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['python'],
        patternType: 'taint',
        taintConfig: {
            sources: [
                { methodPattern: 'request.args.get' },
                { methodPattern: 'request.form.get' },
                { functionName: 'input' }
            ],
            sinks: [
                { functionName: 'open', argIndex: 0 }
            ],
            sanitizers: [
                { methodPattern: 'os.path.basename' },
                { methodPattern: 'pathlib.Path.resolve' }
            ]
        },
        message: 'File path may be vulnerable to directory traversal',
        remediation: 'Use os.path.basename or validate path is within allowed directory',
        references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
        tags: ['path-traversal', 'file-access', 'python']
    },

    // =============================================================================
    // CWE-502: Deserialization of Untrusted Data
    // =============================================================================
    {
        id: 'py-deserialize-pickle',
        name: 'Unsafe Pickle Deserialization',
        description: 'Usage of pickle.loads on untrusted data',
        cweId: 502,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['python'],
        patternType: 'ast',
        astQuery: `
            (call
                function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @method)
                (#eq? @module "pickle")
                (#any-of? @method "loads" "load"))
        `,
        message: 'Pickle deserialization can lead to arbitrary code execution',
        remediation: 'Use safe serialization formats like JSON, or restrict pickle to trusted data only',
        references: ['https://docs.python.org/3/library/pickle.html#restricting-globals'],
        tags: ['deserialization', 'rce', 'python']
    },
    {
        id: 'py-deserialize-yaml',
        name: 'Unsafe YAML Loading',
        description: 'Usage of yaml.load without SafeLoader',
        cweId: 502,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['python'],
        patternType: 'ast',
        astQuery: `
            (call
                function: (attribute
                    object: (identifier) @module
                    attribute: (identifier) @method)
                (#eq? @module "yaml")
                (#eq? @method "load"))
        `,
        message: 'yaml.load without SafeLoader can execute arbitrary code',
        remediation: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)',
        references: ['https://pyyaml.org/wiki/PyYAMLDocumentation'],
        tags: ['deserialization', 'rce', 'python']
    },
    {
        id: 'js-deserialize-eval',
        name: 'Unsafe eval() usage',
        description: 'Usage of eval() to parse data',
        cweId: 502,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: (identifier) @func
                (#eq? @func "eval"))
        `,
        message: 'eval() can execute arbitrary code and should never be used with untrusted input',
        remediation: 'Use JSON.parse for JSON data, or safer alternatives like new Function() with strict validation',
        references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'],
        tags: ['deserialization', 'rce', 'eval']
    },

    // =============================================================================
    // CWE-798: Hardcoded Credentials
    // =============================================================================
    {
        id: 'generic-hardcoded-password',
        name: 'Hardcoded Password',
        description: 'Password or secret appears to be hardcoded in source',
        cweId: 798,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript', 'python', 'go', 'rust'],
        patternType: 'regex',
        regexPattern: '(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\\s*[=:]\\s*["\'][^"\']{8,}["\']',
        message: 'Potential hardcoded credential detected',
        remediation: 'Use environment variables or a secrets manager for credentials',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
        tags: ['credentials', 'secrets']
    },
    {
        id: 'js-hardcoded-jwt-secret',
        name: 'Hardcoded JWT Secret',
        description: 'JWT secret hardcoded in source code',
        cweId: 798,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: (member_expression
                    property: (property_identifier) @method)
                arguments: (arguments
                    (_)
                    (string) @secret)
                (#any-of? @method "sign" "verify"))
        `,
        message: 'JWT secret should not be hardcoded',
        remediation: 'Load JWT secrets from environment variables or secrets manager',
        references: ['https://jwt.io/introduction'],
        tags: ['credentials', 'jwt', 'secrets']
    },

    // =============================================================================
    // CWE-94: Code Injection
    // =============================================================================
    {
        id: 'js-code-injection-function',
        name: 'Code Injection via Function constructor',
        description: 'Usage of Function constructor with dynamic code',
        cweId: 94,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript'],
        patternType: 'ast',
        astQuery: `
            (new_expression
                constructor: (identifier) @constructor
                (#eq? @constructor "Function"))
        `,
        message: 'Function constructor can execute arbitrary code',
        remediation: 'Avoid dynamic code generation, use safer alternatives',
        references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function'],
        tags: ['code-injection', 'rce']
    },
    {
        id: 'py-code-injection-exec',
        name: 'Code Injection via exec/eval',
        description: 'Usage of exec() or eval() with potentially untrusted input',
        cweId: 94,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['python'],
        patternType: 'ast',
        astQuery: `
            (call
                function: (identifier) @func
                (#any-of? @func "exec" "eval" "compile"))
        `,
        message: 'exec/eval can execute arbitrary code',
        remediation: 'Avoid exec/eval, use ast.literal_eval for literal expressions',
        references: ['https://docs.python.org/3/library/functions.html#eval'],
        tags: ['code-injection', 'rce', 'python']
    },

    // =============================================================================
    // CWE-918: Server-Side Request Forgery (SSRF)
    // =============================================================================
    {
        id: 'js-ssrf-fetch',
        name: 'SSRF via fetch/axios',
        description: 'HTTP request made with user-controlled URL',
        cweId: 918,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript'],
        patternType: 'taint',
        taintConfig: {
            sources: [
                { methodPattern: 'req.body.*' },
                { methodPattern: 'req.query.*' },
                { methodPattern: 'req.params.*' }
            ],
            sinks: [
                { functionName: 'fetch', argIndex: 0 },
                { methodPattern: 'axios.get', argIndex: 0 },
                { methodPattern: 'axios.post', argIndex: 0 },
                { methodPattern: 'http.get', argIndex: 0 }
            ],
            sanitizers: [
                { functionName: 'validateUrl' },
                { methodPattern: 'URL.parse' }
            ]
        },
        message: 'HTTP request with user-controlled URL may be vulnerable to SSRF',
        remediation: 'Validate and whitelist allowed URLs/domains before making requests',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'],
        tags: ['ssrf', 'network']
    },
    {
        id: 'py-ssrf-requests',
        name: 'SSRF via requests library',
        description: 'HTTP request made with user-controlled URL',
        cweId: 918,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['python'],
        patternType: 'taint',
        taintConfig: {
            sources: [
                { methodPattern: 'request.args.get' },
                { methodPattern: 'request.form.get' }
            ],
            sinks: [
                { methodPattern: 'requests.get', argIndex: 0 },
                { methodPattern: 'requests.post', argIndex: 0 },
                { methodPattern: 'urllib.request.urlopen', argIndex: 0 }
            ]
        },
        message: 'HTTP request with user-controlled URL may be vulnerable to SSRF',
        remediation: 'Validate URLs against a whitelist of allowed domains',
        references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
        tags: ['ssrf', 'network', 'python']
    },

    // =============================================================================
    // CWE-434: Unrestricted File Upload
    // =============================================================================
    {
        id: 'js-file-upload-no-validation',
        name: 'Unrestricted File Upload',
        description: 'File upload without proper type/size validation',
        cweId: 434,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['javascript', 'typescript'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: (member_expression
                    property: (property_identifier) @method)
                (#any-of? @method "upload" "single" "array" "fields"))
        `,
        message: 'File upload should validate file type, size, and content',
        remediation: 'Validate file extensions, MIME types, and scan for malicious content',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'],
        tags: ['file-upload', 'validation']
    },

    // =============================================================================
    // CWE-287: Improper Authentication
    // =============================================================================
    {
        id: 'js-weak-password-hash',
        name: 'Weak Password Hashing',
        description: 'Usage of weak hashing algorithm for passwords',
        cweId: 287,
        severity: 'HIGH',
        confidence: 'HIGH',
        languages: ['javascript', 'typescript'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: (member_expression
                    property: (property_identifier) @method)
                arguments: (arguments
                    (string) @algo)
                (#eq? @method "createHash")
                (#any-of? @algo "\"md5\"" "\"sha1\"" "'md5'" "'sha1'"))
        `,
        message: 'MD5 and SHA1 are not suitable for password hashing',
        remediation: 'Use bcrypt, scrypt, or Argon2 for password hashing',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
        tags: ['authentication', 'crypto', 'password']
    },

    // =============================================================================
    // Rust-specific patterns
    // =============================================================================
    {
        id: 'rust-unsafe-block',
        name: 'Unsafe Code Block',
        description: 'Usage of unsafe block that bypasses Rust safety guarantees',
        cweId: 119,
        severity: 'MEDIUM',
        confidence: 'LOW',
        languages: ['rust'],
        patternType: 'ast',
        astQuery: `
            (unsafe_block) @unsafe
        `,
        message: 'Unsafe blocks require careful review as they bypass Rust memory safety guarantees',
        remediation: 'Minimize unsafe code, encapsulate it properly, and document safety invariants',
        references: ['https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html'],
        tags: ['rust', 'unsafe', 'memory-safety']
    },
    {
        id: 'rust-raw-pointer-deref',
        name: 'Raw Pointer Dereference',
        description: 'Dereferencing raw pointers which can lead to memory unsafety',
        cweId: 416,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        languages: ['rust'],
        patternType: 'ast',
        astQuery: `
            (unary_expression
                operator: "*"
                operand: (identifier) @ptr)
        `,
        message: 'Raw pointer dereference requires careful validation',
        remediation: 'Ensure pointer validity before dereferencing, prefer safe references',
        references: ['https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html#dereferencing-a-raw-pointer'],
        tags: ['rust', 'pointer', 'memory-safety']
    },

    // =============================================================================
    // Go-specific patterns
    // =============================================================================
    {
        id: 'go-cmdi-exec-command',
        name: 'Command Injection via exec.Command',
        description: 'Shell command constructed with user input',
        cweId: 78,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        languages: ['go'],
        patternType: 'ast',
        astQuery: `
            (call_expression
                function: (selector_expression
                    operand: (identifier) @pkg
                    field: (field_identifier) @method)
                arguments: (argument_list
                    (interpreted_string_literal) @cmd)
                (#eq? @pkg "exec")
                (#eq? @method "Command")
                (#match? @cmd "sh|bash|cmd"))
        `,
        message: 'exec.Command with shell invocation is vulnerable to command injection',
        remediation: 'Use exec.Command with argument list instead of shell string',
        references: ['https://pkg.go.dev/os/exec#Command'],
        tags: ['cmdi', 'shell', 'go']
    }
];

/**
 * Get patterns by CWE ID
 */
export function getPatternsByCWE(cweId: number): SecurityPattern[] {
    return SECURITY_PATTERNS.filter(p => p.cweId === cweId);
}

/**
 * Get patterns by language
 */
export function getPatternsByLanguage(language: SupportedLanguage): SecurityPattern[] {
    return SECURITY_PATTERNS.filter(p => p.languages.includes(language));
}

/**
 * Get patterns by severity
 */
export function getPatternsBySeverity(severity: Severity): SecurityPattern[] {
    return SECURITY_PATTERNS.filter(p => p.severity === severity);
}

/**
 * Get patterns by type
 */
export function getPatternsByType(patternType: PatternType): SecurityPattern[] {
    return SECURITY_PATTERNS.filter(p => p.patternType === patternType);
}

/**
 * Get pattern by ID
 */
export function getPatternById(id: string): SecurityPattern | undefined {
    return SECURITY_PATTERNS.find(p => p.id === id);
}

/**
 * Get all unique CWE IDs in the pattern library
 */
export function getAllCWEIds(): number[] {
    return [...new Set(SECURITY_PATTERNS.map(p => p.cweId))].sort((a, b) => a - b);
}

/**
 * Get patterns filtered by multiple criteria
 */
export function getPatterns(filters: {
    language?: SupportedLanguage;
    cweId?: number;
    severity?: Severity;
    patternType?: PatternType;
    tags?: string[];
}): SecurityPattern[] {
    return SECURITY_PATTERNS.filter(p => {
        if (filters.language && !p.languages.includes(filters.language)) return false;
        if (filters.cweId && p.cweId !== filters.cweId) return false;
        if (filters.severity && p.severity !== filters.severity) return false;
        if (filters.patternType && p.patternType !== filters.patternType) return false;
        if (filters.tags && !filters.tags.some(t => p.tags?.includes(t))) return false;
        return true;
    });
}
