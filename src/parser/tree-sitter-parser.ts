/**
 * Tree-sitter AST Parser
 * Multi-language parsing with query support for security analysis
 */

import Parser, { Tree, Query, QueryCapture, SyntaxNode } from 'tree-sitter';
import path from 'path';

// Language type definitions
export type SupportedLanguage = 'javascript' | 'typescript' | 'tsx' | 'python' | 'go' | 'rust';

export interface ParseResult {
    tree: Tree;
    language: SupportedLanguage;
    filePath: string;
    parseTimeMs: number;
}

export interface QueryMatch {
    pattern: number;
    captures: QueryCapture[];
}

export interface NodeLocation {
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
    startIndex: number;
    endIndex: number;
}

export interface MatchedNode {
    node: SyntaxNode;
    captureName: string;
    location: NodeLocation;
    text: string;
}

// Cache for loaded languages and parsers
const languageCache = new Map<SupportedLanguage, unknown>();
const parserCache = new Map<SupportedLanguage, Parser>();
const queryCache = new Map<string, Query>();

/**
 * Load a Tree-sitter language grammar
 */
async function loadLanguage(language: SupportedLanguage): Promise<unknown> {
    if (languageCache.has(language)) {
        return languageCache.get(language)!;
    }

    let langModule: unknown;

    switch (language) {
        case 'javascript':
            langModule = (await import('tree-sitter-javascript')).default;
            break;
        case 'typescript':
            langModule = (await import('tree-sitter-typescript')).default.typescript;
            break;
        case 'tsx':
            langModule = (await import('tree-sitter-typescript')).default.tsx;
            break;
        case 'python':
            langModule = (await import('tree-sitter-python')).default;
            break;
        case 'go':
            langModule = (await import('tree-sitter-go')).default;
            break;
        case 'rust':
            langModule = (await import('tree-sitter-rust')).default;
            break;
        default:
            throw new Error(`Unsupported language: ${language}`);
    }

    languageCache.set(language, langModule);
    return langModule;
}

/**
 * Get or create a parser for a language
 */
async function getParser(language: SupportedLanguage): Promise<Parser> {
    if (parserCache.has(language)) {
        return parserCache.get(language)!;
    }

    const parser = new Parser();
    const langModule = await loadLanguage(language);
    parser.setLanguage(langModule as Parser.Language);
    parserCache.set(language, parser);
    return parser;
}

/**
 * Detect language from file extension
 */
export function detectLanguage(filePath: string): SupportedLanguage | null {
    const ext = path.extname(filePath).toLowerCase();

    const extensionMap: Record<string, SupportedLanguage> = {
        '.js': 'javascript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.mts': 'typescript',
        '.cts': 'typescript',
        '.tsx': 'tsx',
        '.py': 'python',
        '.pyw': 'python',
        '.go': 'go',
        '.rs': 'rust'
    };

    return extensionMap[ext] || null;
}

/**
 * Parse source code and return AST
 */
export async function parseCode(
    code: string,
    language: SupportedLanguage
): Promise<Tree> {
    const parser = await getParser(language);
    return parser.parse(code);
}

/**
 * Parse a file and return result with metadata
 */
export async function parseFile(
    filePath: string,
    code: string,
    language?: SupportedLanguage
): Promise<ParseResult> {
    const detectedLang = language || detectLanguage(filePath);
    if (!detectedLang) {
        throw new Error(`Cannot detect language for file: ${filePath}`);
    }

    const startTime = performance.now();
    const tree = await parseCode(code, detectedLang);
    const parseTimeMs = performance.now() - startTime;

    return {
        tree,
        language: detectedLang,
        filePath,
        parseTimeMs
    };
}

/**
 * Get or compile a Tree-sitter query
 */
export async function getQuery(
    language: SupportedLanguage,
    querySource: string
): Promise<Query> {
    const cacheKey = `${language}:${querySource}`;

    if (queryCache.has(cacheKey)) {
        return queryCache.get(cacheKey)!;
    }

    const langModule = await loadLanguage(language);
    const query = new Query(langModule as Parser.Language, querySource);
    queryCache.set(cacheKey, query);
    return query;
}

/**
 * Execute a query against a tree and return matches
 */
export async function executeQuery(
    tree: Tree,
    language: SupportedLanguage,
    querySource: string
): Promise<MatchedNode[]> {
    const query = await getQuery(language, querySource);
    const matches = query.matches(tree.rootNode);

    const results: MatchedNode[] = [];

    for (const match of matches) {
        for (const capture of match.captures) {
            results.push({
                node: capture.node,
                captureName: capture.name,
                location: getNodeLocation(capture.node),
                text: capture.node.text
            });
        }
    }

    return results;
}

/**
 * Extract location information from a node
 */
export function getNodeLocation(node: SyntaxNode): NodeLocation {
    return {
        startLine: node.startPosition.row + 1,  // Convert to 1-indexed
        startColumn: node.startPosition.column + 1,
        endLine: node.endPosition.row + 1,
        endColumn: node.endPosition.column + 1,
        startIndex: node.startIndex,
        endIndex: node.endIndex
    };
}

/**
 * Find all nodes of a specific type in the tree
 */
export function findNodesByType(root: SyntaxNode, nodeType: string): SyntaxNode[] {
    const results: SyntaxNode[] = [];
    const cursor = root.walk();

    let reachedRoot = false;
    while (!reachedRoot) {
        if (cursor.nodeType === nodeType) {
            results.push(cursor.currentNode);
        }

        if (cursor.gotoFirstChild()) {
            continue;
        }

        if (cursor.gotoNextSibling()) {
            continue;
        }

        let retracting = true;
        while (retracting) {
            if (!cursor.gotoParent()) {
                retracting = false;
                reachedRoot = true;
            } else if (cursor.gotoNextSibling()) {
                retracting = false;
            }
        }
    }

    return results;
}

/**
 * Find all function/method definitions
 */
export function findFunctionDefinitions(
    tree: Tree,
    language: SupportedLanguage
): SyntaxNode[] {
    const functionTypes: Record<SupportedLanguage, string[]> = {
        javascript: ['function_declaration', 'function_expression', 'arrow_function', 'method_definition'],
        typescript: ['function_declaration', 'function_expression', 'arrow_function', 'method_definition'],
        tsx: ['function_declaration', 'function_expression', 'arrow_function', 'method_definition'],
        python: ['function_definition'],
        go: ['function_declaration', 'method_declaration'],
        rust: ['function_item']
    };

    const types = functionTypes[language] || [];
    const results: SyntaxNode[] = [];

    for (const type of types) {
        results.push(...findNodesByType(tree.rootNode, type));
    }

    return results;
}

/**
 * Find all call expressions (function calls)
 */
export function findCallExpressions(
    tree: Tree,
    language: SupportedLanguage
): SyntaxNode[] {
    const callTypes: Record<SupportedLanguage, string[]> = {
        javascript: ['call_expression'],
        typescript: ['call_expression'],
        tsx: ['call_expression'],
        python: ['call'],
        go: ['call_expression'],
        rust: ['call_expression', 'macro_invocation']
    };

    const types = callTypes[language] || [];
    const results: SyntaxNode[] = [];

    for (const type of types) {
        results.push(...findNodesByType(tree.rootNode, type));
    }

    return results;
}

/**
 * Find string literals that might contain SQL, shell commands, etc.
 */
export function findStringLiterals(
    tree: Tree,
    language: SupportedLanguage
): SyntaxNode[] {
    const stringTypes: Record<SupportedLanguage, string[]> = {
        javascript: ['string', 'template_string'],
        typescript: ['string', 'template_string'],
        tsx: ['string', 'template_string'],
        python: ['string', 'concatenated_string'],
        go: ['interpreted_string_literal', 'raw_string_literal'],
        rust: ['string_literal', 'raw_string_literal']
    };

    const types = stringTypes[language] || [];
    const results: SyntaxNode[] = [];

    for (const type of types) {
        results.push(...findNodesByType(tree.rootNode, type));
    }

    return results;
}

/**
 * Get the parent function of a node
 */
export function getParentFunction(
    node: SyntaxNode,
    language: SupportedLanguage
): SyntaxNode | null {
    const functionTypes: Record<SupportedLanguage, string[]> = {
        javascript: ['function_declaration', 'function_expression', 'arrow_function', 'method_definition'],
        typescript: ['function_declaration', 'function_expression', 'arrow_function', 'method_definition'],
        tsx: ['function_declaration', 'function_expression', 'arrow_function', 'method_definition'],
        python: ['function_definition'],
        go: ['function_declaration', 'method_declaration'],
        rust: ['function_item']
    };

    const types = new Set(functionTypes[language] || []);
    let current: SyntaxNode | null = node.parent;

    while (current) {
        if (types.has(current.type)) {
            return current;
        }
        current = current.parent;
    }

    return null;
}

/**
 * Check if a node is inside a try-catch block
 */
export function isInTryCatch(
    node: SyntaxNode,
    language: SupportedLanguage
): boolean {
    const tryTypes: Record<SupportedLanguage, string[]> = {
        javascript: ['try_statement'],
        typescript: ['try_statement'],
        tsx: ['try_statement'],
        python: ['try_statement'],
        go: [],  // Go uses explicit error handling
        rust: []  // Rust uses Result type
    };

    const types = new Set(tryTypes[language] || []);
    let current: SyntaxNode | null = node.parent;

    while (current) {
        if (types.has(current.type)) {
            return true;
        }
        current = current.parent;
    }

    return false;
}

/**
 * Extract function name from a call expression
 */
export function getCallFunctionName(
    callNode: SyntaxNode,
    language: SupportedLanguage
): string | null {
    let functionNode: SyntaxNode | null = null;

    switch (language) {
        case 'javascript':
        case 'typescript':
        case 'tsx':
            functionNode = callNode.childForFieldName('function');
            break;
        case 'python':
            functionNode = callNode.childForFieldName('function');
            break;
        case 'go':
            functionNode = callNode.childForFieldName('function');
            break;
        case 'rust':
            functionNode = callNode.childForFieldName('function');
            break;
    }

    if (!functionNode) {
        return null;
    }

    // Handle member expressions (e.g., obj.method)
    if (functionNode.type === 'member_expression' || functionNode.type === 'attribute') {
        const property = functionNode.childForFieldName('property') ||
                         functionNode.childForFieldName('attribute');
        return property?.text || null;
    }

    return functionNode.text;
}

/**
 * Get import statements from a file
 */
export function findImports(
    tree: Tree,
    language: SupportedLanguage
): SyntaxNode[] {
    const importTypes: Record<SupportedLanguage, string[]> = {
        javascript: ['import_statement', 'import_specifier'],
        typescript: ['import_statement', 'import_specifier'],
        tsx: ['import_statement', 'import_specifier'],
        python: ['import_statement', 'import_from_statement'],
        go: ['import_declaration', 'import_spec'],
        rust: ['use_declaration']
    };

    const types = importTypes[language] || [];
    const results: SyntaxNode[] = [];

    for (const type of types) {
        results.push(...findNodesByType(tree.rootNode, type));
    }

    return results;
}

/**
 * Check if tree has syntax errors
 */
export function hasSyntaxErrors(tree: Tree): boolean {
    return tree.rootNode.hasError;
}

/**
 * Get all syntax error nodes
 */
export function getSyntaxErrors(tree: Tree): SyntaxNode[] {
    return findNodesByType(tree.rootNode, 'ERROR');
}

// Export parser management functions
export function clearQueryCache(): void {
    queryCache.clear();
}

export function clearAllCaches(): void {
    languageCache.clear();
    parserCache.clear();
    queryCache.clear();
}
