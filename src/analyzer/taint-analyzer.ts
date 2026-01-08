/**
 * Taint Analysis Engine
 * Tracks data flow from untrusted sources to dangerous sinks
 */

import { SyntaxNode, Tree } from 'tree-sitter';
import {
    SupportedLanguage,
    findNodesByType,
    findCallExpressions,
    getCallFunctionName,
    getNodeLocation,
    getParentFunction,
    NodeLocation
} from '../parser/tree-sitter-parser.js';
import { TaintConfig, SourceSinkDef } from '../patterns/pattern-library.js';

export interface TaintedVariable {
    name: string;
    sourceNode: SyntaxNode;
    sourceLocation: NodeLocation;
    taintSource: string;  // Description of where taint originated
    propagationPath: TaintPropagation[];
}

export interface TaintPropagation {
    node: SyntaxNode;
    location: NodeLocation;
    type: 'assignment' | 'argument' | 'return' | 'property';
    description: string;
}

export interface TaintFinding {
    sinkNode: SyntaxNode;
    sinkLocation: NodeLocation;
    sinkDescription: string;
    taintedVar: TaintedVariable;
    sanitized: boolean;
    sanitizerLocation?: NodeLocation;
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface TaintAnalysisResult {
    findings: TaintFinding[];
    taintedVariables: TaintedVariable[];
    analysisTimeMs: number;
}

/**
 * Language-specific source definitions
 */
const DEFAULT_SOURCES: Record<SupportedLanguage, SourceSinkDef[]> = {
    javascript: [
        { methodPattern: 'req.body' },
        { methodPattern: 'req.query' },
        { methodPattern: 'req.params' },
        { methodPattern: 'req.headers' },
        { methodPattern: 'process.argv' },
        { functionName: 'prompt' },
        { methodPattern: 'location.search' },
        { methodPattern: 'location.hash' },
        { methodPattern: 'document.cookie' }
    ],
    typescript: [
        { methodPattern: 'req.body' },
        { methodPattern: 'req.query' },
        { methodPattern: 'req.params' },
        { methodPattern: 'req.headers' },
        { methodPattern: 'process.argv' }
    ],
    tsx: [
        { methodPattern: 'req.body' },
        { methodPattern: 'req.query' },
        { methodPattern: 'props' }
    ],
    python: [
        { methodPattern: 'request.args' },
        { methodPattern: 'request.form' },
        { methodPattern: 'request.json' },
        { methodPattern: 'request.data' },
        { functionName: 'input' },
        { methodPattern: 'sys.argv' },
        { methodPattern: 'os.environ' }
    ],
    go: [
        { methodPattern: 'r.URL.Query' },
        { methodPattern: 'r.FormValue' },
        { methodPattern: 'r.Body' },
        { methodPattern: 'os.Args' },
        { methodPattern: 'os.Getenv' }
    ],
    rust: [
        { methodPattern: 'std::env::args' },
        { methodPattern: 'std::env::var' }
    ]
};

/**
 * Common sanitizers by language
 */
const DEFAULT_SANITIZERS: Record<SupportedLanguage, SourceSinkDef[]> = {
    javascript: [
        { functionName: 'escape' },
        { functionName: 'encodeURIComponent' },
        { functionName: 'encodeURI' },
        { methodPattern: 'DOMPurify.sanitize' },
        { functionName: 'parseInt' },
        { functionName: 'parseFloat' },
        { functionName: 'Number' },
        { methodPattern: 'validator.escape' }
    ],
    typescript: [
        { functionName: 'escape' },
        { functionName: 'encodeURIComponent' },
        { functionName: 'parseInt' },
        { functionName: 'Number' }
    ],
    tsx: [
        { functionName: 'escape' },
        { functionName: 'encodeURIComponent' },
        { methodPattern: 'DOMPurify.sanitize' }
    ],
    python: [
        { functionName: 'escape' },
        { methodPattern: 'html.escape' },
        { functionName: 'int' },
        { functionName: 'float' },
        { methodPattern: 'bleach.clean' },
        { methodPattern: 'shlex.quote' }
    ],
    go: [
        { methodPattern: 'html.EscapeString' },
        { methodPattern: 'url.QueryEscape' },
        { methodPattern: 'strconv.Atoi' },
        { methodPattern: 'template.HTMLEscapeString' }
    ],
    rust: [
        { methodPattern: 'html_escape' }
    ]
};

export class TaintAnalyzer {
    private language: SupportedLanguage;
    private sources: SourceSinkDef[];
    private sanitizers: SourceSinkDef[];
    private taintedVars: Map<string, TaintedVariable>;
    private findings: TaintFinding[];

    constructor(language: SupportedLanguage) {
        this.language = language;
        this.sources = DEFAULT_SOURCES[language] || [];
        this.sanitizers = DEFAULT_SANITIZERS[language] || [];
        this.taintedVars = new Map();
        this.findings = [];
    }

    /**
     * Configure custom sources and sanitizers
     */
    configure(config: TaintConfig): void {
        if (config.sources) {
            this.sources = [...this.sources, ...config.sources];
        }
        if (config.sanitizers) {
            this.sanitizers = [...this.sanitizers, ...config.sanitizers];
        }
    }

    /**
     * Perform taint analysis on a syntax tree
     */
    analyze(tree: Tree, config: TaintConfig): TaintAnalysisResult {
        const startTime = performance.now();

        this.taintedVars.clear();
        this.findings = [];

        // Merge provided config with defaults
        const sources = [...this.sources, ...(config.sources || [])];
        const sanitizers = [...this.sanitizers, ...(config.sanitizers || [])];
        const sinks = config.sinks || [];

        // Step 1: Find all taint sources
        this.findTaintSources(tree.rootNode, sources);

        // Step 2: Track taint propagation through assignments
        this.trackTaintPropagation(tree.rootNode);

        // Step 3: Check for tainted data reaching sinks
        this.checkSinks(tree.rootNode, sinks, sanitizers);

        const analysisTimeMs = performance.now() - startTime;

        return {
            findings: this.findings,
            taintedVariables: Array.from(this.taintedVars.values()),
            analysisTimeMs
        };
    }

    /**
     * Find initial taint sources in the code
     */
    private findTaintSources(root: SyntaxNode, sources: SourceSinkDef[]): void {
        const cursor = root.walk();
        let reachedRoot = false;

        while (!reachedRoot) {
            const node = cursor.currentNode;

            for (const source of sources) {
                if (this.matchesSourceSink(node, source)) {
                    // Find the variable this is assigned to
                    const assignment = this.findAssignmentTarget(node);
                    if (assignment) {
                        this.taintedVars.set(assignment.name, {
                            name: assignment.name,
                            sourceNode: node,
                            sourceLocation: getNodeLocation(node),
                            taintSource: this.describeSource(source),
                            propagationPath: []
                        });
                    }
                }
            }

            if (cursor.gotoFirstChild()) continue;
            if (cursor.gotoNextSibling()) continue;

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
    }

    /**
     * Track how taint propagates through the code
     */
    private trackTaintPropagation(root: SyntaxNode): void {
        const assignments = this.findAssignments(root);

        // Multiple passes to catch transitive taint
        let changed = true;
        let iterations = 0;
        const maxIterations = 10;

        while (changed && iterations < maxIterations) {
            changed = false;
            iterations++;

            for (const { target, value } of assignments) {
                if (this.taintedVars.has(target)) continue;

                // Check if value contains any tainted variable
                const taintSource = this.findTaintInExpression(value);
                if (taintSource) {
                    this.taintedVars.set(target, {
                        name: target,
                        sourceNode: value,
                        sourceLocation: getNodeLocation(value),
                        taintSource: `Propagated from ${taintSource.name}`,
                        propagationPath: [
                            ...taintSource.propagationPath,
                            {
                                node: value,
                                location: getNodeLocation(value),
                                type: 'assignment',
                                description: `Assigned to ${target}`
                            }
                        ]
                    });
                    changed = true;
                }
            }
        }
    }

    /**
     * Check if tainted data reaches any sinks
     */
    private checkSinks(
        root: SyntaxNode,
        sinks: SourceSinkDef[],
        sanitizers: SourceSinkDef[]
    ): void {
        const calls = findCallExpressions({ rootNode: root } as Tree, this.language);

        for (const call of calls) {
            for (const sink of sinks) {
                if (this.matchesSourceSink(call, sink)) {
                    // Get the argument at the specified index (or all arguments)
                    const args = this.getCallArguments(call);
                    const targetArgIndex = sink.argIndex ?? 0;

                    for (let i = 0; i < args.length; i++) {
                        if (sink.argIndex !== undefined && i !== targetArgIndex) continue;

                        const taint = this.findTaintInExpression(args[i]);
                        if (taint) {
                            // Check if sanitized between source and sink
                            const sanitized = this.isSanitizedBetween(
                                taint.sourceNode,
                                call,
                                sanitizers
                            );

                            this.findings.push({
                                sinkNode: call,
                                sinkLocation: getNodeLocation(call),
                                sinkDescription: this.describeSink(sink),
                                taintedVar: taint,
                                sanitized,
                                confidence: sanitized ? 'LOW' : (this.hasDirectFlow(taint, call) ? 'HIGH' : 'MEDIUM')
                            });
                        }
                    }
                }
            }
        }
    }

    /**
     * Check if a node matches a source/sink definition
     */
    private matchesSourceSink(node: SyntaxNode, def: SourceSinkDef): boolean {
        if (def.functionName) {
            const funcName = this.getFunctionName(node);
            return funcName === def.functionName;
        }

        if (def.methodPattern) {
            const nodeText = node.text;
            const pattern = def.methodPattern.replace(/\./g, '\\.').replace(/\*/g, '.*');
            return new RegExp(pattern).test(nodeText);
        }

        return false;
    }

    /**
     * Get the function name from a call expression
     */
    private getFunctionName(node: SyntaxNode): string | null {
        if (node.type !== 'call_expression' && node.type !== 'call') {
            return null;
        }
        return getCallFunctionName(node, this.language);
    }

    /**
     * Find the assignment target for a node (if it's being assigned)
     */
    private findAssignmentTarget(node: SyntaxNode): { name: string; node: SyntaxNode } | null {
        let current = node.parent;

        while (current) {
            if (current.type === 'assignment_expression' || current.type === 'assignment') {
                const left = current.childForFieldName('left');
                if (left && left.type === 'identifier') {
                    return { name: left.text, node: left };
                }
            }

            if (current.type === 'variable_declarator' || current.type === 'assignment') {
                const name = current.childForFieldName('name');
                if (name) {
                    return { name: name.text, node: name };
                }
            }

            current = current.parent;
        }

        return null;
    }

    /**
     * Find all assignments in the code
     */
    private findAssignments(root: SyntaxNode): Array<{ target: string; value: SyntaxNode }> {
        const assignments: Array<{ target: string; value: SyntaxNode }> = [];

        // Variable declarations
        const declarators = findNodesByType(root, 'variable_declarator');
        for (const decl of declarators) {
            const name = decl.childForFieldName('name');
            const value = decl.childForFieldName('value');
            if (name && value) {
                assignments.push({ target: name.text, value });
            }
        }

        // Assignment expressions
        const assignExprs = findNodesByType(root, 'assignment_expression');
        for (const expr of assignExprs) {
            const left = expr.childForFieldName('left');
            const right = expr.childForFieldName('right');
            if (left && right && left.type === 'identifier') {
                assignments.push({ target: left.text, value: right });
            }
        }

        // Python assignments
        const pyAssignments = findNodesByType(root, 'assignment');
        for (const expr of pyAssignments) {
            const left = expr.childForFieldName('left');
            const right = expr.childForFieldName('right');
            if (left && right && left.type === 'identifier') {
                assignments.push({ target: left.text, value: right });
            }
        }

        return assignments;
    }

    /**
     * Check if an expression contains tainted data
     */
    private findTaintInExpression(node: SyntaxNode): TaintedVariable | null {
        // Direct identifier match
        if (node.type === 'identifier') {
            return this.taintedVars.get(node.text) || null;
        }

        // Check children recursively
        for (let i = 0; i < node.childCount; i++) {
            const child = node.child(i);
            if (child) {
                const taint = this.findTaintInExpression(child);
                if (taint) return taint;
            }
        }

        return null;
    }

    /**
     * Get arguments from a call expression
     */
    private getCallArguments(call: SyntaxNode): SyntaxNode[] {
        const args: SyntaxNode[] = [];
        const argsNode = call.childForFieldName('arguments');

        if (argsNode) {
            for (let i = 0; i < argsNode.childCount; i++) {
                const child = argsNode.child(i);
                // Skip parentheses and commas
                if (child && child.type !== '(' && child.type !== ')' && child.type !== ',') {
                    args.push(child);
                }
            }
        }

        return args;
    }

    /**
     * Check if data was sanitized between source and sink
     */
    private isSanitizedBetween(
        source: SyntaxNode,
        sink: SyntaxNode,
        sanitizers: SourceSinkDef[]
    ): boolean {
        // Get the function containing both nodes
        const sourceFunc = getParentFunction(source, this.language);
        const sinkFunc = getParentFunction(sink, this.language);

        if (sourceFunc !== sinkFunc) {
            // Cross-function analysis is more complex
            return false;
        }

        // Simple approach: check if any sanitizer call appears between source and sink line numbers
        const sourceStart = source.startPosition.row;
        const sinkStart = sink.startPosition.row;

        if (!sourceFunc) return false;

        const calls = findCallExpressions({ rootNode: sourceFunc } as Tree, this.language);

        for (const call of calls) {
            const callLine = call.startPosition.row;
            if (callLine > sourceStart && callLine < sinkStart) {
                for (const sanitizer of sanitizers) {
                    if (this.matchesSourceSink(call, sanitizer)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Check if there's a direct flow from source to sink (higher confidence)
     */
    private hasDirectFlow(taint: TaintedVariable, sink: SyntaxNode): boolean {
        // Check if the taint source and sink are in the same function
        const sourceFunc = getParentFunction(taint.sourceNode, this.language);
        const sinkFunc = getParentFunction(sink, this.language);

        if (sourceFunc === sinkFunc) {
            // Same function = higher confidence
            return taint.propagationPath.length <= 2;
        }

        return false;
    }

    /**
     * Describe a source for reporting
     */
    private describeSource(source: SourceSinkDef): string {
        if (source.functionName) {
            return `Function call: ${source.functionName}()`;
        }
        if (source.methodPattern) {
            return `Expression: ${source.methodPattern}`;
        }
        return 'Unknown source';
    }

    /**
     * Describe a sink for reporting
     */
    private describeSink(sink: SourceSinkDef): string {
        if (sink.functionName) {
            return `Function: ${sink.functionName}()`;
        }
        if (sink.methodPattern) {
            return `Method: ${sink.methodPattern}`;
        }
        return 'Unknown sink';
    }
}

/**
 * Factory function to create a taint analyzer
 */
export function createTaintAnalyzer(language: SupportedLanguage): TaintAnalyzer {
    return new TaintAnalyzer(language);
}
