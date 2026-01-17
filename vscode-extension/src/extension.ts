import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

interface Vulnerability {
    type: string;
    severity: string;
    title: string;
    description: string;
    location: {
        line: number;
        column: number;
    };
    function: string;
    contract: string;
    remediation: string;
    confidence: string;
}

interface AnalysisResult {
    file: string;
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        total: number;
    };
    vulnerabilities: Vulnerability[];
    parse_errors: string[];
}

class ReentrancyDiagnosticProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private outputChannel: vscode.OutputChannel;
    private activeProcesses: Map<string, ChildProcess> = new Map();
    private debounceTimers: Map<string, NodeJS.Timeout> = new Map();
    private readonly MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private readonly PROCESS_TIMEOUT = 60000; // 60 seconds
    private readonly DEBOUNCE_DELAY = 500; // 500ms

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('reentrancy-detector');
        this.outputChannel = vscode.window.createOutputChannel('Re-entrancy Detector');
    }

    private getConfig(): vscode.WorkspaceConfiguration {
        return vscode.workspace.getConfiguration('reentrancy-detector');
    }

    private validatePath(filePath: string): boolean {
        // Basic path validation - prevent path traversal
        const normalized = path.normalize(filePath);
        return !normalized.includes('..') && path.isAbsolute(normalized) || !normalized.startsWith('..');
    }

    private sanitizePythonPath(pythonPath: string): string {
        // Remove any shell metacharacters and validate
        const sanitized = pythonPath.trim().replace(/[;&|`$(){}[\]<>]/g, '');
        if (!sanitized || sanitized.length === 0) {
            return 'python3';
        }
        // Only allow alphanumeric, dots, slashes, dashes, underscores, and spaces
        if (!/^[a-zA-Z0-9./_\- ]+$/.test(sanitized)) {
            return 'python3';
        }
        return sanitized;
    }

    private getSeverity(vulnSeverity: string): vscode.DiagnosticSeverity {
        switch (vulnSeverity.toLowerCase()) {
            case 'critical':
                return vscode.DiagnosticSeverity.Error;
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            case 'info':
                return vscode.DiagnosticSeverity.Hint;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    private async runAnalyzer(filePath: string, sourceCode: string): Promise<AnalysisResult | null> {
        return new Promise((resolve, reject) => {
            const config = this.getConfig();
            const pythonPathRaw = config.get<string>('pythonPath', 'python3');
            const pythonPath = this.sanitizePythonPath(pythonPathRaw);
            const analyzerPath = config.get<string>('analyzerPath', '');
            const severityThreshold = config.get<string>('severityThreshold', 'low');

            // Validate file size
            if (sourceCode.length > this.MAX_FILE_SIZE) {
                reject(new Error(`File too large (${Math.round(sourceCode.length / 1024 / 1024)}MB). Maximum size is ${this.MAX_FILE_SIZE / 1024 / 1024}MB.`));
                return;
            }

            // Cancel any existing process for this file
            const existingProcess = this.activeProcesses.get(filePath);
            if (existingProcess) {
                try {
                    existingProcess.kill();
                } catch (e) {
                    // Ignore errors when killing
                }
                this.activeProcesses.delete(filePath);
            }

            // Determine the analyzer script path
            let scriptPath: string;
            if (analyzerPath && analyzerPath.trim().length > 0) {
                // Validate custom analyzer path
                if (!this.validatePath(analyzerPath)) {
                    reject(new Error('Invalid analyzer path provided'));
                    return;
                }
                if (!fs.existsSync(analyzerPath)) {
                    reject(new Error(`Analyzer script not found at: ${analyzerPath}`));
                    return;
                }
                scriptPath = analyzerPath;
            } else {
                // Try workspace root first (for development)
                const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
                if (workspaceRoot) {
                    const workspacePath = path.join(workspaceRoot, 'vscode-extension', 'analyzer_server.py');
                    if (fs.existsSync(workspacePath)) {
                        scriptPath = workspacePath;
                    } else {
                        reject(new Error(`Analyzer script not found. Tried: ${workspacePath}`));
                        return;
                    }
                } else {
                    // Try to find extension by name pattern
                    const allExtensions = vscode.extensions.all;
                    const extension = allExtensions.find(ext => 
                        ext.packageJSON.name === 'reentrancy-detector'
                    );
                    const extensionPath = extension?.extensionPath;
                    if (extensionPath) {
                        scriptPath = path.join(extensionPath, 'analyzer_server.py');
                        if (!fs.existsSync(scriptPath)) {
                            reject(new Error(`Analyzer script not found at ${scriptPath}`));
                            return;
                        }
                    } else {
                        reject(new Error('Could not find analyzer script. No workspace or extension path available.'));
                        return;
                    }
                }
            }

            this.outputChannel.appendLine(`Running analyzer: ${pythonPath} ${scriptPath}`);
            this.outputChannel.appendLine(`File: ${filePath}`);

            const process = spawn(pythonPath, [scriptPath, '--severity', severityThreshold], {
                stdio: ['pipe', 'pipe', 'pipe'],
                shell: false // Prevent shell injection
            });

            // Set up timeout after process is created
            const timeout = setTimeout(() => {
                if (process && !process.killed) {
                    process.kill();
                    this.activeProcesses.delete(filePath);
                    reject(new Error(`Analyzer process timed out after ${this.PROCESS_TIMEOUT / 1000} seconds`));
                }
            }, this.PROCESS_TIMEOUT);

            this.activeProcesses.set(filePath, process);

            let stdout = '';
            let stderr = '';
            const MAX_OUTPUT_SIZE = 50 * 1024 * 1024; // 50MB max output

            process.stdout.on('data', (data) => {
                stdout += data.toString();
                if (stdout.length > MAX_OUTPUT_SIZE) {
                    process.kill();
                    this.activeProcesses.delete(filePath);
                    clearTimeout(timeout);
                    reject(new Error('Analyzer output too large'));
                }
            });

            process.stderr.on('data', (data) => {
                stderr += data.toString();
                if (stderr.length > MAX_OUTPUT_SIZE) {
                    process.kill();
                    this.activeProcesses.delete(filePath);
                    clearTimeout(timeout);
                    reject(new Error('Analyzer error output too large'));
                }
            });

            process.on('error', (error) => {
                clearTimeout(timeout);
                this.activeProcesses.delete(filePath);
                this.outputChannel.appendLine(`Error: ${error.message}`);
                reject(new Error(`Failed to start analyzer: ${error.message}`));
            });

            process.on('close', (code) => {
                clearTimeout(timeout);
                this.activeProcesses.delete(filePath);

                if (code !== 0) {
                    this.outputChannel.appendLine(`Process exited with code ${code}`);
                    if (stderr) {
                        this.outputChannel.appendLine(`Stderr: ${stderr.substring(0, 1000)}`); // Limit stderr output
                    }
                    reject(new Error(`Analyzer process exited with code ${code}${stderr ? ': ' + stderr.substring(0, 200) : ''}`));
                    return;
                }

                if (!stdout || stdout.trim().length === 0) {
                    reject(new Error('Analyzer produced no output'));
                    return;
                }

                try {
                    const result = JSON.parse(stdout);
                    // Validate result structure
                    if (!result || typeof result !== 'object') {
                        reject(new Error('Invalid analyzer output format'));
                        return;
                    }
                    resolve(result);
                } catch (error: any) {
                    this.outputChannel.appendLine(`Failed to parse JSON: ${stdout.substring(0, 500)}`);
                    reject(new Error(`Failed to parse analyzer output: ${error.message || error}`));
                }
            });

            // Send source code to analyzer with error handling
            try {
                const input = JSON.stringify({ source: sourceCode, filename: path.basename(filePath) });
                process.stdin.write(input + '\n');
                process.stdin.end();
            } catch (error: any) {
                clearTimeout(timeout);
                process.kill();
                this.activeProcesses.delete(filePath);
                reject(new Error(`Failed to send input to analyzer: ${error.message || error}`));
            }
        });
    }

    async analyzeDocument(document: vscode.TextDocument, skipDebounce: boolean = false): Promise<void> {
        const config = this.getConfig();
        if (document.languageId !== 'solidity' || !config.get<boolean>('enable', true)) {
            return;
        }

        // Debounce analysis to avoid spamming processes
        if (!skipDebounce) {
            const uri = document.uri.toString();
            const existingTimer = this.debounceTimers.get(uri);
            if (existingTimer) {
                clearTimeout(existingTimer);
            }

            const timer = setTimeout(() => {
                this.debounceTimers.delete(uri);
                this.analyzeDocument(document, true);
            }, this.DEBOUNCE_DELAY);

            this.debounceTimers.set(uri, timer);
            return;
        }

        const filePath = document.uri.fsPath;
        const sourceCode = document.getText();

        this.outputChannel.appendLine(`Analyzing: ${filePath}`);

        try {
            const result = await this.runAnalyzer(filePath, sourceCode);

            if (!result) {
                this.outputChannel.appendLine('Analyzer returned no result');
                this.diagnosticCollection.set(document.uri, []);
                return;
            }

            this.outputChannel.appendLine(`Analyzer returned result with ${result.vulnerabilities?.length || 0} vulnerabilities`);

            // Show parse errors
            if (result.parse_errors && result.parse_errors.length > 0) {
                this.outputChannel.appendLine('Parse errors:');
                result.parse_errors.forEach(error => {
                    this.outputChannel.appendLine(`  - ${error}`);
                });
            }

            // Create diagnostics
            const diagnostics: vscode.Diagnostic[] = [];

            const maxLine = document.lineCount - 1;

            const vulnerabilities = result.vulnerabilities || [];
            this.outputChannel.appendLine(`Processing ${vulnerabilities.length} vulnerabilities...`);

            for (const vuln of vulnerabilities) {
                // Validate and clamp line numbers
                // Line numbers from analyzer are 1-based, convert to 0-based for VSCode
                let line = vuln.location.line - 1;
                
                // Clamp to valid range
                if (line < 0) {
                    line = 0;
                } else if (line > maxLine) {
                    line = maxLine;
                }
                
                const column = Math.max(0, vuln.location.column - 1);
                
                // Get actual line length for proper range
                let lineText = '';
                try {
                    lineText = document.lineAt(line).text;
                } catch (e) {
                    this.outputChannel.appendLine(`Warning: Could not get line ${line + 1}, using line 0`);
                    line = 0;
                    lineText = document.lineAt(0).text;
                }
                
                const endColumn = Math.min(Math.max(column + 50, column + 1), lineText.length); // Ensure valid range

                const range = new vscode.Range(
                    line,
                    column,
                    line,
                    endColumn
                );

                const severity = this.getSeverity(vuln.severity);
                const message = `${vuln.title}\n\n${vuln.description}${vuln.remediation ? `\n\nRemediation: ${vuln.remediation}` : ''}`;

                const diagnostic = new vscode.Diagnostic(range, message, severity);
                diagnostic.source = 'reentrancy-detector';
                diagnostic.code = vuln.type;

                diagnostics.push(diagnostic);
                this.outputChannel.appendLine(`Added diagnostic: ${vuln.severity} - ${vuln.title} at line ${line + 1}`);
            }

            this.diagnosticCollection.set(document.uri, diagnostics);

            // Show summary in output channel
            const totalVulns = vulnerabilities.length;
            const summary = result.summary || { critical: 0, high: 0, medium: 0, low: 0, total: totalVulns };
            
            if (totalVulns > 0) {
                this.outputChannel.appendLine(
                    `Found ${totalVulns} vulnerabilities: ` +
                    `${summary.critical} Critical, ` +
                    `${summary.high} High, ` +
                    `${summary.medium} Medium, ` +
                    `${summary.low} Low`
                );
                if (diagnostics.length > 0) {
                    vscode.window.showInformationMessage(
                        `Found ${totalVulns} re-entrancy issue${totalVulns > 1 ? 's' : ''}. Check Problems panel for details.`
                    );
                } else {
                    this.outputChannel.appendLine(`Warning: ${totalVulns} vulnerabilities found but ${diagnostics.length} diagnostics created. This may indicate a line number issue.`);
                }
            } else {
                this.outputChannel.appendLine('No vulnerabilities found.');
            }

        } catch (error: any) {
            this.outputChannel.appendLine(`Error: ${error.message}`);
            vscode.window.showErrorMessage(`Re-entrancy Detector: ${error.message}`);
        }
    }

    async analyzeWorkspace(): Promise<void> {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            vscode.window.showWarningMessage('No workspace folder open');
            return;
        }

        this.outputChannel.clear();
        this.outputChannel.appendLine('Scanning workspace...');

        const solFiles = await vscode.workspace.findFiles(
            '**/*.sol',
            '**/{node_modules,test,mock,Mock}/**',
            100
        );

        if (solFiles.length === 0) {
            vscode.window.showInformationMessage('No Solidity files found in workspace');
            return;
        }

        // Show progress
        const progressOptions: vscode.ProgressOptions = {
            location: vscode.ProgressLocation.Notification,
            title: 'Scanning workspace for re-entrancy vulnerabilities',
            cancellable: false
        };

        let totalVulns = 0;
        let processedFiles = 0;

        await vscode.window.withProgress(progressOptions, async (progress) => {
            for (const file of solFiles) {
                try {
                    progress.report({
                        increment: 100 / solFiles.length,
                        message: `Analyzing ${path.basename(file.fsPath)} (${processedFiles + 1}/${solFiles.length})`
                    });

                    const document = await vscode.workspace.openTextDocument(file);
                    await this.analyzeDocument(document, true); // Skip debounce for workspace scan
                    const diagnostics = this.diagnosticCollection.get(file);
                    if (diagnostics) {
                        totalVulns += diagnostics.length;
                    }
                    processedFiles++;
                } catch (error: any) {
                    this.outputChannel.appendLine(`Error analyzing ${file.fsPath}: ${error.message}`);
                    processedFiles++;
                }
            }
        });

        vscode.window.showInformationMessage(
            `Workspace scan complete. Found ${totalVulns} vulnerabilities across ${solFiles.length} files.`
        );
    }

    clearDiagnostics(): void {
        this.diagnosticCollection.clear();
    }

    clearDiagnosticsForFile(uri: vscode.Uri): void {
        this.diagnosticCollection.delete(uri);
    }

    dispose(): void {
        // Kill all active processes
        for (const [filePath, process] of this.activeProcesses.entries()) {
            try {
                if (!process.killed) {
                    process.kill();
                }
            } catch (e) {
                // Ignore errors
            }
        }
        this.activeProcesses.clear();

        // Clear all timers
        for (const timer of this.debounceTimers.values()) {
            clearTimeout(timer);
        }
        this.debounceTimers.clear();

        this.diagnosticCollection.dispose();
        this.outputChannel.dispose();
    }
}

let diagnosticProvider: ReentrancyDiagnosticProvider;

export function activate(context: vscode.ExtensionContext) {
    diagnosticProvider = new ReentrancyDiagnosticProvider();

    // Register commands
    const scanCommand = vscode.commands.registerCommand('reentrancy-detector.scan', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor && editor.document.languageId === 'solidity') {
            await diagnosticProvider.analyzeDocument(editor.document);
            vscode.window.showInformationMessage('Re-entrancy scan complete. Check Problems panel for results.');
        } else {
            vscode.window.showWarningMessage('Please open a Solidity file to scan');
        }
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('reentrancy-detector.scanWorkspace', async () => {
        await diagnosticProvider.analyzeWorkspace();
    });

    // Run on save if enabled
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('reentrancy-detector');
        if (config.get<boolean>('runOnSave', true) && document.languageId === 'solidity') {
            await diagnosticProvider.analyzeDocument(document, false); // Use debouncing
        }
    });

    // Run on document open (with debounce)
    const onOpenDisposable = vscode.workspace.onDidOpenTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('reentrancy-detector');
        if (config.get<boolean>('enable', true) && document.languageId === 'solidity') {
            await diagnosticProvider.analyzeDocument(document, false); // Use debouncing
        }
    });

    // Clean up diagnostics when files are deleted
    const onDeleteDisposable = vscode.workspace.onDidDeleteFiles(async (event) => {
        for (const file of event.files) {
            diagnosticProvider.clearDiagnosticsForFile(file);
        }
    });

    context.subscriptions.push(
        scanCommand,
        scanWorkspaceCommand,
        onSaveDisposable,
        onOpenDisposable,
        onDeleteDisposable,
        diagnosticProvider
    );
}

export function deactivate() {
    if (diagnosticProvider) {
        diagnosticProvider.dispose();
    }
}
