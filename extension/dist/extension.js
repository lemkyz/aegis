"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const path = __importStar(require("node:path"));
const vscode = __importStar(require("vscode"));
let lastAnalysis;
let diagnosticCollection;
function activate(context) {
    diagnosticCollection =
        vscode.languages.createDiagnosticCollection("aegis");
    const fastScanCommand = vscode.commands.registerCommand("aegis.fastScanSelectedCode", async () => analyzeSelectedCode("fast"));
    const fastScanCurrentFileCommand = vscode.commands.registerCommand("aegis.fastScanCurrentFile", fastScanCurrentFile);
    const deepAnalysisCommand = vscode.commands.registerCommand("aegis.deepAnalyzeSelectedCode", async () => analyzeSelectedCode("deep"));
    const applyFixCommand = vscode.commands.registerCommand("aegis.applySecureFix", applySecureFix);
    const deepAnalyzeDiagnosticCommand = vscode.commands.registerCommand("aegis.deepAnalyzeDiagnostic", deepAnalyzeDiagnostic);
    const openLastReportCommand = vscode.commands.registerCommand("aegis.openLastSecurityReport", openLastSecurityReport);
    const codeActionProvider = vscode.languages.registerCodeActionsProvider({
        scheme: "file",
        language: "*",
    }, new AegisCodeActionProvider(), {
        providedCodeActionKinds: [
            vscode.CodeActionKind.QuickFix,
        ],
    });
    context.subscriptions.push(diagnosticCollection, fastScanCommand, fastScanCurrentFileCommand, deepAnalysisCommand, applyFixCommand, deepAnalyzeDiagnosticCommand, openLastReportCommand, codeActionProvider);
}
async function fastScanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showErrorMessage("Aegis: No active editor was found.");
        return;
    }
    const document = editor.document;
    const code = document.getText();
    if (!code.trim()) {
        void vscode.window.showWarningMessage("Aegis: The current file is empty.");
        return;
    }
    const filename = path.basename(document.fileName || "unknown.py");
    const language = normalizeLanguage(document.languageId);
    const configuration = vscode.workspace.getConfiguration("aegis");
    const backendUrl = configuration
        .get("backendUrl", "http://127.0.0.1:8000")
        .replace(/\/+$/, "");
    try {
        const result = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Aegis is scanning the current file",
            cancellable: false,
        }, async () => requestAnalysis({
            backendUrl,
            code,
            filename,
            language,
            mode: "fast",
        }));
        lastAnalysis = {
            documentUri: document.uri.toString(),
            documentVersion: document.version,
            selection: new vscode.Range(document.positionAt(0), document.positionAt(code.length)),
            response: result,
            mode: "fast",
        };
        updateDiagnostics(document, result, 0);
        await showAnalysisResult(result, "fast");
        if (result.findings.length > 0) {
            const action = await vscode.window.showWarningMessage(`Aegis Fast Scan found ${result.findings.length} suspicious finding(s).`, "Run Deep Analysis", "Keep Report Open");
            if (action === "Run Deep Analysis") {
                editor.selection = new vscode.Selection(document.positionAt(0), document.positionAt(code.length));
                await analyzeSelectedCode("deep");
            }
        }
    }
    catch (error) {
        const message = error instanceof Error
            ? error.message
            : "Unknown analysis error.";
        void vscode.window.showErrorMessage(`Aegis: ${message}`);
    }
}
async function analyzeSelectedCode(mode) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showErrorMessage("Aegis: No active editor was found.");
        return;
    }
    if (editor.selection.isEmpty) {
        void vscode.window.showWarningMessage("Aegis: Select the code you want to analyze first.");
        return;
    }
    const document = editor.document;
    const selection = new vscode.Range(editor.selection.start, editor.selection.end);
    const selectedCode = document.getText(selection);
    const filename = path.basename(document.fileName || "unknown.py");
    const language = normalizeLanguage(document.languageId);
    const configuration = vscode.workspace.getConfiguration("aegis");
    const backendUrl = configuration
        .get("backendUrl", "http://127.0.0.1:8000")
        .replace(/\/+$/, "");
    const progressTitle = mode === "fast"
        ? "Aegis is running a fast security scan"
        : "Aegis is running deep AI analysis";
    try {
        const result = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: progressTitle,
            cancellable: false,
        }, async () => requestAnalysis({
            backendUrl,
            code: selectedCode,
            filename,
            language,
            mode,
        }));
        lastAnalysis = {
            documentUri: document.uri.toString(),
            documentVersion: document.version,
            selection,
            response: result,
            mode,
        };
        updateDiagnostics(document, result, selection.start.line);
        await showAnalysisResult(result, mode);
        if (mode === "fast" && result.findings.length > 0) {
            const action = await vscode.window.showWarningMessage(`Aegis Fast Scan ${result.findings.length} suspicious finding(s).`, "Run Deep Analysis", "Keep Report Open");
            if (action === "Run Deep Analysis") {
                await analyzeSelectedCode("deep");
            }
            return;
        }
        const firstPatch = findFirstPatch(result);
        if (mode === "deep" && firstPatch) {
            const action = await vscode.window.showInformationMessage(`Aegis ${result.findings.length} security finding(s).`, "Apply Secure Fix", "Keep Report Open");
            if (action === "Apply Secure Fix") {
                await applySecureFix();
            }
        }
    }
    catch (error) {
        const message = error instanceof Error
            ? error.message
            : "Unknown analysis error.";
        void vscode.window.showErrorMessage(`Aegis: ${message}`);
    }
}
async function applySecureFix() {
    if (!lastAnalysis) {
        void vscode.window.showWarningMessage("Aegis: Run Deep Analysis before applying a fix.");
        return;
    }
    if (lastAnalysis.mode !== "deep") {
        void vscode.window.showWarningMessage("Aegis: Fast Scan does not produce patches. Run Deep Analysis first.");
        return;
    }
    const analyzedState = lastAnalysis;
    const documentUri = vscode.Uri.parse(analyzedState.documentUri);
    const document = await vscode.workspace.openTextDocument(documentUri);
    const editor = await vscode.window.showTextDocument(document, {
        preview: false,
        viewColumn: vscode.ViewColumn.One,
    });
    if (document.version !== analyzedState.documentVersion) {
        void vscode.window.showWarningMessage("Aegis: The file changed after analysis. Run Deep Analysis again.");
        return;
    }
    const patch = findFirstPatch(analyzedState.response);
    if (!patch) {
        void vscode.window.showWarningMessage("Aegis: No applicable secure patch was found.");
        return;
    }
    const originalSelectionCode = document.getText(analyzedState.selection);
    const secureSelectionCode = preserveIndentation(originalSelectionCode, patch);
    const originalDocument = await vscode.workspace.openTextDocument({
        language: document.languageId,
        content: originalSelectionCode,
    });
    const secureDocument = await vscode.workspace.openTextDocument({
        language: document.languageId,
        content: secureSelectionCode,
    });
    await vscode.commands.executeCommand("vscode.diff", originalDocument.uri, secureDocument.uri, `Aegis Secure Fix Preview — ${path.basename(document.fileName)}`, {
        preview: true,
        viewColumn: vscode.ViewColumn.Beside,
    });
    const decision = await vscode.window.showWarningMessage("Review the Aegis secure fix in the diff editor.", {
        modal: true,
        detail: "Apply Fix replaces only the code selection analyzed by Aegis. The file will then be saved and scanned again automatically.",
    }, "Apply Fix", "Cancel");
    if (decision !== "Apply Fix") {
        return;
    }
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, analyzedState.selection, secureSelectionCode);
    const applied = await vscode.workspace.applyEdit(edit);
    if (!applied) {
        void vscode.window.showErrorMessage("Aegis: The secure fix could not be applied.");
        return;
    }
    const saved = await document.save();
    if (!saved) {
        void vscode.window.showWarningMessage("Aegis: The fix was applied, but the file could not be saved.");
        return;
    }
    diagnosticCollection?.delete(document.uri);
    lastAnalysis = undefined;
    const configuration = vscode.workspace.getConfiguration("aegis");
    const backendUrl = configuration
        .get("backendUrl", "http://127.0.0.1:8000")
        .replace(/\/+$/, "");
    const verificationResult = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is verifying the secure fix",
        cancellable: false,
    }, async () => requestAnalysis({
        backendUrl,
        code: document.getText(),
        filename: path.basename(document.fileName) || "unknown.py",
        language: normalizeLanguage(document.languageId),
        mode: "fast",
    }));
    updateDiagnostics(document, verificationResult, 0);
    lastAnalysis = {
        documentUri: document.uri.toString(),
        documentVersion: document.version,
        selection: new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)),
        response: verificationResult,
        mode: "fast",
    };
    await showAnalysisResult(verificationResult, "fast");
    if (verificationResult.findings.length === 0) {
        void vscode.window.showInformationMessage("Aegis Fix Status: VERIFIED — the vulnerability was not detected after rescanning.");
        return;
    }
    void vscode.window.showWarningMessage(`Aegis Fix Status: STILL VULNERABLE — ${verificationResult.findings.length} finding(s) remain after rescanning.`, "Open Problems").then((action) => {
        if (action === "Open Problems") {
            void vscode.commands.executeCommand("workbench.actions.view.problems");
        }
    });
    editor.revealRange(analyzedState.selection, vscode.TextEditorRevealType.InCenter);
}
async function requestAnalysis(input) {
    const controller = new AbortController();
    const timeoutMilliseconds = input.mode === "fast" ? 30_000 : 300_000;
    const timeout = setTimeout(() => controller.abort(), timeoutMilliseconds);
    const endpoint = input.mode === "fast"
        ? "/v1/analyze/fast"
        : "/v1/analyze/deep";
    try {
        const response = await fetch(`${input.backendUrl}${endpoint}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                code: input.code,
                filename: input.filename,
                language: input.language,
            }),
            signal: controller.signal,
        });
        const rawBody = await response.text();
        if (!response.ok) {
            throw new Error(`Backend HTTP ${response.status} döndürdü: ${rawBody}`);
        }
        return JSON.parse(rawBody);
    }
    catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
            const timeoutMessage = input.mode === "fast"
                ? "Fast Scan timed out after 30 seconds."
                : "Deep Analysis timed out after five minutes.";
            throw new Error(timeoutMessage);
        }
        throw error;
    }
    finally {
        clearTimeout(timeout);
    }
}
class AegisCodeActionProvider {
    provideCodeActions(document, _range, context) {
        const storedDiagnostics = diagnosticCollection?.get(document.uri) ?? [];
        const aegisDiagnostics = [
            ...context.diagnostics,
            ...storedDiagnostics,
        ].filter((diagnostic, index, diagnostics) => diagnostic.source === "Aegis" &&
            diagnostics.findIndex((candidate) => candidate.source === diagnostic.source &&
                candidate.message === diagnostic.message &&
                candidate.range.isEqual(diagnostic.range)) === index);
        if (aegisDiagnostics.length === 0) {
            return [];
        }
        const actions = [];
        for (const diagnostic of aegisDiagnostics) {
            const deepAnalysisAction = new vscode.CodeAction("Aegis: Run Deep Analysis", vscode.CodeActionKind.QuickFix);
            deepAnalysisAction.diagnostics = [diagnostic];
            deepAnalysisAction.isPreferred = true;
            deepAnalysisAction.command = {
                command: "aegis.deepAnalyzeDiagnostic",
                title: "Run Aegis Deep Analysis",
                arguments: [
                    document.uri,
                    diagnostic.range,
                ],
            };
            actions.push(deepAnalysisAction);
        }
        const analysisMatchesDocument = lastAnalysis?.documentUri === document.uri.toString();
        if (analysisMatchesDocument && lastAnalysis) {
            const openReportAction = new vscode.CodeAction("Aegis: Open Security Report", vscode.CodeActionKind.QuickFix);
            openReportAction.command = {
                command: "aegis.openLastSecurityReport",
                title: "Open Aegis Security Report",
            };
            actions.push(openReportAction);
            if (lastAnalysis.mode === "deep" &&
                findFirstPatch(lastAnalysis.response)) {
                const applyFixAction = new vscode.CodeAction("Aegis: Apply Secure Fix", vscode.CodeActionKind.QuickFix);
                applyFixAction.command = {
                    command: "aegis.applySecureFix",
                    title: "Apply Aegis Secure Fix",
                };
                actions.push(applyFixAction);
            }
        }
        return actions;
    }
}
async function deepAnalyzeDiagnostic(documentUri, range) {
    const document = await vscode.workspace.openTextDocument(documentUri);
    const editor = await vscode.window.showTextDocument(document, {
        preview: false,
        viewColumn: vscode.ViewColumn.One,
    });
    editor.selection = new vscode.Selection(range.start, range.end);
    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    await analyzeSelectedCode("deep");
}
async function openLastSecurityReport() {
    if (!lastAnalysis) {
        void vscode.window.showWarningMessage("Aegis: No previous security report is available.");
        return;
    }
    await showAnalysisResult(lastAnalysis.response, lastAnalysis.mode);
}
function updateDiagnostics(document, result, lineOffset) {
    if (!diagnosticCollection) {
        return;
    }
    const diagnostics = [];
    for (const finding of result.findings) {
        const evidenceItems = finding.scanner_evidence.length > 0
            ? finding.scanner_evidence
            : [
                {
                    line_start: finding.vulnerable_lines[0] ?? 1,
                    line_end: finding.vulnerable_lines.at(-1) ?? 1,
                },
            ];
        for (const evidence of evidenceItems) {
            const startLine = clampLine(evidence.line_start - 1 + lineOffset, document);
            const endLine = clampLine(evidence.line_end - 1 + lineOffset, document);
            const endCharacter = document.lineAt(endLine).text.length;
            const range = new vscode.Range(new vscode.Position(startLine, 0), new vscode.Position(endLine, endCharacter));
            const diagnostic = new vscode.Diagnostic(range, buildDiagnosticMessage(finding), mapDiagnosticSeverity(finding.severity));
            diagnostic.source = "Aegis";
            diagnostic.code =
                finding.cwe[0] ??
                    finding.scanner_evidence[0]?.rule_id ??
                    "security";
            diagnostics.push(diagnostic);
        }
    }
    diagnosticCollection.set(document.uri, diagnostics);
}
function buildDiagnosticMessage(finding) {
    const metadata = [
        finding.severity.toUpperCase(),
        finding.cwe[0],
        finding.owasp[0],
    ].filter(Boolean);
    return `${metadata.join(" · ")} — ${finding.title}`;
}
function mapDiagnosticSeverity(severity) {
    switch (severity) {
        case "critical":
        case "high":
            return vscode.DiagnosticSeverity.Error;
        case "medium":
            return vscode.DiagnosticSeverity.Warning;
        case "low":
            return vscode.DiagnosticSeverity.Information;
        case "info":
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}
function clampLine(line, document) {
    return Math.max(0, Math.min(line, document.lineCount - 1));
}
async function showAnalysisResult(result, mode) {
    const document = await vscode.workspace.openTextDocument({
        language: "markdown",
        content: buildMarkdownReport(result, mode),
    });
    await vscode.window.showTextDocument(document, {
        preview: true,
        viewColumn: vscode.ViewColumn.Beside,
    });
}
function findFirstPatch(result) {
    return (result.findings.find((finding) => finding.proposed_patch &&
        finding.proposed_patch.trim().length > 0)?.proposed_patch ?? undefined);
}
function preserveIndentation(originalCode, proposedPatch) {
    const sourceLine = originalCode
        .split("\n")
        .find((line) => line.trim().length > 0) ?? "";
    const indentation = sourceLine.match(/^\s*/)?.[0] ?? "";
    return proposedPatch
        .split("\n")
        .map((line) => (line.length > 0 ? `${indentation}${line}` : line))
        .join("\n");
}
function buildMarkdownReport(result, mode) {
    const modeLabel = mode === "fast" ? "Fast Scan" : "Deep Analysis";
    const lines = [
        `# Aegis ${modeLabel}`,
        "",
        `- **File:** ${result.filename}`,
        `- **Language:** ${result.language}`,
        `- **Mode:** ${modeLabel}`,
        `- **Model:** ${result.model}`,
        `- **Scanner:** ${result.scanner}`,
        `- **AI Review Status:** ${(result.analysis_status ?? "completed").toUpperCase()}`,
        `- **Result Source:** ${(result.result_source ?? "scanner").replaceAll("_", " ").toUpperCase()}`,
        `- **Patch Available:** ${findFirstPatch(result) ? "YES" : "NO"}`,
        `- **Findings:** ${result.findings.length}`,
        "",
    ];
    if (mode === "fast") {
        lines.push("> Fast Scan displays local scanner evidence only. Run Deep Analysis for AI review and a proposed patch.", "");
    }
    if (result.findings.length === 0) {
        lines.push("No meaningful security finding was detected.", "", "> This result does not guarantee that the code is completely secure.");
        return lines.join("\n");
    }
    result.findings.forEach((finding, index) => {
        lines.push(`## ${index + 1}. ${finding.title}`, "", `- **Severity:** ${finding.severity.toUpperCase()}`, `- **Confidence:** ${Math.round(finding.confidence * 100)}%`, `- **CWE:** ${finding.cwe.join(", ") || "Not mapped"}`, `- **OWASP:** ${finding.owasp.join(", ") || "Not mapped"}`, "", "### Summary", "", finding.summary, "", "### Evidence", "");
        finding.evidence.forEach((evidence) => {
            lines.push(`- ${evidence}`);
        });
        lines.push("", "### Scanner Evidence", "");
        finding.scanner_evidence.forEach((evidence) => {
            lines.push(`- **${evidence.tool} / ${evidence.rule_id}**`, `  - Lines: ${evidence.line_start}-${evidence.line_end}`, `  - Severity: ${evidence.severity}`, `  - ${evidence.message}`);
            if (evidence.code) {
                lines.push("", `\`\`\`${result.language}`, evidence.code, "\`\`\`");
            }
        });
        lines.push("", "### Recommended Fix", "", finding.recommended_fix, "");
        if (finding.false_positive_notes.length > 0) {
            lines.push("### Notes", "");
            finding.false_positive_notes.forEach((note) => {
                lines.push(`- ${note}`);
            });
            lines.push("");
        }
        if (finding.proposed_patch) {
            lines.push("### Proposed Patch", "", `\`\`\`${result.language}`, finding.proposed_patch, "```", "");
        }
        lines.push("---", "");
    });
    return lines.join("\n");
}
function normalizeLanguage(languageId) {
    const supported = {
        python: "python",
        javascript: "javascript",
        javascriptreact: "javascript",
        typescript: "typescript",
        typescriptreact: "typescript",
    };
    return supported[languageId] ?? languageId;
}
function deactivate() {
    diagnosticCollection?.clear();
    diagnosticCollection = undefined;
    lastAnalysis = undefined;
}
//# sourceMappingURL=extension.js.map