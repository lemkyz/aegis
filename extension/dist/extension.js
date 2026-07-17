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
const vscode = __importStar(require("vscode"));
function activate(context) {
    const command = vscode.commands.registerCommand("aegis.analyzeSelectedCode", analyzeSelectedCode);
    context.subscriptions.push(command);
}
async function analyzeSelectedCode() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showErrorMessage("Aegis: Açık bir editör bulunamadı.");
        return;
    }
    const selection = editor.selection;
    if (selection.isEmpty) {
        void vscode.window.showWarningMessage("Aegis: Önce analiz edilecek kodu seç.");
        return;
    }
    const selectedCode = editor.document.getText(selection);
    const filename = editor.document.fileName.split("/").pop() ?? "unknown.py";
    const language = normalizeLanguage(editor.document.languageId);
    const configuration = vscode.workspace.getConfiguration("aegis");
    const backendUrl = configuration
        .get("backendUrl", "http://127.0.0.1:8000")
        .replace(/\/+$/, "");
    try {
        const result = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Aegis seçili kodu analiz ediyor",
            cancellable: false,
        }, async () => requestAnalysis({
            backendUrl,
            code: selectedCode,
            filename,
            language,
        }));
        await showAnalysisResult(result);
    }
    catch (error) {
        const message = error instanceof Error
            ? error.message
            : "Bilinmeyen analiz hatası.";
        void vscode.window.showErrorMessage(`Aegis: ${message}`);
    }
}
async function requestAnalysis(input) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 300_000);
    try {
        const response = await fetch(`${input.backendUrl}/v1/analyze`, {
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
            throw new Error("Analiz beş dakika sonunda zaman aşımına uğradı.");
        }
        throw error;
    }
    finally {
        clearTimeout(timeout);
    }
}
async function showAnalysisResult(result) {
    const document = await vscode.workspace.openTextDocument({
        language: "markdown",
        content: buildMarkdownReport(result),
    });
    await vscode.window.showTextDocument(document, {
        preview: true,
        viewColumn: vscode.ViewColumn.Beside,
    });
}
function buildMarkdownReport(result) {
    const lines = [
        "# Aegis Security Analysis",
        "",
        `- **File:** ${result.filename}`,
        `- **Language:** ${result.language}`,
        `- **Model:** ${result.model}`,
        `- **Scanner:** ${result.scanner}`,
        `- **Findings:** ${result.findings.length}`,
        "",
    ];
    if (result.findings.length === 0) {
        lines.push("Anlamlı bir güvenlik bulgusu tespit edilmedi.", "", "> Bu sonuç kodun tamamen güvenli olduğunu garanti etmez.");
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
        });
        lines.push("", "### Recommended Fix", "", finding.recommended_fix, "");
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
    // Şimdilik temizlenecek kaynak bulunmuyor.
}
//# sourceMappingURL=extension.js.map