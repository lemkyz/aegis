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
function activate(context) {
    const analyzeCommand = vscode.commands.registerCommand("aegis.analyzeSelectedCode", analyzeSelectedCode);
    const applyFixCommand = vscode.commands.registerCommand("aegis.applySecureFix", applySecureFix);
    context.subscriptions.push(analyzeCommand, applyFixCommand);
}
async function analyzeSelectedCode() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showErrorMessage("Aegis: Açık bir editör bulunamadı.");
        return;
    }
    if (editor.selection.isEmpty) {
        void vscode.window.showWarningMessage("Aegis: Önce analiz edilecek kodu seç.");
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
        lastAnalysis = {
            documentUri: document.uri.toString(),
            documentVersion: document.version,
            selection,
            response: result,
        };
        await showAnalysisResult(result);
        const firstPatch = findFirstPatch(result);
        if (firstPatch) {
            const action = await vscode.window.showInformationMessage(`Aegis ${result.findings.length} güvenlik bulgusu tespit etti.`, "Güvenli düzeltmeyi uygula", "Raporu açık bırak");
            if (action === "Güvenli düzeltmeyi uygula") {
                await applySecureFix();
            }
        }
    }
    catch (error) {
        const message = error instanceof Error
            ? error.message
            : "Bilinmeyen analiz hatası.";
        void vscode.window.showErrorMessage(`Aegis: ${message}`);
    }
}
async function applySecureFix() {
    if (!lastAnalysis) {
        void vscode.window.showWarningMessage("Aegis: Önce seçili kodu analiz et.");
        return;
    }
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        void vscode.window.showErrorMessage("Aegis: Düzeltmenin uygulanacağı editör bulunamadı.");
        return;
    }
    if (editor.document.uri.toString() !== lastAnalysis.documentUri) {
        void vscode.window.showWarningMessage("Aegis: Analiz edilen dosya şu anda açık değil.");
        return;
    }
    if (editor.document.version !== lastAnalysis.documentVersion) {
        void vscode.window.showWarningMessage("Aegis: Dosya analizden sonra değiştirildi. Yeniden analiz et.");
        return;
    }
    const patch = findFirstPatch(lastAnalysis.response);
    if (!patch) {
        void vscode.window.showWarningMessage("Aegis: Uygulanabilir bir güvenli patch bulunamadı.");
        return;
    }
    const originalCode = editor.document.getText(lastAnalysis.selection);
    const previewDocument = await vscode.workspace.openTextDocument({
        language: editor.document.languageId,
        content: patch,
    });
    await vscode.window.showTextDocument(previewDocument, {
        preview: true,
        viewColumn: vscode.ViewColumn.Beside,
    });
    const decision = await vscode.window.showWarningMessage("Aegis seçili kodu önerilen güvenli patch ile değiştirecek.", {
        modal: true,
        detail: "Değişiklik yalnızca açık dosyadaki analiz edilmiş seçim alanına uygulanacaktır.",
    }, "Düzeltmeyi uygula", "İptal");
    if (decision !== "Düzeltmeyi uygula") {
        return;
    }
    const edit = new vscode.WorkspaceEdit();
    edit.replace(editor.document.uri, lastAnalysis.selection, preserveIndentation(originalCode, patch));
    const applied = await vscode.workspace.applyEdit(edit);
    if (!applied) {
        void vscode.window.showErrorMessage("Aegis: Güvenli düzeltme uygulanamadı.");
        return;
    }
    await editor.document.save();
    lastAnalysis = undefined;
    void vscode.window.showInformationMessage("Aegis: Güvenli düzeltme uygulandı. Kodu yeniden analiz et.");
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
function findFirstPatch(result) {
    return result.findings.find((finding) => finding.proposed_patch &&
        finding.proposed_patch.trim().length > 0)?.proposed_patch ?? undefined;
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
    lastAnalysis = undefined;
}
//# sourceMappingURL=extension.js.map