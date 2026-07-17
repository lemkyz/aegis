import * as path from "node:path";
import * as vscode from "vscode";

type Severity = "info" | "low" | "medium" | "high" | "critical";

interface ScannerEvidence {
  tool: string;
  rule_id: string;
  message: string;
  severity: string;
  file: string;
  line_start: number;
  line_end: number;
  code: string | null;
}

interface SecurityFinding {
  title: string;
  severity: Severity;
  confidence: number;
  summary: string;
  evidence: string[];
  scanner_evidence: ScannerEvidence[];
  cwe: string[];
  owasp: string[];
  vulnerable_lines: number[];
  false_positive_notes: string[];
  recommended_fix: string;
  proposed_patch: string | null;
}

interface AnalyzeResponse {
  filename: string;
  language: string;
  model: string;
  scanner: string;
  findings: SecurityFinding[];
}

interface LastAnalysis {
  documentUri: string;
  documentVersion: number;
  selection: vscode.Range;
  response: AnalyzeResponse;
}

let lastAnalysis: LastAnalysis | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const analyzeCommand = vscode.commands.registerCommand(
    "aegis.analyzeSelectedCode",
    analyzeSelectedCode,
  );

  const applyFixCommand = vscode.commands.registerCommand(
    "aegis.applySecureFix",
    applySecureFix,
  );

  context.subscriptions.push(analyzeCommand, applyFixCommand);
}

async function analyzeSelectedCode(): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: Açık bir editör bulunamadı.",
    );
    return;
  }

  if (editor.selection.isEmpty) {
    void vscode.window.showWarningMessage(
      "Aegis: Önce analiz edilecek kodu seç.",
    );
    return;
  }

  const document = editor.document;
  const selection = new vscode.Range(
    editor.selection.start,
    editor.selection.end,
  );

  const selectedCode = document.getText(selection);
  const filename = path.basename(document.fileName || "unknown.py");
  const language = normalizeLanguage(document.languageId);

  const configuration = vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>("backendUrl", "http://127.0.0.1:8000")
    .replace(/\/+$/, "");

  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis seçili kodu analiz ediyor",
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code: selectedCode,
          filename,
          language,
        }),
    );

    lastAnalysis = {
      documentUri: document.uri.toString(),
      documentVersion: document.version,
      selection,
      response: result,
    };

    await showAnalysisResult(result);

    const firstPatch = findFirstPatch(result);

    if (firstPatch) {
      const action = await vscode.window.showInformationMessage(
        `Aegis ${result.findings.length} güvenlik bulgusu tespit etti.`,
        "Güvenli düzeltmeyi uygula",
        "Raporu açık bırak",
      );

      if (action === "Güvenli düzeltmeyi uygula") {
        await applySecureFix();
      }
    }
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Bilinmeyen analiz hatası.";

    void vscode.window.showErrorMessage(`Aegis: ${message}`);
  }
}

async function applySecureFix(): Promise<void> {
  if (!lastAnalysis) {
    void vscode.window.showWarningMessage(
      "Aegis: Önce seçili kodu analiz et.",
    );
    return;
  }

  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: Düzeltmenin uygulanacağı editör bulunamadı.",
    );
    return;
  }

  if (editor.document.uri.toString() !== lastAnalysis.documentUri) {
    void vscode.window.showWarningMessage(
      "Aegis: Analiz edilen dosya şu anda açık değil.",
    );
    return;
  }

  if (editor.document.version !== lastAnalysis.documentVersion) {
    void vscode.window.showWarningMessage(
      "Aegis: Dosya analizden sonra değiştirildi. Yeniden analiz et.",
    );
    return;
  }

  const patch = findFirstPatch(lastAnalysis.response);

  if (!patch) {
    void vscode.window.showWarningMessage(
      "Aegis: Uygulanabilir bir güvenli patch bulunamadı.",
    );
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

  const decision = await vscode.window.showWarningMessage(
    "Aegis seçili kodu önerilen güvenli patch ile değiştirecek.",
    {
      modal: true,
      detail:
        "Değişiklik yalnızca açık dosyadaki analiz edilmiş seçim alanına uygulanacaktır.",
    },
    "Düzeltmeyi uygula",
    "İptal",
  );

  if (decision !== "Düzeltmeyi uygula") {
    return;
  }

  const edit = new vscode.WorkspaceEdit();

  edit.replace(
    editor.document.uri,
    lastAnalysis.selection,
    preserveIndentation(originalCode, patch),
  );

  const applied = await vscode.workspace.applyEdit(edit);

  if (!applied) {
    void vscode.window.showErrorMessage(
      "Aegis: Güvenli düzeltme uygulanamadı.",
    );
    return;
  }

  await editor.document.save();

  lastAnalysis = undefined;

  void vscode.window.showInformationMessage(
    "Aegis: Güvenli düzeltme uygulandı. Kodu yeniden analiz et.",
  );
}

async function requestAnalysis(input: {
  backendUrl: string;
  code: string;
  filename: string;
  language: string;
}): Promise<AnalyzeResponse> {
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
      throw new Error(
        `Backend HTTP ${response.status} döndürdü: ${rawBody}`,
      );
    }

    return JSON.parse(rawBody) as AnalyzeResponse;
  } catch (error: unknown) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("Analiz beş dakika sonunda zaman aşımına uğradı.");
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function showAnalysisResult(
  result: AnalyzeResponse,
): Promise<void> {
  const document = await vscode.workspace.openTextDocument({
    language: "markdown",
    content: buildMarkdownReport(result),
  });

  await vscode.window.showTextDocument(document, {
    preview: true,
    viewColumn: vscode.ViewColumn.Beside,
  });
}

function findFirstPatch(result: AnalyzeResponse): string | undefined {
  return result.findings.find(
    (finding) =>
      finding.proposed_patch &&
      finding.proposed_patch.trim().length > 0,
  )?.proposed_patch ?? undefined;
}

function preserveIndentation(
  originalCode: string,
  proposedPatch: string,
): string {
  const sourceLine =
    originalCode
      .split("\n")
      .find((line) => line.trim().length > 0) ?? "";

  const indentation = sourceLine.match(/^\s*/)?.[0] ?? "";

  return proposedPatch
    .split("\n")
    .map((line) => (line.length > 0 ? `${indentation}${line}` : line))
    .join("\n");
}

function buildMarkdownReport(result: AnalyzeResponse): string {
  const lines: string[] = [
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
    lines.push(
      "Anlamlı bir güvenlik bulgusu tespit edilmedi.",
      "",
      "> Bu sonuç kodun tamamen güvenli olduğunu garanti etmez.",
    );

    return lines.join("\n");
  }

  result.findings.forEach((finding, index) => {
    lines.push(
      `## ${index + 1}. ${finding.title}`,
      "",
      `- **Severity:** ${finding.severity.toUpperCase()}`,
      `- **Confidence:** ${Math.round(finding.confidence * 100)}%`,
      `- **CWE:** ${finding.cwe.join(", ") || "Not mapped"}`,
      `- **OWASP:** ${finding.owasp.join(", ") || "Not mapped"}`,
      "",
      "### Summary",
      "",
      finding.summary,
      "",
      "### Evidence",
      "",
    );

    finding.evidence.forEach((evidence) => {
      lines.push(`- ${evidence}`);
    });

    lines.push("", "### Scanner Evidence", "");

    finding.scanner_evidence.forEach((evidence) => {
      lines.push(
        `- **${evidence.tool} / ${evidence.rule_id}**`,
        `  - Lines: ${evidence.line_start}-${evidence.line_end}`,
        `  - Severity: ${evidence.severity}`,
        `  - ${evidence.message}`,
      );
    });

    lines.push(
      "",
      "### Recommended Fix",
      "",
      finding.recommended_fix,
      "",
    );

    if (finding.proposed_patch) {
      lines.push(
        "### Proposed Patch",
        "",
        `\`\`\`${result.language}`,
        finding.proposed_patch,
        "```",
        "",
      );
    }

    lines.push("---", "");
  });

  return lines.join("\n");
}

function normalizeLanguage(languageId: string): string {
  const supported: Record<string, string> = {
    python: "python",
    javascript: "javascript",
    javascriptreact: "javascript",
    typescript: "typescript",
    typescriptreact: "typescript",
  };

  return supported[languageId] ?? languageId;
}

export function deactivate(): void {
  lastAnalysis = undefined;
}