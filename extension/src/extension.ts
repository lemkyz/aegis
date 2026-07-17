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

export function activate(context: vscode.ExtensionContext): void {
  const command = vscode.commands.registerCommand(
    "aegis.analyzeSelectedCode",
    analyzeSelectedCode,
  );

  context.subscriptions.push(command);
}

async function analyzeSelectedCode(): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: Açık bir editör bulunamadı.",
    );
    return;
  }

  const selection = editor.selection;

  if (selection.isEmpty) {
    void vscode.window.showWarningMessage(
      "Aegis: Önce analiz edilecek kodu seç.",
    );
    return;
  }

  const selectedCode = editor.document.getText(selection);
  const filename =
    editor.document.fileName.split("/").pop() ?? "unknown.py";

  const language = normalizeLanguage(editor.document.languageId);

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

    await showAnalysisResult(result);
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Bilinmeyen analiz hatası.";

    void vscode.window.showErrorMessage(`Aegis: ${message}`);
  }
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
  // Şimdilik temizlenecek kaynak bulunmuyor.
}
