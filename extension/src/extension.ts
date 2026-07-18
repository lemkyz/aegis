import * as path from "node:path";
import * as vscode from "vscode";

type Severity = "info" | "low" | "medium" | "high" | "critical";
type AnalysisMode = "fast" | "deep";

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
  analysis_status?: "completed" | "skipped" | "fallback";
  result_source?: "scanner" | "ai" | "scanner_fallback";
  findings: SecurityFinding[];
}

interface LastAnalysis {
  documentUri: string;
  documentVersion: number;
  selection: vscode.Range;
  response: AnalyzeResponse;
  mode: AnalysisMode;
}

interface AnalysisInput {
  backendUrl: string;
  code: string;
  filename: string;
  language: string;
  mode: AnalysisMode;
}

let lastAnalysis: LastAnalysis | undefined;
let diagnosticCollection: vscode.DiagnosticCollection | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("aegis");

  const fastScanCommand = vscode.commands.registerCommand(
    "aegis.fastScanSelectedCode",
    async () => analyzeSelectedCode("fast"),
  );

  const fastScanCurrentFileCommand = vscode.commands.registerCommand(
    "aegis.fastScanCurrentFile",
    fastScanCurrentFile,
  );

  const deepAnalysisCommand = vscode.commands.registerCommand(
    "aegis.deepAnalyzeSelectedCode",
    async () => analyzeSelectedCode("deep"),
  );

  const applyFixCommand = vscode.commands.registerCommand(
    "aegis.applySecureFix",
    applySecureFix,
  );

  context.subscriptions.push(
    diagnosticCollection,
    fastScanCommand,
    fastScanCurrentFileCommand,
    deepAnalysisCommand,
    applyFixCommand,
  );
}

async function fastScanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: No active editor was found.",
    );
    return;
  }

  const document = editor.document;
  const code = document.getText();

  if (!code.trim()) {
    void vscode.window.showWarningMessage(
      "Aegis: The current file is empty.",
    );
    return;
  }

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
        title: "Aegis is scanning the current file",
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code,
          filename,
          language,
          mode: "fast",
        }),
    );

    lastAnalysis = {
      documentUri: document.uri.toString(),
      documentVersion: document.version,
      selection: new vscode.Range(
        document.positionAt(0),
        document.positionAt(code.length),
      ),
      response: result,
      mode: "fast",
    };

    updateDiagnostics(
      document,
      result,
      0,
    );

    await showAnalysisResult(result, "fast");

    if (result.findings.length > 0) {
      const action = await vscode.window.showWarningMessage(
        `Aegis Fast Scan found ${result.findings.length} suspicious finding(s).`,
        "Run Deep Analysis",
        "Keep Report Open",
      );

      if (action === "Run Deep Analysis") {
        editor.selection = new vscode.Selection(
          document.positionAt(0),
          document.positionAt(code.length),
        );

        await analyzeSelectedCode("deep");
      }
    }
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown analysis error.";

    void vscode.window.showErrorMessage(`Aegis: ${message}`);
  }
}

async function analyzeSelectedCode(mode: AnalysisMode): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: No active editor was found.",
    );
    return;
  }

  if (editor.selection.isEmpty) {
    void vscode.window.showWarningMessage(
      "Aegis: Select the code you want to analyze first.",
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

  const progressTitle =
    mode === "fast"
      ? "Aegis is running a fast security scan"
      : "Aegis is running deep AI analysis";

  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: progressTitle,
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code: selectedCode,
          filename,
          language,
          mode,
        }),
    );

    lastAnalysis = {
      documentUri: document.uri.toString(),
      documentVersion: document.version,
      selection,
      response: result,
      mode,
    };

    updateDiagnostics(
      document,
      result,
      selection.start.line,
    );

    await showAnalysisResult(result, mode);

    if (mode === "fast" && result.findings.length > 0) {
      const action = await vscode.window.showWarningMessage(
        `Aegis Fast Scan ${result.findings.length} suspicious finding(s).`,
        "Run Deep Analysis",
        "Keep Report Open",
      );

      if (action === "Run Deep Analysis") {
        await analyzeSelectedCode("deep");
      }

      return;
    }

    const firstPatch = findFirstPatch(result);

    if (mode === "deep" && firstPatch) {
      const action = await vscode.window.showInformationMessage(
        `Aegis ${result.findings.length} security finding(s).`,
        "Apply Secure Fix",
        "Keep Report Open",
      );

      if (action === "Apply Secure Fix") {
        await applySecureFix();
      }
    }
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown analysis error.";

    void vscode.window.showErrorMessage(`Aegis: ${message}`);
  }
}

async function applySecureFix(): Promise<void> {
  if (!lastAnalysis) {
    void vscode.window.showWarningMessage(
      "Aegis: Önce Run Deep Analysis.",
    );
    return;
  }

  if (lastAnalysis.mode !== "deep") {
    void vscode.window.showWarningMessage(
      "Aegis: Fast Scan patch üretmez. Önce Run Deep Analysis.",
    );
    return;
  }

  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: The editor for applying the fix was not found.",
    );
    return;
  }

  if (editor.document.uri.toString() !== lastAnalysis.documentUri) {
    void vscode.window.showWarningMessage(
      "Aegis: The analyzed file is not currently open.",
    );
    return;
  }

  if (editor.document.version !== lastAnalysis.documentVersion) {
    void vscode.window.showWarningMessage(
      "Aegis: The file changed after analysis. Run the analysis again.",
    );
    return;
  }

  const patch = findFirstPatch(lastAnalysis.response);

  if (!patch) {
    void vscode.window.showWarningMessage(
      "Aegis: No applicable secure patch was found.",
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
    "Aegis will replace the selected code with the proposed secure patch.",
    {
      modal: true,
      detail:
        "The change will only be applied to the analyzed selection.",
    },
    "Apply Fix",
    "Cancel",
  );

  if (decision !== "Apply Fix") {
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
      "Aegis: The secure fix could not be applied.",
    );
    return;
  }

  await editor.document.save();
  lastAnalysis = undefined;

  void vscode.window.showInformationMessage(
    "Aegis: The secure fix was applied. Verify it with Fast Scan.",
  );
}

async function requestAnalysis(
  input: AnalysisInput,
): Promise<AnalyzeResponse> {
  const controller = new AbortController();

  const timeoutMilliseconds =
    input.mode === "fast" ? 30_000 : 300_000;

  const timeout = setTimeout(
    () => controller.abort(),
    timeoutMilliseconds,
  );

  const endpoint =
    input.mode === "fast"
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
      throw new Error(
        `Backend HTTP ${response.status} döndürdü: ${rawBody}`,
      );
    }

    return JSON.parse(rawBody) as AnalyzeResponse;
  } catch (error: unknown) {
    if (error instanceof Error && error.name === "AbortError") {
      const timeoutMessage =
        input.mode === "fast"
          ? "Fast Scan timed out after 30 seconds."
          : "Deep Analysis timed out after five minutes.";

      throw new Error(timeoutMessage);
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function updateDiagnostics(
  document: vscode.TextDocument,
  result: AnalyzeResponse,
  lineOffset: number,
): void {
  if (!diagnosticCollection) {
    return;
  }

  const diagnostics: vscode.Diagnostic[] = [];

  for (const finding of result.findings) {
    const evidenceItems =
      finding.scanner_evidence.length > 0
        ? finding.scanner_evidence
        : [
            {
              line_start:
                finding.vulnerable_lines[0] ?? 1,
              line_end:
                finding.vulnerable_lines.at(-1) ?? 1,
            },
          ];

    for (const evidence of evidenceItems) {
      const startLine = clampLine(
        evidence.line_start - 1 + lineOffset,
        document,
      );

      const endLine = clampLine(
        evidence.line_end - 1 + lineOffset,
        document,
      );

      const endCharacter =
        document.lineAt(endLine).text.length;

      const range = new vscode.Range(
        new vscode.Position(startLine, 0),
        new vscode.Position(endLine, endCharacter),
      );

      const diagnostic = new vscode.Diagnostic(
        range,
        buildDiagnosticMessage(finding),
        mapDiagnosticSeverity(finding.severity),
      );

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

function buildDiagnosticMessage(
  finding: SecurityFinding,
): string {
  const metadata = [
    finding.severity.toUpperCase(),
    finding.cwe[0],
    finding.owasp[0],
  ].filter(Boolean);

  return `${metadata.join(" · ")} — ${finding.title}`;
}

function mapDiagnosticSeverity(
  severity: Severity,
): vscode.DiagnosticSeverity {
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

function clampLine(
  line: number,
  document: vscode.TextDocument,
): number {
  return Math.max(
    0,
    Math.min(line, document.lineCount - 1),
  );
}

async function showAnalysisResult(
  result: AnalyzeResponse,
  mode: AnalysisMode,
): Promise<void> {
  const document = await vscode.workspace.openTextDocument({
    language: "markdown",
    content: buildMarkdownReport(result, mode),
  });

  await vscode.window.showTextDocument(document, {
    preview: true,
    viewColumn: vscode.ViewColumn.Beside,
  });
}

function findFirstPatch(result: AnalyzeResponse): string | undefined {
  return (
    result.findings.find(
      (finding) =>
        finding.proposed_patch &&
        finding.proposed_patch.trim().length > 0,
    )?.proposed_patch ?? undefined
  );
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

function buildMarkdownReport(
  result: AnalyzeResponse,
  mode: AnalysisMode,
): string {
  const modeLabel =
    mode === "fast" ? "Fast Scan" : "Deep Analysis";

  const lines: string[] = [
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
    lines.push(
      "> Fast Scan displays local scanner evidence only. Run Deep Analysis for AI review and a proposed patch.",
      "",
    );
  }

  if (result.findings.length === 0) {
    lines.push(
      "No meaningful security finding was detected.",
      "",
      "> This result does not guarantee that the code is completely secure.",
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

      if (evidence.code) {
        lines.push(
          "",
          `\`\`\`${result.language}`,
          evidence.code,
          "\`\`\`",
        );
      }
    });

    lines.push(
      "",
      "### Recommended Fix",
      "",
      finding.recommended_fix,
      "",
    );

    if (finding.false_positive_notes.length > 0) {
      lines.push("### Notes", "");

      finding.false_positive_notes.forEach((note) => {
        lines.push(`- ${note}`);
      });

      lines.push("");
    }

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
  diagnosticCollection?.clear();
  diagnosticCollection = undefined;
  lastAnalysis = undefined;
}
