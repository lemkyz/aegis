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

interface WorkspaceFileResult {
  uri: vscode.Uri;
  relativePath: string;
  response: AnalyzeResponse;
}

interface WorkspaceScanSummary {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  filesFailed: number;
  results: WorkspaceFileResult[];
  errors: string[];
}

let lastAnalysis: LastAnalysis | undefined;
let latestWorkspaceScan: WorkspaceScanSummary | undefined;
let diagnosticCollection: vscode.DiagnosticCollection | undefined;
let securityTreeProvider: AegisSecurityTreeProvider | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("aegis");

  securityTreeProvider = new AegisSecurityTreeProvider();

  const securityTreeView =
    vscode.window.createTreeView("aegis.securityView", {
      treeDataProvider: securityTreeProvider,
      showCollapseAll: true,
    });

  const openWorkspaceFindingCommand =
    vscode.commands.registerCommand(
      "aegis.openWorkspaceFinding",
      openWorkspaceFinding,
    );

  const refreshSecurityViewCommand =
    vscode.commands.registerCommand(
      "aegis.refreshSecurityView",
      () => securityTreeProvider?.refresh(),
    );

  const fastScanCommand = vscode.commands.registerCommand(
    "aegis.fastScanSelectedCode",
    async () => analyzeSelectedCode("fast"),
  );

  const fastScanCurrentFileCommand = vscode.commands.registerCommand(
    "aegis.fastScanCurrentFile",
    fastScanCurrentFile,
  );

  const scanWorkspaceCommand = vscode.commands.registerCommand(
    "aegis.scanWorkspace",
    scanEntireWorkspace,
  );

  const deepAnalysisCommand = vscode.commands.registerCommand(
    "aegis.deepAnalyzeSelectedCode",
    async () => analyzeSelectedCode("deep"),
  );

  const applyFixCommand = vscode.commands.registerCommand(
    "aegis.applySecureFix",
    applySecureFix,
  );

  const deepAnalyzeDiagnosticCommand =
    vscode.commands.registerCommand(
      "aegis.deepAnalyzeDiagnostic",
      deepAnalyzeDiagnostic,
    );

  const openLastReportCommand =
    vscode.commands.registerCommand(
      "aegis.openLastSecurityReport",
      openLastSecurityReport,
    );

  const codeActionProvider =
    vscode.languages.registerCodeActionsProvider(
      {
        scheme: "file",
        language: "*",
      },
      new AegisCodeActionProvider(),
      {
        providedCodeActionKinds: [
          vscode.CodeActionKind.QuickFix,
        ],
      },
    );

  context.subscriptions.push(
    diagnosticCollection,
    securityTreeView,
    openWorkspaceFindingCommand,
    refreshSecurityViewCommand,
    fastScanCommand,
    fastScanCurrentFileCommand,
    scanWorkspaceCommand,
    deepAnalysisCommand,
    applyFixCommand,
    deepAnalyzeDiagnosticCommand,
    openLastReportCommand,
    codeActionProvider,
  );
}

type SecurityTreeElement =
  | SecuritySummaryTreeItem
  | SecurityFileTreeItem
  | SecurityFindingTreeItem
  | SecurityMessageTreeItem;

class AegisSecurityTreeProvider
  implements vscode.TreeDataProvider<SecurityTreeElement> {
  private readonly changeEmitter =
    new vscode.EventEmitter<
      SecurityTreeElement | undefined | null | void
    >();

  readonly onDidChangeTreeData =
    this.changeEmitter.event;

  refresh(): void {
    this.changeEmitter.fire();
  }

  getTreeItem(
    element: SecurityTreeElement,
  ): vscode.TreeItem {
    return element;
  }

  getChildren(
    element?: SecurityTreeElement,
  ): SecurityTreeElement[] {
    if (!latestWorkspaceScan) {
      return element
        ? []
        : [
            new SecurityMessageTreeItem(
              "Run Workspace Scan to populate Aegis Security.",
              "shield",
            ),
          ];
    }

    if (!element) {
      const findingCount =
        latestWorkspaceScan.results.reduce(
          (total, result) =>
            total + result.response.findings.length,
          0,
        );

      const risk = getWorkspaceRisk(
        latestWorkspaceScan,
      );

      const items: SecurityTreeElement[] = [
        new SecuritySummaryTreeItem(
          `Workspace Risk: ${risk.toUpperCase()}`,
          risk,
        ),
        new SecuritySummaryTreeItem(
          `${findingCount} finding(s) in ${latestWorkspaceScan.filesScanned} file(s)`,
          "summary",
        ),
      ];

      const vulnerableFiles =
        latestWorkspaceScan.results.filter(
          (result) =>
            result.response.findings.length > 0,
        );

      if (vulnerableFiles.length === 0) {
        items.push(
          new SecurityMessageTreeItem(
            "No findings detected",
            "pass",
          ),
        );

        return items;
      }

      items.push(
        ...vulnerableFiles.map(
          (result) =>
            new SecurityFileTreeItem(result),
        ),
      );

      return items;
    }

    if (element instanceof SecurityFileTreeItem) {
      return element.result.response.findings.map(
        (finding) =>
          new SecurityFindingTreeItem(
            element.result,
            finding,
          ),
      );
    }

    return [];
  }
}

class SecuritySummaryTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    kind: Severity | "summary" | "none",
  ) {
    super(
      label,
      vscode.TreeItemCollapsibleState.None,
    );

    this.contextValue = "aegisSecuritySummary";

    this.iconPath =
      kind === "critical" || kind === "high"
        ? new vscode.ThemeIcon("error")
        : kind === "medium"
          ? new vscode.ThemeIcon("warning")
          : kind === "low" || kind === "info"
            ? new vscode.ThemeIcon("info")
            : new vscode.ThemeIcon("shield");
  }
}

class SecurityFileTreeItem extends vscode.TreeItem {
  constructor(
    readonly result: WorkspaceFileResult,
  ) {
    super(
      result.relativePath,
      vscode.TreeItemCollapsibleState.Expanded,
    );

    this.description =
      `${result.response.findings.length} finding(s)`;

    this.tooltip =
      `${result.relativePath}\n${this.description}`;

    this.contextValue = "aegisSecurityFile";
    this.resourceUri = result.uri;
    this.iconPath = new vscode.ThemeIcon("file-code");
  }
}

class SecurityFindingTreeItem extends vscode.TreeItem {
  constructor(
    readonly result: WorkspaceFileResult,
    readonly finding: SecurityFinding,
  ) {
    super(
      finding.title,
      vscode.TreeItemCollapsibleState.None,
    );

    const cwe = finding.cwe[0] ?? "Security";
    const line =
      finding.scanner_evidence[0]?.line_start ??
      finding.vulnerable_lines[0] ??
      1;

    this.description =
      `${finding.severity.toUpperCase()} · ${cwe}`;

    this.tooltip = new vscode.MarkdownString(
      [
        `**${finding.title}**`,
        "",
        `- Severity: ${finding.severity.toUpperCase()}`,
        `- CWE: ${finding.cwe.join(", ") || "Not specified"}`,
        `- OWASP: ${finding.owasp.join(", ") || "Not specified"}`,
        `- File: ${result.relativePath}`,
        `- Line: ${line}`,
        "",
        finding.summary,
      ].join("\n"),
    );

    this.contextValue = "aegisSecurityFinding";
    this.iconPath = severityIcon(finding.severity);

    this.command = {
      command: "aegis.openWorkspaceFinding",
      title: "Open Security Finding",
      arguments: [
        result.uri,
        line,
      ],
    };
  }
}

class SecurityMessageTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    icon: "shield" | "pass",
  ) {
    super(
      label,
      vscode.TreeItemCollapsibleState.None,
    );

    this.iconPath = new vscode.ThemeIcon(
      icon === "pass"
        ? "pass-filled"
        : "shield",
    );
  }
}

function severityIcon(
  severity: Severity,
): vscode.ThemeIcon {
  switch (severity) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error");

    case "medium":
      return new vscode.ThemeIcon("warning");

    case "low":
    case "info":
    default:
      return new vscode.ThemeIcon("info");
  }
}

function getWorkspaceRisk(
  summary: WorkspaceScanSummary,
): Severity | "none" {
  const severities =
    summary.results.flatMap(
      (result) =>
        result.response.findings.map(
          (finding) => finding.severity,
        ),
    );

  if (severities.includes("critical")) {
    return "critical";
  }

  if (severities.includes("high")) {
    return "high";
  }

  if (severities.includes("medium")) {
    return "medium";
  }

  if (severities.includes("low")) {
    return "low";
  }

  if (severities.includes("info")) {
    return "info";
  }

  return "none";
}

async function openWorkspaceFinding(
  uri: vscode.Uri,
  oneBasedLine: number,
): Promise<void> {
  const document =
    await vscode.workspace.openTextDocument(uri);

  const editor =
    await vscode.window.showTextDocument(
      document,
      {
        preview: false,
        viewColumn: vscode.ViewColumn.One,
      },
    );

  const line = Math.max(
    0,
    Math.min(
      oneBasedLine - 1,
      document.lineCount - 1,
    ),
  );

  const range = document.lineAt(line).range;

  editor.selection = new vscode.Selection(
    range.start,
    range.start,
  );

  editor.revealRange(
    range,
    vscode.TextEditorRevealType.InCenter,
  );
}

async function scanEntireWorkspace(): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a workspace folder before running Workspace Scan.",
    );
    return;
  }

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  const includePattern = "**/*.{py,js,jsx,ts,tsx}";

  const excludePattern =
    "**/{.git,node_modules,.venv,venv,dist,build,out,coverage,__pycache__,.pytest_cache,.mypy_cache}/**";

  const fileUris = await vscode.workspace.findFiles(
    includePattern,
    excludePattern,
    500,
  );

  if (fileUris.length === 0) {
    void vscode.window.showInformationMessage(
      "Aegis: No supported source files were found in this workspace.",
    );
    return;
  }

  diagnosticCollection?.clear();

  const summary: WorkspaceScanSummary = {
    filesDiscovered: fileUris.length,
    filesScanned: 0,
    filesSkipped: 0,
    filesFailed: 0,
    results: [],
    errors: [],
  };

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Aegis is scanning the workspace",
      cancellable: true,
    },
    async (progress, cancellationToken) => {
      const increment = 100 / fileUris.length;

      for (const [index, uri] of fileUris.entries()) {
        if (cancellationToken.isCancellationRequested) {
          break;
        }

        const relativePath =
          vscode.workspace.asRelativePath(uri, false);

        progress.report({
          increment,
          message:
            `${index + 1}/${fileUris.length} · ${relativePath}`,
        });

        try {
          const document =
            await vscode.workspace.openTextDocument(uri);

          const code = document.getText();

          if (!code.trim()) {
            summary.filesSkipped += 1;
            continue;
          }

          if (code.length > 1_000_000) {
            summary.filesSkipped += 1;
            summary.errors.push(
              `${relativePath}: skipped because the file exceeds 1 MB.`,
            );
            continue;
          }

          const result = await requestAnalysis({
            backendUrl,
            code,
            filename: relativePath,
            language: normalizeLanguage(document.languageId),
            mode: "fast",
          });

          summary.filesScanned += 1;

          summary.results.push({
            uri,
            relativePath,
            response: result,
          });

          updateDiagnostics(
            document,
            result,
            0,
          );
        } catch (error: unknown) {
          summary.filesFailed += 1;

          const message =
            error instanceof Error
              ? error.message
              : "Unknown scan error.";

          summary.errors.push(
            `${relativePath}: ${message}`,
          );
        }
      }
    },
  );

  latestWorkspaceScan = summary;
  securityTreeProvider?.refresh();

  await showWorkspaceScanReport(summary);

  const totalFindings = summary.results.reduce(
    (total, result) =>
      total + result.response.findings.length,
    0,
  );

  if (totalFindings === 0) {
    void vscode.window.showInformationMessage(
      `Aegis Workspace Scan completed: ${summary.filesScanned} file(s) scanned and no findings detected.`,
    );
    return;
  }

  const action = await vscode.window.showWarningMessage(
    `Aegis Workspace Scan found ${totalFindings} security finding(s) across ${summary.filesScanned} scanned file(s).`,
    "Open Problems",
    "Keep Report Open",
  );

  if (action === "Open Problems") {
    await vscode.commands.executeCommand(
      "workbench.actions.view.problems",
    );
  }
}

async function showWorkspaceScanReport(
  summary: WorkspaceScanSummary,
): Promise<void> {
  const content = buildWorkspaceScanReport(summary);

  const reportDocument =
    await vscode.workspace.openTextDocument({
      language: "markdown",
      content,
    });

  await vscode.window.showTextDocument(
    reportDocument,
    {
      preview: true,
      viewColumn: vscode.ViewColumn.Beside,
    },
  );
}

function buildWorkspaceScanReport(
  summary: WorkspaceScanSummary,
): string {
  const findings = summary.results.flatMap(
    (result) =>
      result.response.findings.map((finding) => ({
        relativePath: result.relativePath,
        finding,
      })),
  );

  const countSeverity = (severity: Severity): number =>
    findings.filter(
      (item) => item.finding.severity === severity,
    ).length;

  const lines: string[] = [
    "# Aegis Workspace Security Scan",
    "",
    `- **Files discovered:** ${summary.filesDiscovered}`,
    `- **Files scanned:** ${summary.filesScanned}`,
    `- **Files skipped:** ${summary.filesSkipped}`,
    `- **Files failed:** ${summary.filesFailed}`,
    `- **Total findings:** ${findings.length}`,
    "",
    "## Severity Summary",
    "",
    `- **Critical:** ${countSeverity("critical")}`,
    `- **High:** ${countSeverity("high")}`,
    `- **Medium:** ${countSeverity("medium")}`,
    `- **Low:** ${countSeverity("low")}`,
    `- **Info:** ${countSeverity("info")}`,
    "",
  ];

  if (findings.length === 0) {
    lines.push(
      "No meaningful security finding was detected in the scanned files.",
      "",
      "> This result does not guarantee that the workspace is completely secure.",
    );
  } else {
    lines.push("## Findings", "");

    findings.forEach((item, index) => {
      const finding = item.finding;

      lines.push(
        `### ${index + 1}. ${finding.title}`,
        "",
        `- **File:** \`${item.relativePath}\``,
        `- **Severity:** ${finding.severity.toUpperCase()}`,
        `- **Confidence:** ${Math.round(finding.confidence * 100)}%`,
        `- **CWE:** ${finding.cwe.join(", ") || "Not specified"}`,
        `- **OWASP:** ${finding.owasp.join(", ") || "Not specified"}`,
        "",
        finding.summary,
        "",
      );

      if (finding.scanner_evidence.length > 0) {
        lines.push("#### Evidence", "");

        for (const evidence of finding.scanner_evidence) {
          lines.push(
            `- Lines ${evidence.line_start}-${evidence.line_end}: ${evidence.message}`,
          );
        }

        lines.push("");
      }

      lines.push("---", "");
    });
  }

  if (summary.errors.length > 0) {
    lines.push("## Scan Warnings", "");

    for (const error of summary.errors) {
      lines.push(`- ${error}`);
    }

    lines.push("");
  }

  return lines.join("\n");
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
      "Aegis: Run Deep Analysis before applying a fix.",
    );
    return;
  }

  if (lastAnalysis.mode !== "deep") {
    void vscode.window.showWarningMessage(
      "Aegis: Fast Scan does not produce patches. Run Deep Analysis first.",
    );
    return;
  }

  const analyzedState = lastAnalysis;
  const documentUri = vscode.Uri.parse(
    analyzedState.documentUri,
  );

  const document = await vscode.workspace.openTextDocument(
    documentUri,
  );

  const editor = await vscode.window.showTextDocument(
    document,
    {
      preview: false,
      viewColumn: vscode.ViewColumn.One,
    },
  );

  if (document.version !== analyzedState.documentVersion) {
    void vscode.window.showWarningMessage(
      "Aegis: The file changed after analysis. Run Deep Analysis again.",
    );
    return;
  }

  const patch = findFirstPatch(analyzedState.response);

  if (!patch) {
    void vscode.window.showWarningMessage(
      "Aegis: No applicable secure patch was found.",
    );
    return;
  }

  const originalSelectionCode = document.getText(
    analyzedState.selection,
  );

  const secureSelectionCode = preserveIndentation(
    originalSelectionCode,
    patch,
  );

  const originalDocument = await vscode.workspace.openTextDocument({
    language: document.languageId,
    content: originalSelectionCode,
  });

  const secureDocument = await vscode.workspace.openTextDocument({
    language: document.languageId,
    content: secureSelectionCode,
  });

  await vscode.commands.executeCommand(
    "vscode.diff",
    originalDocument.uri,
    secureDocument.uri,
    `Aegis Secure Fix Preview — ${path.basename(document.fileName)}`,
    {
      preview: true,
      viewColumn: vscode.ViewColumn.Beside,
    },
  );

  const decision = await vscode.window.showWarningMessage(
    "Review the Aegis secure fix in the diff editor.",
    {
      modal: true,
      detail:
        "Apply Fix replaces only the code selection analyzed by Aegis. The file will then be saved and scanned again automatically.",
    },
    "Apply Fix",
    "Cancel",
  );

  if (decision !== "Apply Fix") {
    return;
  }

  const edit = new vscode.WorkspaceEdit();

  edit.replace(
    document.uri,
    analyzedState.selection,
    secureSelectionCode,
  );

  const applied = await vscode.workspace.applyEdit(edit);

  if (!applied) {
    void vscode.window.showErrorMessage(
      "Aegis: The secure fix could not be applied.",
    );
    return;
  }

  const saved = await document.save();

  if (!saved) {
    void vscode.window.showWarningMessage(
      "Aegis: The fix was applied, but the file could not be saved.",
    );
    return;
  }

  diagnosticCollection?.delete(document.uri);
  lastAnalysis = undefined;

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  const verificationResult =
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is verifying the secure fix",
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code: document.getText(),
          filename:
            path.basename(document.fileName) || "unknown.py",
          language: normalizeLanguage(document.languageId),
          mode: "fast",
        }),
    );

  updateDiagnostics(
    document,
    verificationResult,
    0,
  );

  lastAnalysis = {
    documentUri: document.uri.toString(),
    documentVersion: document.version,
    selection: new vscode.Range(
      document.positionAt(0),
      document.positionAt(document.getText().length),
    ),
    response: verificationResult,
    mode: "fast",
  };

  await showAnalysisResult(
    verificationResult,
    "fast",
  );

  if (verificationResult.findings.length === 0) {
    void vscode.window.showInformationMessage(
      "Aegis Fix Status: VERIFIED — the vulnerability was not detected after rescanning.",
    );
    return;
  }

  void vscode.window.showWarningMessage(
    `Aegis Fix Status: STILL VULNERABLE — ${verificationResult.findings.length} finding(s) remain after rescanning.`,
    "Open Problems",
  ).then((action) => {
    if (action === "Open Problems") {
      void vscode.commands.executeCommand(
        "workbench.actions.view.problems",
      );
    }
  });

  editor.revealRange(
    analyzedState.selection,
    vscode.TextEditorRevealType.InCenter,
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

class AegisCodeActionProvider
  implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const storedDiagnostics =
      diagnosticCollection?.get(document.uri) ?? [];

    const aegisDiagnostics = [
      ...context.diagnostics,
      ...storedDiagnostics,
    ].filter(
      (diagnostic, index, diagnostics) =>
        diagnostic.source === "Aegis" &&
        diagnostics.findIndex(
          (candidate) =>
            candidate.source === diagnostic.source &&
            candidate.message === diagnostic.message &&
            candidate.range.isEqual(diagnostic.range),
        ) === index,
    );

    if (aegisDiagnostics.length === 0) {
      return [];
    }

    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of aegisDiagnostics) {
      const deepAnalysisAction = new vscode.CodeAction(
        "Aegis: Run Deep Analysis",
        vscode.CodeActionKind.QuickFix,
      );

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

    const analysisMatchesDocument =
      lastAnalysis?.documentUri === document.uri.toString();

    if (analysisMatchesDocument && lastAnalysis) {
      const openReportAction = new vscode.CodeAction(
        "Aegis: Open Security Report",
        vscode.CodeActionKind.QuickFix,
      );

      openReportAction.command = {
        command: "aegis.openLastSecurityReport",
        title: "Open Aegis Security Report",
      };

      actions.push(openReportAction);

      if (
        lastAnalysis.mode === "deep" &&
        findFirstPatch(lastAnalysis.response)
      ) {
        const applyFixAction = new vscode.CodeAction(
          "Aegis: Apply Secure Fix",
          vscode.CodeActionKind.QuickFix,
        );

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

async function deepAnalyzeDiagnostic(
  documentUri: vscode.Uri,
  range: vscode.Range,
): Promise<void> {
  const document = await vscode.workspace.openTextDocument(
    documentUri,
  );

  const editor = await vscode.window.showTextDocument(
    document,
    {
      preview: false,
      viewColumn: vscode.ViewColumn.One,
    },
  );

  editor.selection = new vscode.Selection(
    range.start,
    range.end,
  );

  editor.revealRange(
    range,
    vscode.TextEditorRevealType.InCenter,
  );

  await analyzeSelectedCode("deep");
}

async function openLastSecurityReport(): Promise<void> {
  if (!lastAnalysis) {
    void vscode.window.showWarningMessage(
      "Aegis: No previous security report is available.",
    );
    return;
  }

  await showAnalysisResult(
    lastAnalysis.response,
    lastAnalysis.mode,
  );
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
  securityTreeProvider = undefined;
  latestWorkspaceScan = undefined;
  lastAnalysis = undefined;
}
