import { execFile } from "node:child_process";
import * as path from "node:path";
import { promisify } from "node:util";
import * as vscode from "vscode";

const execFileAsync = promisify(execFile);

const aegisReportScheme = "aegis-report";

type AegisReportKind =
  | "analysis"
  | "workspace"
  | "git-changes"
  | "dependencies"
  | "fix-verification";

class AegisReportContentProvider
  implements vscode.TextDocumentContentProvider {
  private readonly contents =
    new Map<string, string>();

  private readonly changeEmitter =
    new vscode.EventEmitter<vscode.Uri>();

  readonly onDidChange =
    this.changeEmitter.event;

  provideTextDocumentContent(
    uri: vscode.Uri,
  ): string {
    return (
      this.contents.get(uri.toString()) ??
      "# Aegis Report\n\nNo report content is available."
    );
  }

  update(
    uri: vscode.Uri,
    content: string,
  ): void {
    this.contents.set(
      uri.toString(),
      content,
    );

    this.changeEmitter.fire(uri);
  }

  dispose(): void {
    this.contents.clear();
    this.changeEmitter.dispose();
  }
}

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

type VerificationStatus =
  | "passed"
  | "failed"
  | "skipped";

interface VerificationCheckResult {
  name: string;
  status: VerificationStatus;
  command?: string;
  details: string;
}

interface SecurityVerificationDelta {
  targetRuleIds: string[];
  remainingTargetFindings: SecurityFinding[];
  introducedFindings: SecurityFinding[];
  unchangedFindings: SecurityFinding[];
}

interface ProjectVerificationSuite {
  syntax: VerificationCheckResult;
  tests: VerificationCheckResult;
  build: VerificationCheckResult;
}

interface FixVerificationReportInput {
  fileName: string;
  status: "VERIFIED" | "FAILED";
  projectVerification: ProjectVerificationSuite;
  targetResolved?: boolean;
  regressionFree?: boolean;
  securityDelta?: SecurityVerificationDelta;
  rollbackStatus?: string;
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

type DependencyEcosystem = "PyPI" | "npm";

type DependencySeverity =
  | "unknown"
  | "low"
  | "medium"
  | "high"
  | "critical";

interface DependencyPackage {
  name: string;
  version: string;
  ecosystem: DependencyEcosystem;
  manifest: string;
  direct: boolean;
}

interface DependencyVulnerability {
  id: string;
  aliases: string[];
  package_name: string;
  installed_version: string;
  ecosystem: string;
  manifest: string;
  direct: boolean;
  summary: string;
  details: string;
  severity: DependencySeverity;
  fixed_versions: string[];
  references: string[];
  published: string | null;
  modified: string | null;
}

interface DependencyScanResponse {
  scanner: string;
  packages_scanned: number;
  vulnerable_packages: number;
  vulnerabilities: DependencyVulnerability[];
}

let lastAnalysis: LastAnalysis | undefined;
let latestWorkspaceScan: WorkspaceScanSummary | undefined;
let reportContentProvider:
  AegisReportContentProvider | undefined;
let latestDependencyScan: DependencyScanResponse | undefined;
let diagnosticCollection: vscode.DiagnosticCollection | undefined;
let securityTreeProvider: AegisSecurityTreeProvider | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("aegis");

  reportContentProvider =
    new AegisReportContentProvider();

  const reportProviderRegistration =
    vscode.workspace.registerTextDocumentContentProvider(
      aegisReportScheme,
      reportContentProvider,
    );

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

  const openDependencyManifestCommand =
    vscode.commands.registerCommand(
      "aegis.openDependencyManifest",
      openDependencyManifest,
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

  const scanDependenciesCommand =
    vscode.commands.registerCommand(
      "aegis.scanDependencies",
      scanDependencies,
    );

  const scanUncommittedChangesCommand =
    vscode.commands.registerCommand(
      "aegis.scanUncommittedChanges",
      () => scanGitChanges("uncommitted"),
    );

  const scanStagedChangesCommand =
    vscode.commands.registerCommand(
      "aegis.scanStagedChanges",
      () => scanGitChanges("staged"),
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
    reportContentProvider,
    reportProviderRegistration,
    securityTreeView,
    openWorkspaceFindingCommand,
    openDependencyManifestCommand,
    refreshSecurityViewCommand,
    fastScanCommand,
    fastScanCurrentFileCommand,
    scanWorkspaceCommand,
    scanDependenciesCommand,
    scanUncommittedChangesCommand,
    scanStagedChangesCommand,
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
  | SecurityMessageTreeItem
  | DependencyRootTreeItem
  | DependencyPackageTreeItem
  | DependencyVulnerabilityTreeItem;

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
    if (!element) {
      const items: SecurityTreeElement[] = [];

      if (latestWorkspaceScan) {
        const findingCount =
          latestWorkspaceScan.results.reduce(
            (total, result) =>
              total + result.response.findings.length,
            0,
          );

        const risk = getWorkspaceRisk(
          latestWorkspaceScan,
        );

        items.push(
          new SecuritySummaryTreeItem(
            `Workspace Risk: ${risk.toUpperCase()}`,
            risk,
          ),
          new SecuritySummaryTreeItem(
            `${findingCount} code finding(s) in ${latestWorkspaceScan.filesScanned} file(s)`,
            "summary",
          ),
        );

        const vulnerableFiles =
          latestWorkspaceScan.results.filter(
            (result) =>
              result.response.findings.length > 0,
          );

        items.push(
          ...vulnerableFiles.map(
            (result) =>
              new SecurityFileTreeItem(result),
          ),
        );
      }

      if (latestDependencyScan) {
        items.push(
          new DependencyRootTreeItem(
            latestDependencyScan,
          ),
        );
      }

      if (items.length === 0) {
        return [
          new SecurityMessageTreeItem(
            "Run Workspace Scan or Dependency Scan.",
            "shield",
          ),
        ];
      }

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

    if (element instanceof DependencyRootTreeItem) {
      const grouped =
        groupDependencyVulnerabilities(
          element.result.vulnerabilities,
        );

      return Array.from(grouped.entries()).map(
        ([packageKey, vulnerabilities]) =>
          new DependencyPackageTreeItem(
            packageKey,
            vulnerabilities,
          ),
      );
    }

    if (element instanceof DependencyPackageTreeItem) {
      return element.vulnerabilities.map(
        (vulnerability) =>
          new DependencyVulnerabilityTreeItem(
            vulnerability,
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

class DependencyRootTreeItem extends vscode.TreeItem {
  constructor(
    readonly result: DependencyScanResponse,
  ) {
    super(
      "Supply Chain Risks",
      vscode.TreeItemCollapsibleState.Expanded,
    );

    this.description =
      `${result.vulnerable_packages} package(s) · ${result.vulnerabilities.length} advisory(s)`;

    this.tooltip =
      `${result.packages_scanned} package version(s) checked with ${result.scanner.toUpperCase()}`;

    this.contextValue = "aegisDependencyRoot";
    this.iconPath = new vscode.ThemeIcon(
      result.vulnerabilities.length > 0
        ? "package"
        : "pass-filled",
    );
  }
}

class DependencyPackageTreeItem extends vscode.TreeItem {
  constructor(
    readonly packageKey: string,
    readonly vulnerabilities:
      DependencyVulnerability[],
  ) {
    const first = vulnerabilities[0];

    super(
      `${first.package_name} ${first.installed_version}`,
      vscode.TreeItemCollapsibleState.Expanded,
    );

    const strongest =
      strongestDependencySeverity(
        vulnerabilities,
      );

    this.description =
      `${strongest.toUpperCase()} · ${vulnerabilities.length} advisory(s)`;

    this.tooltip = new vscode.MarkdownString(
      [
        `**${first.package_name} ${first.installed_version}**`,
        "",
        `- Ecosystem: ${first.ecosystem}`,
        `- Manifest: ${first.manifest}`,
        `- Direct dependency: ${first.direct ? "YES" : "NO"}`,
        `- Advisory records: ${vulnerabilities.length}`,
      ].join("\n"),
    );

    this.contextValue = "aegisDependencyPackage";
    this.iconPath = dependencySeverityIcon(strongest);

    this.command = {
      command: "aegis.openDependencyManifest",
      title: "Open Dependency Manifest",
      arguments: [first.manifest],
    };
  }
}

class DependencyVulnerabilityTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly vulnerability:
      DependencyVulnerability,
  ) {
    super(
      vulnerability.id,
      vscode.TreeItemCollapsibleState.None,
    );

    const fixed =
      vulnerability.fixed_versions[0];

    this.description = fixed
      ? `${vulnerability.severity.toUpperCase()} · fix ${fixed}`
      : vulnerability.severity.toUpperCase();

    this.tooltip = new vscode.MarkdownString(
      [
        `**${vulnerability.summary}**`,
        "",
        `- Advisory: ${vulnerability.id}`,
        `- Severity: ${vulnerability.severity.toUpperCase()}`,
        `- Package: ${vulnerability.package_name} ${vulnerability.installed_version}`,
        `- Fixed versions: ${vulnerability.fixed_versions.join(", ") || "Not specified"}`,
        `- Manifest: ${vulnerability.manifest}`,
      ].join("\n"),
    );

    this.contextValue =
      "aegisDependencyVulnerability";

    this.iconPath = dependencySeverityIcon(
      vulnerability.severity,
    );

    this.command = {
      command: "aegis.openDependencyManifest",
      title: "Open Dependency Manifest",
      arguments: [vulnerability.manifest],
    };
  }
}

function groupDependencyVulnerabilities(
  vulnerabilities: DependencyVulnerability[],
): Map<string, DependencyVulnerability[]> {
  const grouped =
    new Map<string, DependencyVulnerability[]>();

  for (const vulnerability of vulnerabilities) {
    const key = [
      vulnerability.ecosystem,
      vulnerability.package_name.toLowerCase(),
      vulnerability.installed_version,
    ].join(":");

    const packageItems = grouped.get(key) ?? [];
    packageItems.push(vulnerability);
    grouped.set(key, packageItems);
  }

  return new Map(
    Array.from(grouped.entries()).sort(
      ([left], [right]) =>
        left.localeCompare(right),
    ),
  );
}

function strongestDependencySeverity(
  vulnerabilities: DependencyVulnerability[],
): DependencySeverity {
  const rank: Record<DependencySeverity, number> = {
    unknown: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };

  return vulnerabilities.reduce<DependencySeverity>(
    (strongest, vulnerability) =>
      rank[vulnerability.severity] >
      rank[strongest]
        ? vulnerability.severity
        : strongest,
    "unknown",
  );
}

function dependencySeverityIcon(
  severity: DependencySeverity,
): vscode.ThemeIcon {
  switch (severity) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error");

    case "medium":
      return new vscode.ThemeIcon("warning");

    case "low":
      return new vscode.ThemeIcon("info");

    case "unknown":
    default:
      return new vscode.ThemeIcon(
        "question",
      );
  }
}

async function openDependencyManifest(
  manifest: string,
): Promise<void> {
  const normalized =
    manifest.replaceAll("\\", "/");

  const matches = await vscode.workspace.findFiles(
    `**/${normalized}`,
    "**/{.git,node_modules,.venv,venv,dist,build,out}/**",
    10,
  );

  const fallbackMatches =
    matches.length > 0
      ? matches
      : await vscode.workspace.findFiles(
          `**/${path.basename(normalized)}`,
          "**/{.git,node_modules,.venv,venv,dist,build,out}/**",
          10,
        );

  if (fallbackMatches.length === 0) {
    void vscode.window.showWarningMessage(
      `Aegis: Could not locate dependency manifest ${manifest}.`,
    );
    return;
  }

  const document =
    await vscode.workspace.openTextDocument(
      fallbackMatches[0],
    );

  await vscode.window.showTextDocument(
    document,
    {
      preview: false,
      viewColumn: vscode.ViewColumn.One,
    },
  );
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

async function scanDependencies(): Promise<void> {
  const workspaceFolders =
    vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a workspace before scanning dependencies.",
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

  try {
    const packages = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is discovering dependencies",
        cancellable: false,
      },
      async () => discoverWorkspaceDependencies(),
    );

    if (packages.length === 0) {
      void vscode.window.showInformationMessage(
        "Aegis: No exact dependency versions were found. Use pinned requirements or a package lockfile.",
      );
      return;
    }

    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title:
          `Aegis is checking ${packages.length} dependency version(s)`,
        cancellable: false,
      },
      async () =>
        requestDependencyScan(
          backendUrl,
          packages,
        ),
    );

    latestDependencyScan = result;
    securityTreeProvider?.refresh();

    await showDependencyScanReport(
      result,
      packages,
    );

    if (result.vulnerabilities.length === 0) {
      void vscode.window.showInformationMessage(
        `Aegis Dependency Scan completed: ${result.packages_scanned} package(s) checked and no known vulnerabilities detected.`,
      );
      return;
    }

    void vscode.window.showWarningMessage(
      `Aegis found ${result.vulnerabilities.length} known vulnerability record(s) across ${result.vulnerable_packages} package(s).`,
      "Keep Report Open",
    );
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown dependency scan error.";

    void vscode.window.showErrorMessage(
      `Aegis Dependency Scan failed: ${message}`,
    );
  }
}

async function discoverWorkspaceDependencies():
  Promise<DependencyPackage[]> {
  const manifestUris = await vscode.workspace.findFiles(
    "**/{requirements.txt,package.json,package-lock.json}",
    "**/{.git,node_modules,.venv,venv,dist,build,out,coverage}/**",
    100,
  );

  const packages: DependencyPackage[] = [];

  for (const uri of manifestUris) {
    const document =
      await vscode.workspace.openTextDocument(uri);

    const filename = path.basename(uri.fsPath);
    const relativePath =
      vscode.workspace.asRelativePath(uri, false);
    const content = document.getText();

    if (filename === "requirements.txt") {
      packages.push(
        ...parseRequirementsTxt(
          content,
          relativePath,
        ),
      );

      continue;
    }

    if (filename === "package-lock.json") {
      packages.push(
        ...parsePackageLock(
          content,
          relativePath,
        ),
      );

      continue;
    }

    if (filename === "package.json") {
      packages.push(
        ...parsePackageJson(
          content,
          relativePath,
        ),
      );
    }
  }

  return deduplicateDependencies(packages);
}

function parseRequirementsTxt(
  content: string,
  manifest: string,
): DependencyPackage[] {
  const packages: DependencyPackage[] = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (
      !line ||
      line.startsWith("#") ||
      line.startsWith("-")
    ) {
      continue;
    }

    const withoutComment =
      line.split(/\s+#/, 1)[0]?.trim() ?? "";

    const match = withoutComment.match(
      /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9_.+!-]+)$/,
    );

    if (!match) {
      continue;
    }

    packages.push({
      name: match[1],
      version: match[2],
      ecosystem: "PyPI",
      manifest,
      direct: true,
    });
  }

  return packages;
}

function parsePackageJson(
  content: string,
  manifest: string,
): DependencyPackage[] {
  let payload: unknown;

  try {
    payload = JSON.parse(content);
  } catch {
    throw new Error(
      `${manifest} contains invalid JSON.`,
    );
  }

  if (!isRecord(payload)) {
    return [];
  }

  const packages: DependencyPackage[] = [];

  for (const field of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
  ]) {
    const dependencies = payload[field];

    if (!isRecord(dependencies)) {
      continue;
    }

    for (const [name, rawVersion] of Object.entries(
      dependencies,
    )) {
      if (typeof rawVersion !== "string") {
        continue;
      }

      const version = normalizeExactNpmVersion(
        rawVersion,
      );

      if (!version) {
        continue;
      }

      packages.push({
        name,
        version,
        ecosystem: "npm",
        manifest,
        direct: true,
      });
    }
  }

  return packages;
}

function parsePackageLock(
  content: string,
  manifest: string,
): DependencyPackage[] {
  let payload: unknown;

  try {
    payload = JSON.parse(content);
  } catch {
    throw new Error(
      `${manifest} contains invalid JSON.`,
    );
  }

  if (!isRecord(payload)) {
    return [];
  }

  const packages: DependencyPackage[] = [];
  const lockPackages = payload.packages;

  if (isRecord(lockPackages)) {
    for (const [packagePath, rawMetadata] of Object.entries(
      lockPackages,
    )) {
      if (
        !packagePath.startsWith("node_modules/") ||
        !isRecord(rawMetadata)
      ) {
        continue;
      }

      const name = packagePath.replace(
        /^node_modules\//,
        "",
      );

      const version = rawMetadata.version;

      if (
        !name ||
        typeof version !== "string" ||
        !isExactVersion(version)
      ) {
        continue;
      }

      packages.push({
        name,
        version,
        ecosystem: "npm",
        manifest,
        direct: false,
      });
    }

    return packages;
  }

  const dependencies = payload.dependencies;

  if (isRecord(dependencies)) {
    collectLegacyPackageLockDependencies(
      dependencies,
      manifest,
      packages,
    );
  }

  return packages;
}

function collectLegacyPackageLockDependencies(
  dependencies: Record<string, unknown>,
  manifest: string,
  output: DependencyPackage[],
): void {
  for (const [name, rawMetadata] of Object.entries(
    dependencies,
  )) {
    if (!isRecord(rawMetadata)) {
      continue;
    }

    const version = rawMetadata.version;

    if (
      typeof version === "string" &&
      isExactVersion(version)
    ) {
      output.push({
        name,
        version,
        ecosystem: "npm",
        manifest,
        direct: false,
      });
    }

    const nestedDependencies =
      rawMetadata.dependencies;

    if (isRecord(nestedDependencies)) {
      collectLegacyPackageLockDependencies(
        nestedDependencies,
        manifest,
        output,
      );
    }
  }
}

function normalizeExactNpmVersion(
  rawVersion: string,
): string | undefined {
  const trimmed = rawVersion.trim();

  if (
    trimmed.startsWith("workspace:") ||
    trimmed.startsWith("file:") ||
    trimmed.startsWith("git+") ||
    trimmed.startsWith("http:") ||
    trimmed.startsWith("https:")
  ) {
    return undefined;
  }

  const normalized = trimmed.startsWith("=")
    ? trimmed.slice(1)
    : trimmed;

  return isExactVersion(normalized)
    ? normalized
    : undefined;
}

function isExactVersion(
  value: string,
): boolean {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(
    value,
  );
}

function deduplicateDependencies(
  packages: DependencyPackage[],
): DependencyPackage[] {
  const deduplicated =
    new Map<string, DependencyPackage>();

  for (const packageItem of packages) {
    const key = [
      packageItem.ecosystem,
      packageItem.name.toLowerCase(),
      packageItem.version,
    ].join(":");

    const existing = deduplicated.get(key);

    if (!existing || packageItem.direct) {
      deduplicated.set(
        key,
        packageItem,
      );
    }
  }

  return Array.from(
    deduplicated.values(),
  ).sort((left, right) =>
    `${left.ecosystem}:${left.name}`.localeCompare(
      `${right.ecosystem}:${right.name}`,
    ),
  );
}

function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

async function requestDependencyScan(
  backendUrl: string,
  packages: DependencyPackage[],
): Promise<DependencyScanResponse> {
  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    180_000,
  );

  try {
    const response = await fetch(
      `${backendUrl}/v1/dependencies/scan`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          packages,
        }),
        signal: controller.signal,
      },
    );

    const rawBody = await response.text();

    if (!response.ok) {
      let detail = rawBody;

      try {
        const payload = JSON.parse(rawBody) as {
          detail?: string;
        };

        detail = payload.detail ?? rawBody;
      } catch {
        // Preserve raw response body.
      }

      throw new Error(
        `Backend returned HTTP ${response.status}: ${detail}`,
      );
    }

    return JSON.parse(
      rawBody,
    ) as DependencyScanResponse;
  } catch (error: unknown) {
    if (
      error instanceof Error &&
      error.name === "AbortError"
    ) {
      throw new Error(
        "Dependency Scan timed out after three minutes.",
      );
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function aegisReportUri(
  kind: AegisReportKind,
): vscode.Uri {
  return vscode.Uri.from({
    scheme: aegisReportScheme,
    path: `/${kind}.md`,
  });
}

async function showReusableAegisReport(
  kind: AegisReportKind,
  content: string,
  viewColumn:
    vscode.ViewColumn =
      vscode.ViewColumn.Beside,
): Promise<void> {
  if (!reportContentProvider) {
    throw new Error(
      "Aegis report provider is unavailable.",
    );
  }

  const uri = aegisReportUri(kind);

  reportContentProvider.update(
    uri,
    content,
  );

  const document =
    await vscode.workspace.openTextDocument(uri);

  await vscode.languages.setTextDocumentLanguage(
    document,
    "markdown",
  );

  await vscode.window.showTextDocument(
    document,
    {
      preview: true,
      preserveFocus: false,
      viewColumn,
    },
  );
}

async function showDependencyScanReport(
  result: DependencyScanResponse,
  packages: DependencyPackage[],
): Promise<void> {
  const report = buildDependencyScanReport(
    result,
    packages,
  );

  await showReusableAegisReport(
    "dependencies",
    report,
  );
}

function buildDependencyScanReport(
  result: DependencyScanResponse,
  packages: DependencyPackage[],
): string {
  const severityOrder:
    Record<DependencySeverity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      unknown: 4,
    };

  const vulnerabilities = [
    ...result.vulnerabilities,
  ].sort((left, right) => {
    const severityDifference =
      severityOrder[left.severity] -
      severityOrder[right.severity];

    if (severityDifference !== 0) {
      return severityDifference;
    }

    return left.package_name.localeCompare(
      right.package_name,
    );
  });

  const countSeverity = (
    severity: DependencySeverity,
  ): number =>
    vulnerabilities.filter(
      (item) => item.severity === severity,
    ).length;

  const manifests = Array.from(
    new Set(
      packages.map(
        (packageItem) => packageItem.manifest,
      ),
    ),
  );

  const lines: string[] = [
    "# Aegis Dependency Security Scan",
    "",
    `- **Scanner:** ${result.scanner.toUpperCase()}`,
    `- **Packages checked:** ${result.packages_scanned}`,
    `- **Vulnerable packages:** ${result.vulnerable_packages}`,
    `- **Vulnerability records:** ${vulnerabilities.length}`,
    `- **Manifests:** ${manifests.length}`,
    "",
    "## Severity Summary",
    "",
    `- **Critical:** ${countSeverity("critical")}`,
    `- **High:** ${countSeverity("high")}`,
    `- **Medium:** ${countSeverity("medium")}`,
    `- **Low:** ${countSeverity("low")}`,
    `- **Unknown:** ${countSeverity("unknown")}`,
    "",
  ];

  if (vulnerabilities.length === 0) {
    lines.push(
      "No known dependency vulnerability was found for the exact versions checked.",
      "",
      "> This result depends on available advisory data and does not guarantee that every dependency is secure.",
    );

    return lines.join("\n");
  }

  lines.push("## Vulnerabilities", "");

  vulnerabilities.forEach(
    (vulnerability, index) => {
      const aliases =
        vulnerability.aliases.length > 0
          ? vulnerability.aliases.join(", ")
          : "None";

      const fixedVersions =
        vulnerability.fixed_versions.length > 0
          ? vulnerability.fixed_versions.join(", ")
          : "No fixed version specified";

      lines.push(
        `### ${index + 1}. ${vulnerability.package_name} ${vulnerability.installed_version}`,
        "",
        `- **Severity:** ${vulnerability.severity.toUpperCase()}`,
        `- **Advisory:** ${vulnerability.id}`,
        `- **Aliases:** ${aliases}`,
        `- **Ecosystem:** ${vulnerability.ecosystem}`,
        `- **Manifest:** \`${vulnerability.manifest}\``,
        `- **Direct dependency:** ${vulnerability.direct ? "YES" : "NO"}`,
        `- **Fixed version(s):** ${fixedVersions}`,
        "",
        vulnerability.summary ||
          "Known dependency vulnerability.",
        "",
      );

      if (vulnerability.references.length > 0) {
        lines.push("#### References", "");

        for (const reference of
          vulnerability.references.slice(0, 5)) {
          lines.push(`- ${reference}`);
        }

        lines.push("");
      }

      lines.push("---", "");
    },
  );

  return lines.join("\n");
}

type GitScanMode = "uncommitted" | "staged";

async function scanGitChanges(
  mode: GitScanMode,
): Promise<void> {
  const workspaceFolder =
    vscode.workspace.workspaceFolders?.[0];

  if (!workspaceFolder) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a Git workspace before scanning changes.",
    );
    return;
  }

  const workspacePath = workspaceFolder.uri.fsPath;

  const repositoryRoot = await findGitRepositoryRoot(
    workspacePath,
  );

  if (!repositoryRoot) {
    void vscode.window.showWarningMessage(
      "Aegis: The current workspace is not inside a Git repository.",
    );
    return;
  }

  let relativePaths: string[];

  try {
    relativePaths = await getGitChangedFiles(
      repositoryRoot,
      mode,
    );
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown Git error.";

    void vscode.window.showErrorMessage(
      `Aegis: Git change discovery failed: ${message}`,
    );
    return;
  }

  const supportedPaths = relativePaths.filter(
    isSupportedSourcePath,
  );

  if (supportedPaths.length === 0) {
    const label =
      mode === "staged"
        ? "staged"
        : "uncommitted";

    void vscode.window.showInformationMessage(
      `Aegis: No supported ${label} source files were found.`,
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

  const summary: WorkspaceScanSummary = {
    filesDiscovered: supportedPaths.length,
    filesScanned: 0,
    filesSkipped: 0,
    filesFailed: 0,
    results: [],
    errors: [],
  };

  diagnosticCollection?.clear();

  const label =
    mode === "staged"
      ? "staged changes"
      : "uncommitted changes";

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Aegis is scanning ${label}`,
      cancellable: true,
    },
    async (progress, cancellationToken) => {
      const increment = 100 / supportedPaths.length;

      for (
        const [index, relativePath] of
        supportedPaths.entries()
      ) {
        if (cancellationToken.isCancellationRequested) {
          break;
        }

        progress.report({
          increment,
          message:
            `${index + 1}/${supportedPaths.length} · ${relativePath}`,
        });

        const uri = vscode.Uri.file(
          path.join(repositoryRoot, relativePath),
        );

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
            language: normalizeLanguage(
              document.languageId,
            ),
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

  await showGitChangesReport(
    summary,
    mode,
  );

  const totalFindings = summary.results.reduce(
    (total, result) =>
      total + result.response.findings.length,
    0,
  );

  if (totalFindings === 0) {
    void vscode.window.showInformationMessage(
      `Aegis found no security findings in ${summary.filesScanned} scanned ${label} file(s).`,
    );
    return;
  }

  const action = await vscode.window.showWarningMessage(
    `Aegis found ${totalFindings} security finding(s) in ${label}.`,
    "Open Problems",
    "Keep Report Open",
  );

  if (action === "Open Problems") {
    await vscode.commands.executeCommand(
      "workbench.actions.view.problems",
    );
  }
}

async function findGitRepositoryRoot(
  workspacePath: string,
): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["rev-parse", "--show-toplevel"],
      {
        cwd: workspacePath,
        timeout: 10_000,
      },
    );

    const repositoryRoot = stdout.trim();

    return repositoryRoot || undefined;
  } catch {
    return undefined;
  }
}

async function getGitChangedFiles(
  workspacePath: string,
  mode: GitScanMode,
): Promise<string[]> {
  if (mode === "staged") {
    const { stdout } = await execFileAsync(
      "git",
      [
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACMR",
      ],
      {
        cwd: workspacePath,
        timeout: 15_000,
      },
    );

    return uniqueNonEmptyLines(stdout);
  }

  const [
    trackedResult,
    untrackedResult,
  ] = await Promise.all([
    execFileAsync(
      "git",
      [
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        "HEAD",
      ],
      {
        cwd: workspacePath,
        timeout: 15_000,
      },
    ),
    execFileAsync(
      "git",
      [
        "ls-files",
        "--others",
        "--exclude-standard",
      ],
      {
        cwd: workspacePath,
        timeout: 15_000,
      },
    ),
  ]);

  return Array.from(
    new Set([
      ...uniqueNonEmptyLines(
        trackedResult.stdout,
      ),
      ...uniqueNonEmptyLines(
        untrackedResult.stdout,
      ),
    ]),
  ).sort();
}

function uniqueNonEmptyLines(
  output: string,
): string[] {
  return Array.from(
    new Set(
      output
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  );
}

function isSupportedSourcePath(
  relativePath: string,
): boolean {
  return /\.(py|js|jsx|ts|tsx)$/i.test(
    relativePath,
  );
}

async function showGitChangesReport(
  summary: WorkspaceScanSummary,
  mode: GitScanMode,
): Promise<void> {
  const baseReport =
    buildWorkspaceScanReport(summary);

  const heading =
    mode === "staged"
      ? "# Aegis Staged Changes Security Scan"
      : "# Aegis Uncommitted Changes Security Scan";

  const content = baseReport.replace(
    "# Aegis Workspace Security Scan",
    heading,
  );

  await showReusableAegisReport(
    "git-changes",
    content,
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

  await showReusableAegisReport(
    "workspace",
    content,
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

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  const baselineResult =
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is recording the security baseline",
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

  const originalSelectionCode = document.getText(
    analyzedState.selection,
  );

  const originalSelectionStartOffset =
    document.offsetAt(analyzedState.selection.start);

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

  const projectVerification =
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is verifying syntax, tests, and build",
        cancellable: false,
      },
      async () =>
        verifyPatchedProject(document),
    );

  const failedProjectChecks = [
    projectVerification.syntax,
    projectVerification.tests,
    projectVerification.build,
  ].filter(
    (check) => check.status === "failed",
  );

  if (failedProjectChecks.length > 0) {
    const patchedSelection = new vscode.Range(
      document.positionAt(
        originalSelectionStartOffset,
      ),
      document.positionAt(
        originalSelectionStartOffset +
          secureSelectionCode.length,
      ),
    );

    const rollbackEdit = new vscode.WorkspaceEdit();

    rollbackEdit.replace(
      document.uri,
      patchedSelection,
      originalSelectionCode,
    );

    const rolledBack =
      await vscode.workspace.applyEdit(
        rollbackEdit,
      );

    if (rolledBack) {
      await document.save();
    }

    diagnosticCollection?.delete(document.uri);
    lastAnalysis = undefined;

    const rollbackStatus = rolledBack
      ? "The original code was restored automatically."
      : "Automatic rollback failed. Review the file immediately.";

    const failedCheckSummary =
      failedProjectChecks
        .map(
          (check) =>
            `${check.name}: ${check.details}`,
        )
        .join(" | ");

    await showFixVerificationReport({
      fileName: document.fileName,
      status: "FAILED",
      projectVerification,
      rollbackStatus,
    });

    void vscode.window.showErrorMessage(
      [
        "Aegis Fix Status: FAILED — project verification did not pass.",
        failedCheckSummary,
        rollbackStatus,
      ].join(" "),
      "Open File",
    ).then((action) => {
      if (action === "Open File") {
        void vscode.window.showTextDocument(
          document,
          {
            preview: false,
            viewColumn: vscode.ViewColumn.One,
          },
        );
      }
    });

    return;
  }

  diagnosticCollection?.delete(document.uri);
  lastAnalysis = undefined;

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

  const securityDelta =
    compareSecurityVerificationResults(
      analyzedState.response,
      baselineResult,
      verificationResult,
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

  const verificationMessages = [
    formatVerificationCheck(
      projectVerification.syntax,
    ),
    formatVerificationCheck(
      projectVerification.tests,
    ),
    formatVerificationCheck(
      projectVerification.build,
    ),
  ];

  const targetResolved =
    securityDelta.remainingTargetFindings.length === 0;

  const regressionFree =
    securityDelta.introducedFindings.length === 0;

  await showFixVerificationReport({
    fileName: document.fileName,
    status:
      targetResolved && regressionFree
        ? "VERIFIED"
        : "FAILED",
    projectVerification,
    targetResolved,
    regressionFree,
    securityDelta,
  });

  if (targetResolved && regressionFree) {
    const existingMessage =
      securityDelta.unchangedFindings.length > 0
        ? `${securityDelta.unchangedFindings.length} unrelated pre-existing finding(s) remain.`
        : "No pre-existing findings remain.";

    void vscode.window.showInformationMessage(
      [
        "Aegis Fix Status: VERIFIED.",
        ...verificationMessages,
        "Target vulnerability: RESOLVED.",
        "Regression check: PASSED.",
        existingMessage,
      ].join(" "),
    );

    return;
  }

  const failureReasons: string[] = [];

  if (!targetResolved) {
    failureReasons.push(
      `${securityDelta.remainingTargetFindings.length} target finding(s) remain`,
    );
  }

  if (!regressionFree) {
    failureReasons.push(
      `${securityDelta.introducedFindings.length} new finding(s) were introduced`,
    );
  }

  void vscode.window.showWarningMessage(
    `Aegis Fix Status: FAILED — ${failureReasons.join("; ")}.`,
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

async function showFixVerificationReport(
  input: FixVerificationReportInput,
): Promise<void> {
  await showReusableAegisReport(
    "fix-verification",
    buildFixVerificationReport(input),
  );
}

function buildFixVerificationReport(
  input: FixVerificationReportInput,
): string {
  const checks = [
    input.projectVerification.syntax,
    input.projectVerification.tests,
    input.projectVerification.build,
  ];

  const checkSections = checks
    .map(buildVerificationCheckSection)
    .join("\n\n");

  const targetStatus =
    input.targetResolved === undefined
      ? "NOT RUN"
      : input.targetResolved
        ? "PASSED"
        : "FAILED";

  const regressionStatus =
    input.regressionFree === undefined
      ? "NOT RUN"
      : input.regressionFree
        ? "PASSED"
        : "FAILED";

  const remainingTargetFindings =
    input.securityDelta?.remainingTargetFindings ?? [];

  const introducedFindings =
    input.securityDelta?.introducedFindings ?? [];

  const unchangedFindings =
    input.securityDelta?.unchangedFindings ?? [];

  const securitySections = [
    buildFindingListSection(
      "Remaining Target Findings",
      remainingTargetFindings,
    ),
    buildFindingListSection(
      "Newly Introduced Findings",
      introducedFindings,
    ),
    buildFindingListSection(
      "Unchanged Pre-existing Findings",
      unchangedFindings,
    ),
  ].join("\n\n");

  const rollbackSection =
    input.rollbackStatus
      ? [
          "## Rollback",
          "",
          input.rollbackStatus,
        ].join("\n")
      : [
          "## Rollback",
          "",
          "Not required.",
        ].join("\n");

  return [
    "# Aegis Fix Verification",
    "",
    `- **File:** ${path.basename(input.fileName)}`,
    `- **Final Status:** ${input.status}`,
    `- **Target Vulnerability:** ${targetStatus}`,
    `- **Regression Check:** ${regressionStatus}`,
    `- **Generated:** ${new Date().toISOString()}`,
    "",
    "> VERIFIED means the configured syntax, project, and security checks completed without a detected failure. Skipped checks are shown explicitly.",
    "",
    "## Project Verification",
    "",
    checkSections,
    "",
    "## Security Verification",
    "",
    `- **Target findings remaining:** ${remainingTargetFindings.length}`,
    `- **New findings introduced:** ${introducedFindings.length}`,
    `- **Unchanged findings:** ${unchangedFindings.length}`,
    "",
    securitySections,
    "",
    rollbackSection,
  ].join("\n");
}

function buildVerificationCheckSection(
  check: VerificationCheckResult,
): string {
  const lines = [
    `### ${check.name}`,
    "",
    `- **Status:** ${check.status.toUpperCase()}`,
  ];

  if (check.command) {
    lines.push(
      `- **Command:** \`${escapeMarkdownInlineCode(check.command)}\``,
    );
  }

  lines.push(
    "",
    "```text",
    sanitizeVerificationDetails(check.details),
    "```",
  );

  return lines.join("\n");
}

function buildFindingListSection(
  heading: string,
  findings: SecurityFinding[],
): string {
  if (findings.length === 0) {
    return [
      `### ${heading}`,
      "",
      "None.",
    ].join("\n");
  }

  const items = findings.map(
    (finding, index) => {
      const ruleIds = finding.scanner_evidence
        .map((evidence) => evidence.rule_id)
        .filter(
          (ruleId, ruleIndex, allRuleIds) =>
            allRuleIds.indexOf(ruleId) === ruleIndex,
        );

      const cwes =
        finding.cwe.length > 0
          ? finding.cwe.join(", ")
          : "Not specified";

      return [
        `${index + 1}. **${finding.title}**`,
        `   - Severity: ${finding.severity.toUpperCase()}`,
        `   - CWE: ${cwes}`,
        `   - Rules: ${ruleIds.join(", ") || "Not specified"}`,
      ].join("\n");
    },
  );

  return [
    `### ${heading}`,
    "",
    ...items,
  ].join("\n");
}

function escapeMarkdownInlineCode(
  value: string,
): string {
  return value.replace(/`/g, "\\`");
}

function sanitizeVerificationDetails(
  details: string,
): string {
  const trimmed = details.trim();

  if (!trimmed) {
    return "No additional details were provided.";
  }

  return trimmed
    .replace(/```/g, "~~~")
    .slice(0, 12_000);
}

function compareSecurityVerificationResults(
  analyzedResponse: AnalyzeResponse,
  baselineResponse: AnalyzeResponse,
  verificationResponse: AnalyzeResponse,
): SecurityVerificationDelta {
  const targetRuleIds = Array.from(
    new Set(
      analyzedResponse.findings.flatMap(
        (finding) =>
          finding.scanner_evidence.map(
            (evidence) => evidence.rule_id,
          ),
      ),
    ),
  );

  const baselineIdentities = new Set(
    baselineResponse.findings.map(
      securityFindingIdentity,
    ),
  );

  const remainingTargetFindings =
    verificationResponse.findings.filter(
      (finding) =>
        finding.scanner_evidence.some(
          (evidence) =>
            targetRuleIds.includes(
              evidence.rule_id,
            ),
        ),
    );

  const introducedFindings =
    verificationResponse.findings.filter(
      (finding) =>
        !baselineIdentities.has(
          securityFindingIdentity(finding),
        ),
    );

  const unchangedFindings =
    verificationResponse.findings.filter(
      (finding) =>
        baselineIdentities.has(
          securityFindingIdentity(finding),
        ),
    );

  return {
    targetRuleIds,
    remainingTargetFindings,
    introducedFindings,
    unchangedFindings,
  };
}

function securityFindingIdentity(
  finding: SecurityFinding,
): string {
  const ruleIds = finding.scanner_evidence
    .map(
      (evidence) => evidence.rule_id,
    )
    .sort()
    .join(",");

  return [
    ruleIds || finding.title,
    finding.severity,
    finding.cwe.slice().sort().join(","),
  ].join("|");
}

async function verifyPatchedProject(
  document: vscode.TextDocument,
): Promise<ProjectVerificationSuite> {
  const syntax =
    await verifyPatchedDocumentSyntax(document);

  if (syntax.status === "failed") {
    return {
      syntax,
      tests: {
        name: "Project tests",
        status: "skipped",
        details:
          "Tests were skipped because syntax verification failed.",
      },
      build: {
        name: "Build/typecheck",
        status: "skipped",
        details:
          "Build was skipped because syntax verification failed.",
      },
    };
  }

  const workspaceFolder =
    vscode.workspace.getWorkspaceFolder(
      document.uri,
    );

  if (!workspaceFolder) {
    return {
      syntax,
      tests: {
        name: "Project tests",
        status: "skipped",
        details:
          "No workspace folder was available for test discovery.",
      },
      build: {
        name: "Build/typecheck",
        status: "skipped",
        details:
          "No workspace folder was available for build discovery.",
      },
    };
  }

  const workspacePath =
    workspaceFolder.uri.fsPath;

  const tests =
    await discoverAndRunProjectTests(
      workspacePath,
      document,
    );

  if (tests.status === "failed") {
    return {
      syntax,
      tests,
      build: {
        name: "Build/typecheck",
        status: "skipped",
        details:
          "Build was skipped because project tests failed.",
      },
    };
  }

  const build =
    await discoverAndRunProjectBuild(
      workspacePath,
      document,
    );

  return {
    syntax,
    tests,
    build,
  };
}

function formatVerificationCheck(
  check: VerificationCheckResult,
): string {
  return (
    `${check.name}: ${check.status.toUpperCase()}.`
  );
}

async function discoverAndRunProjectTests(
  workspacePath: string,
  document: vscode.TextDocument,
): Promise<VerificationCheckResult> {
  const language = normalizeLanguage(
    document.languageId,
  );

  if (language === "python") {
    const pytestFiles = await vscode.workspace.findFiles(
      "**/{pytest.ini,pyproject.toml,setup.cfg,tox.ini}",
      "**/{.git,.venv,venv,node_modules,dist,build}/**",
      20,
    );

    const testFiles = await vscode.workspace.findFiles(
      "**/{test_*.py,*_test.py,tests/**/*.py}",
      "**/{.git,.venv,venv,node_modules,dist,build}/**",
      20,
    );

    if (
      pytestFiles.length > 0 ||
      testFiles.length > 0
    ) {
      return runVerificationCommand({
        name: "Python tests",
        command: "python3",
        args: [
          "-m",
          "pytest",
          "-q",
        ],
        cwd: workspacePath,
        timeout: 120_000,
        missingToolMeansSkipped: true,
      });
    }

    return {
      name: "Python tests",
      status: "skipped",
      details:
        "No pytest configuration or Python test files were discovered.",
    };
  }

  if (
    language === "javascript" ||
    language === "typescript"
  ) {
    const packageJsonPath = await findNearestPackageJson(
      document.fileName,
      workspacePath,
    );

    if (!packageJsonPath) {
      return {
        name: "Node tests",
        status: "skipped",
        details:
          "No package.json was found for the patched file.",
      };
    }

    const scripts = await readPackageScripts(
      packageJsonPath,
    );

    const testScript = scripts.test;

    if (
      !testScript ||
      isDefaultNpmTestScript(testScript)
    ) {
      return {
        name: "Node tests",
        status: "skipped",
        details:
          "No meaningful npm test script was configured.",
      };
    }

    return runVerificationCommand({
      name: "Node tests",
      command: "npm",
      args: [
        "test",
        "--",
        "--runInBand",
      ],
      cwd: path.dirname(packageJsonPath),
      timeout: 180_000,
      missingToolMeansSkipped: true,
    });
  }

  return {
    name: "Project tests",
    status: "skipped",
    details:
      `No test runner is configured for ${document.languageId}.`,
  };
}

async function discoverAndRunProjectBuild(
  workspacePath: string,
  document: vscode.TextDocument,
): Promise<VerificationCheckResult> {
  const language = normalizeLanguage(
    document.languageId,
  );

  if (language === "python") {
    const pyprojectFiles =
      await vscode.workspace.findFiles(
        "**/pyproject.toml",
        "**/{.git,.venv,venv,node_modules,dist,build}/**",
        10,
      );

    if (pyprojectFiles.length === 0) {
      return {
        name: "Python build",
        status: "skipped",
        details:
          "No Python project build configuration was discovered.",
      };
    }

    return runVerificationCommand({
      name: "Python compile-all",
      command: "python3",
      args: [
        "-m",
        "compileall",
        "-q",
        workspacePath,
      ],
      cwd: workspacePath,
      timeout: 120_000,
    });
  }

  if (
    language === "javascript" ||
    language === "typescript"
  ) {
    const packageJsonPath = await findNearestPackageJson(
      document.fileName,
      workspacePath,
    );

    if (!packageJsonPath) {
      return {
        name: "Build/typecheck",
        status: "skipped",
        details:
          "No package.json was found for build discovery.",
      };
    }

    const scripts = await readPackageScripts(
      packageJsonPath,
    );

    const packageDirectory =
      path.dirname(packageJsonPath);

    if (scripts.typecheck) {
      return runVerificationCommand({
        name: "Typecheck",
        command: "npm",
        args: [
          "run",
          "typecheck",
          "--",
          "--pretty",
          "false",
        ],
        cwd: packageDirectory,
        timeout: 180_000,
        missingToolMeansSkipped: true,
      });
    }

    if (scripts.build) {
      return runVerificationCommand({
        name: "Project build",
        command: "npm",
        args: [
          "run",
          "build",
        ],
        cwd: packageDirectory,
        timeout: 180_000,
        missingToolMeansSkipped: true,
      });
    }

    if (language === "typescript") {
      return runVerificationCommand({
        name: "TypeScript project check",
        command: "npx",
        args: [
          "--no-install",
          "tsc",
          "--noEmit",
          "--pretty",
          "false",
        ],
        cwd: packageDirectory,
        timeout: 180_000,
        missingToolMeansSkipped: true,
      });
    }

    return {
      name: "Build/typecheck",
      status: "skipped",
      details:
        "No build or typecheck script was configured.",
    };
  }

  return {
    name: "Build/typecheck",
    status: "skipped",
    details:
      `No build verifier is configured for ${document.languageId}.`,
  };
}

async function findNearestPackageJson(
  fileName: string,
  workspacePath: string,
): Promise<string | undefined> {
  let currentDirectory =
    path.dirname(fileName);

  const normalizedWorkspace =
    path.resolve(workspacePath);

  while (
    currentDirectory.startsWith(
      normalizedWorkspace,
    )
  ) {
    const candidate =
      path.join(
        currentDirectory,
        "package.json",
      );

    try {
      await vscode.workspace.fs.stat(
        vscode.Uri.file(candidate),
      );

      return candidate;
    } catch {
      // Continue toward the workspace root.
    }

    if (
      currentDirectory === normalizedWorkspace
    ) {
      break;
    }

    const parent =
      path.dirname(currentDirectory);

    if (parent === currentDirectory) {
      break;
    }

    currentDirectory = parent;
  }

  return undefined;
}

async function readPackageScripts(
  packageJsonPath: string,
): Promise<Record<string, string>> {
  try {
    const content =
      await vscode.workspace.fs.readFile(
        vscode.Uri.file(packageJsonPath),
      );

    const parsed = JSON.parse(
      Buffer.from(content).toString("utf-8"),
    ) as {
      scripts?: Record<string, unknown>;
    };

    const scripts:
      Record<string, string> = {};

    for (const [
      name,
      value,
    ] of Object.entries(
      parsed.scripts ?? {},
    )) {
      if (typeof value === "string") {
        scripts[name] = value;
      }
    }

    return scripts;
  } catch {
    return {};
  }
}

function isDefaultNpmTestScript(
  script: string,
): boolean {
  const normalized =
    script.toLowerCase();

  return (
    normalized.includes(
      "error: no test specified",
    ) ||
    normalized.trim() === ""
  );
}

async function verifyPatchedDocumentSyntax(
  document: vscode.TextDocument,
): Promise<VerificationCheckResult> {
  const language = normalizeLanguage(
    document.languageId,
  );

  const workspaceFolder =
    vscode.workspace.getWorkspaceFolder(
      document.uri,
    );

  const workingDirectory =
    workspaceFolder?.uri.fsPath ??
    path.dirname(document.fileName);

  if (language === "python") {
    return runVerificationCommand({
      name: "Python syntax",
      command: "python3",
      args: [
        "-m",
        "py_compile",
        document.fileName,
      ],
      cwd: workingDirectory,
      timeout: 30_000,
    });
  }

  if (language === "javascript") {
    return runVerificationCommand({
      name: "JavaScript syntax",
      command: "node",
      args: [
        "--check",
        document.fileName,
      ],
      cwd: workingDirectory,
      timeout: 30_000,
    });
  }

  if (language === "typescript") {
    const result = await runVerificationCommand({
      name: "TypeScript check",
      command: "npx",
      args: [
        "--no-install",
        "tsc",
        "--noEmit",
        "--pretty",
        "false",
        "--skipLibCheck",
        "--target",
        "ES2022",
        "--module",
        "commonjs",
        document.fileName,
      ],
      cwd: workingDirectory,
      timeout: 90_000,
      missingToolMeansSkipped: true,
    });

    return result;
  }

  return {
    name: "Syntax check",
    status: "skipped",
    details:
      `No syntax verifier is configured for ${document.languageId}.`,
  };
}

interface VerificationCommandInput {
  name: string;
  command: string;
  args: string[];
  cwd: string;
  timeout: number;
  missingToolMeansSkipped?: boolean;
}

async function runVerificationCommand(
  input: VerificationCommandInput,
): Promise<VerificationCheckResult> {
  const printableCommand = [
    input.command,
    ...input.args,
  ].join(" ");

  try {
    const result = await execFileAsync(
      input.command,
      input.args,
      {
        cwd: input.cwd,
        timeout: input.timeout,
        maxBuffer: 1024 * 1024,
      },
    );

    const output = [
      result.stdout,
      result.stderr,
    ]
      .filter(
        (value) =>
          typeof value === "string" &&
          value.trim().length > 0,
      )
      .join("\n")
      .trim();

    return {
      name: input.name,
      status: "passed",
      command: printableCommand,
      details:
        output ||
        `${input.name} completed successfully.`,
    };
  } catch (error: unknown) {
    const commandError = error as {
      code?: string | number;
      stdout?: string;
      stderr?: string;
      message?: string;
      killed?: boolean;
      signal?: string;
    };

    const missingTool =
      commandError.code === "ENOENT" ||
      (
        typeof commandError.stderr === "string" &&
        (
          commandError.stderr.includes(
            "could not determine executable",
          ) ||
          commandError.stderr.includes(
            "not found",
          )
        )
      );

    if (
      missingTool &&
      input.missingToolMeansSkipped
    ) {
      return {
        name: input.name,
        status: "skipped",
        command: printableCommand,
        details:
          `${input.name} was skipped because the required local tool is unavailable.`,
      };
    }

    const details = [
      commandError.stderr,
      commandError.stdout,
      commandError.message,
    ]
      .filter(
        (value) =>
          typeof value === "string" &&
          value.trim().length > 0,
      )
      .join("\n")
      .trim();

    return {
      name: input.name,
      status: "failed",
      command: printableCommand,
      details:
        details ||
        `${input.name} failed without diagnostic output.`,
    };
  }
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
  await showReusableAegisReport(
    "analysis",
    buildMarkdownReport(
      result,
      mode,
    ),
  );
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
  reportContentProvider = undefined;
  securityTreeProvider = undefined;
  latestDependencyScan = undefined;
  latestWorkspaceScan = undefined;
  lastAnalysis = undefined;
}
