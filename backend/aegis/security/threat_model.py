import hashlib

from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
    AttackSurfaceNode,
)
from aegis.schemas.threat_model import (
    ThreatAsset,
    ThreatFinding,
    ThreatModelScanResponse,
    ThreatModelSummary,
    TrustBoundary,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)


class ThreatModeler:
    name = "aegis-deterministic-threat-model"

    def __init__(
        self,
        mapper: AttackSurfaceMapper | None = None,
    ) -> None:
        self.mapper = mapper or AttackSurfaceMapper()

    def scan(
        self,
        files: list[AttackSurfaceFile],
    ) -> ThreatModelScanResponse:
        attack_surface = self.mapper.scan(files)

        assets = self._build_assets(
            attack_surface.nodes,
        )
        trust_boundaries = self._build_trust_boundaries(
            attack_surface.nodes,
        )
        threats = self._build_threats(
            attack_surface.nodes,
        )

        return ThreatModelScanResponse(
            modeler=self.name,
            attack_surface_nodes=attack_surface.nodes,
            attack_surface_edges=attack_surface.edges,
            assets=assets,
            trust_boundaries=trust_boundaries,
            threats=threats,
            summary=ThreatModelSummary(
                files_scanned=len(files),
                assets_found=len(assets),
                trust_boundaries_found=len(
                    trust_boundaries
                ),
                threats_found=len(threats),
                critical=self._count_severity(
                    threats,
                    "critical",
                ),
                high=self._count_severity(
                    threats,
                    "high",
                ),
                medium=self._count_severity(
                    threats,
                    "medium",
                ),
                low=self._count_severity(
                    threats,
                    "low",
                ),
                info=self._count_severity(
                    threats,
                    "info",
                ),
            ),
        )

    def _build_assets(
        self,
        nodes: list[AttackSurfaceNode],
    ) -> list[ThreatAsset]:
        asset_details = {
            "http_route": (
                "HTTP endpoint",
                "entry_point",
                "Application endpoint exposed to callers.",
            ),
            "database": (
                "Application data store",
                "data_store",
                "Database records read or modified by the application.",
            ),
            "filesystem": (
                "Application filesystem",
                "file_store",
                "Files accessed or modified by the application.",
            ),
            "outbound_request": (
                "External service",
                "external_service",
                "Remote service contacted by the application.",
            ),
            "process_execution": (
                "Host execution environment",
                "host",
                "Operating-system commands or child processes.",
            ),
            "secret_access": (
                "Application secrets",
                "secret_store",
                "Credentials and sensitive configuration values.",
            ),
        }

        assets: list[ThreatAsset] = []

        for node in nodes:
            details = asset_details.get(node.kind)

            if details is None:
                continue

            name, kind, description = details

            assets.append(
                ThreatAsset(
                    id=self._stable_id(
                        "asset",
                        node.id,
                    ),
                    name=name,
                    kind=kind,
                    file=node.file,
                    line=node.line_start,
                    description=description,
                    source_node_ids=[node.id],
                )
            )

        return self._deduplicate_assets(assets)

    def _build_trust_boundaries(
        self,
        nodes: list[AttackSurfaceNode],
    ) -> list[TrustBoundary]:
        boundaries: list[TrustBoundary] = []

        for node in nodes:
            if node.kind == "http_route":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "http",
                        ),
                        label="HTTP request boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="network_input",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

            elif node.kind == "user_input":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "input",
                        ),
                        label="Untrusted user-input boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="untrusted_input",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

            elif node.kind == "outbound_request":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "outbound",
                        ),
                        label="External network boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="external_network",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

            elif node.kind == "secret_access":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "secret",
                        ),
                        label="Secret configuration boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="sensitive_configuration",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

        return self._deduplicate_boundaries(
            boundaries
        )

    def _build_threats(
        self,
        nodes: list[AttackSurfaceNode],
    ) -> list[ThreatFinding]:
        threats: list[ThreatFinding] = []

        for node in nodes:
            threat = self._threat_for_node(node)

            if threat is not None:
                threats.append(threat)

        return sorted(
            threats,
            key=lambda threat: (
                self._severity_rank(
                    threat.severity
                ),
                threat.file,
                threat.line,
                threat.category,
            ),
        )

    def _threat_for_node(
        self,
        node: AttackSurfaceNode,
    ) -> ThreatFinding | None:
        if node.kind == "process_execution":
            return self._threat(
                node=node,
                title="Untrusted data may reach process execution",
                category="command_injection",
                severity="critical",
                confidence=0.90,
                affected_asset="Host execution environment",
                trust_boundary="Untrusted input to operating-system process",
                description=(
                    "Process execution can allow command injection "
                    "when attacker-controlled values reach command "
                    "arguments or a shell."
                ),
                attack_path=[
                    "Attacker controls an application input",
                    "Input reaches process or shell execution",
                    "Host command executes with application privileges",
                ],
                mitigations=[
                    "Avoid shell execution where possible",
                    "Pass arguments as a fixed list",
                    "Use strict allowlists for permitted values",
                    "Run the process with minimal privileges",
                ],
            )

        if node.kind == "database":
            return self._threat(
                node=node,
                title="Untrusted data may alter a database query",
                category="sql_injection",
                severity="high",
                confidence=0.82,
                affected_asset="Application data store",
                trust_boundary="Application-to-database boundary",
                description=(
                    "Dynamic or insufficiently constrained database "
                    "operations may allow query manipulation."
                ),
                attack_path=[
                    "Attacker supplies crafted input",
                    "Input influences a database operation",
                    "Database query behavior is altered",
                ],
                mitigations=[
                    "Use parameterized queries",
                    "Avoid string-built SQL",
                    "Apply least-privilege database permissions",
                    "Validate identifiers against allowlists",
                ],
            )

        if node.kind == "filesystem":
            return self._threat(
                node=node,
                title="Untrusted paths may escape the intended directory",
                category="path_traversal",
                severity="high",
                confidence=0.78,
                affected_asset="Application filesystem",
                trust_boundary="Application-to-filesystem boundary",
                description=(
                    "Attacker-controlled path components may permit "
                    "reading, writing, moving, or deleting unintended files."
                ),
                attack_path=[
                    "Attacker controls a filename or path",
                    "Path reaches a filesystem operation",
                    "Operation accesses data outside the intended root",
                ],
                mitigations=[
                    "Resolve paths against a fixed base directory",
                    "Reject paths that escape the allowed root",
                    "Use generated server-side filenames",
                    "Restrict filesystem permissions",
                ],
            )

        if node.kind == "outbound_request":
            return self._threat(
                node=node,
                title="User-controlled destinations may enable SSRF",
                category="ssrf",
                severity="high",
                confidence=0.84,
                affected_asset="External and internal network services",
                trust_boundary="Application-to-network boundary",
                description=(
                    "An attacker may influence an outbound request "
                    "destination and reach internal or privileged services."
                ),
                attack_path=[
                    "Attacker supplies a URL or hostname",
                    "Application performs an outbound request",
                    "Request reaches an internal or restricted service",
                ],
                mitigations=[
                    "Allowlist permitted schemes and hosts",
                    "Block private, loopback, and link-local addresses",
                    "Revalidate destinations after redirects",
                    "Use a restricted outbound proxy",
                ],
            )

        if node.kind == "secret_access":
            return self._threat(
                node=node,
                title="Sensitive configuration may be exposed",
                category="secret_exposure",
                severity="high",
                confidence=0.72,
                affected_asset="Application secrets",
                trust_boundary="Secret configuration boundary",
                description=(
                    "Credentials or sensitive configuration may leak "
                    "through logs, errors, responses, or insecure storage."
                ),
                attack_path=[
                    "Application loads a secret",
                    "Secret enters application memory",
                    "Secret is exposed through an unsafe output or store",
                ],
                mitigations=[
                    "Never log secret values",
                    "Redact secrets from errors and telemetry",
                    "Use a dedicated secret manager",
                    "Rotate credentials after suspected exposure",
                ],
            )

        if (
            node.kind == "http_route"
            and node.authenticated is False
        ):
            return self._threat(
                node=node,
                title="Sensitive route may lack authentication",
                category="authentication_bypass",
                severity="high",
                confidence=0.86,
                affected_asset="Protected application functionality",
                trust_boundary="Unauthenticated HTTP boundary",
                description=(
                    "The route appears reachable without a detected "
                    "authentication or authorization control."
                ),
                attack_path=[
                    "Unauthenticated caller reaches the route",
                    "Route performs a sensitive application action",
                    "Protected data or functionality is exposed",
                ],
                mitigations=[
                    "Require authentication middleware",
                    "Enforce authorization at the operation boundary",
                    "Use deny-by-default access policies",
                    "Add tests for unauthenticated access",
                ],
            )

        if node.kind == "user_input":
            return self._threat(
                node=node,
                title="Untrusted input crosses into application logic",
                category="unsafe_data_flow",
                severity="medium",
                confidence=0.68,
                affected_asset="Application processing logic",
                trust_boundary="Untrusted user-input boundary",
                description=(
                    "Request-controlled data enters application logic "
                    "and requires validation before sensitive use."
                ),
                attack_path=[
                    "Attacker supplies crafted request data",
                    "Application accepts the value",
                    "Value reaches a security-sensitive operation",
                ],
                mitigations=[
                    "Validate type, length, format, and allowed values",
                    "Normalize data before validation",
                    "Encode output for its destination context",
                    "Track data flow into sensitive sinks",
                ],
            )

        return None

    def _threat(
        self,
        *,
        node: AttackSurfaceNode,
        title: str,
        category: str,
        severity: str,
        confidence: float,
        affected_asset: str,
        trust_boundary: str,
        description: str,
        attack_path: list[str],
        mitigations: list[str],
    ) -> ThreatFinding:
        return ThreatFinding(
            id=self._stable_id(
                "threat",
                node.id,
                category,
            ),
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            file=node.file,
            line=node.line_start,
            entry_point=(
                node.label
                if node.kind == "http_route"
                else None
            ),
            affected_asset=affected_asset,
            trust_boundary=trust_boundary,
            description=description,
            attack_path=attack_path,
            mitigations=mitigations,
            evidence=[node.evidence],
            source_node_ids=[node.id],
        )

    @staticmethod
    def _stable_id(
        *parts: str,
    ) -> str:
        value = "::".join(parts).encode(
            "utf-8"
        )

        return hashlib.sha256(
            value
        ).hexdigest()[:20]

    @staticmethod
    def _count_severity(
        threats: list[ThreatFinding],
        severity: str,
    ) -> int:
        return sum(
            threat.severity == severity
            for threat in threats
        )

    @staticmethod
    def _severity_rank(
        severity: str,
    ) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }.get(severity, 5)

    @staticmethod
    def _deduplicate_assets(
        assets: list[ThreatAsset],
    ) -> list[ThreatAsset]:
        deduplicated = {
            asset.id: asset
            for asset in assets
        }

        return sorted(
            deduplicated.values(),
            key=lambda asset: (
                asset.file,
                asset.line,
                asset.kind,
            ),
        )

    @staticmethod
    def _deduplicate_boundaries(
        boundaries: list[TrustBoundary],
    ) -> list[TrustBoundary]:
        deduplicated = {
            boundary.id: boundary
            for boundary in boundaries
        }

        return sorted(
            deduplicated.values(),
            key=lambda boundary: (
                boundary.file,
                boundary.line,
                boundary.boundary_type,
            ),
        )
