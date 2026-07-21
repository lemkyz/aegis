from typing import Literal

from pydantic import BaseModel, Field


AttackSurfaceNodeKind = Literal[
    "http_route",
    "authentication",
    "user_input",
    "function_parameter",
    "database",
    "filesystem",
    "outbound_request",
    "process_execution",
    "secret_access",
]

AttackSurfaceRisk = Literal[
    "info",
    "low",
    "medium",
    "high",
    "critical",
]


class AttackSurfaceFile(BaseModel):
    filename: str = Field(
        min_length=1,
        max_length=500,
    )
    language: str = Field(
        min_length=1,
        max_length=50,
    )
    code: str = Field(
        min_length=1,
        max_length=200_000,
    )


class AttackSurfaceScanRequest(BaseModel):
    files: list[AttackSurfaceFile] = Field(
        min_length=1,
        max_length=300,
    )


class AttackSurfaceNode(BaseModel):
    id: str
    kind: AttackSurfaceNodeKind
    label: str

    file: str
    line_start: int
    line_end: int

    symbol: str | None = None
    framework: str | None = None

    method: str | None = None
    path: str | None = None

    authenticated: bool | None = None
    risk: AttackSurfaceRisk = "info"

    evidence: str
    metadata: dict[str, str] = Field(
        default_factory=dict,
    )


class AttackSurfaceEdge(BaseModel):
    source: str
    target: str
    relationship: str
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )


class AttackSurfaceSummary(BaseModel):
    files_scanned: int
    nodes_found: int
    edges_found: int

    routes: int
    authenticated_routes: int
    unauthenticated_routes: int

    databases: int
    filesystems: int
    outbound_requests: int
    process_executions: int
    secret_accesses: int


class AttackSurfaceScanResponse(BaseModel):
    mapper: str
    nodes: list[AttackSurfaceNode]
    edges: list[AttackSurfaceEdge]
    summary: AttackSurfaceSummary
