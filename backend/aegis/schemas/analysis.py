from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["info", "low", "medium", "high", "critical"]
AnalysisStatus = Literal["completed", "skipped", "fallback"]
ResultSource = Literal["scanner", "ai", "scanner_fallback"]


class AnalyzeCodeRequest(BaseModel):
    code: str = Field(
        min_length=1,
        max_length=100_000,
        description="Analyzed source code",
    )
    language: str = Field(default="python", max_length=50)
    filename: str = Field(default="unknown.py", max_length=500)


class SecretClassification(BaseModel):
    provider: str
    secret_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    likely_placeholder: bool = False
    rotation_required: bool = False
    fingerprint: str | None = None
    entropy: float = Field(default=0.0, ge=0.0)
    remediation: str


class ScannerEvidence(BaseModel):
    tool: str
    rule_id: str
    message: str
    severity: str
    file: str
    line_start: int
    line_end: int
    code: str | None = None
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    secret: SecretClassification | None = None

    corroborated_by: list[str] = Field(
        default_factory=list,
    )
    related_rule_ids: list[str] = Field(
        default_factory=list,
    )


class SecurityFinding(BaseModel):
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)

    summary: str
    evidence: list[str] = Field(default_factory=list)
    scanner_evidence: list[ScannerEvidence] = Field(default_factory=list)

    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)

    vulnerable_lines: list[int] = Field(default_factory=list)
    false_positive_notes: list[str] = Field(default_factory=list)

    recommended_fix: str
    proposed_patch: str | None = None


class AnalyzeCodeResponse(BaseModel):
    filename: str
    language: str
    model: str
    scanner: str
    analysis_status: AnalysisStatus = "completed"
    result_source: ResultSource = "scanner"
    findings: list[SecurityFinding]
