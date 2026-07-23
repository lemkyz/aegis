from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.analysis import (
    AnalyzeCodeResponse,
    ScannerEvidence,
    SecurityFinding,
)


def make_finding(
    *,
    line: int,
) -> SecurityFinding:
    scanner = ScannerEvidence(
        tool="Semgrep",
        rule_id=(
            "aegis.python.command-injection."
            "subprocess-shell"
        ),
        message="Shell execution receives untrusted input.",
        severity="ERROR",
        file="app.py",
        line_start=line,
        line_end=line,
        code="subprocess.run(command, shell=True)",
        cwe=["CWE-78"],
        owasp=["A03:2021"],
    )

    return SecurityFinding(
        title="Command Injection",
        severity="high",
        confidence=0.95,
        summary="Untrusted input reaches shell execution.",
        evidence=[
            "The shell command contains untrusted input.",
        ],
        scanner_evidence=[scanner],
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        vulnerable_lines=[line],
        false_positive_notes=[],
        recommended_fix="Disable shell execution.",
        proposed_patch=None,
    )


def test_same_finding_produces_same_claim_identity() -> None:
    finding = make_finding(line=8)

    first = SecurityAnalyzer._build_claims(
        findings=[finding],
        filename="app.py",
    )
    second = SecurityAnalyzer._build_claims(
        findings=[finding],
        filename="./app.py",
    )

    assert first[0].claim_id == second[0].claim_id


def test_same_rule_at_different_locations_has_distinct_claim_ids() -> None:
    claims = SecurityAnalyzer._build_claims(
        findings=[
            make_finding(line=8),
            make_finding(line=24),
        ],
        filename="app.py",
    )

    assert len(claims) == 2
    assert claims[0].claim_id != claims[1].claim_id


def test_analysis_json_schema_exposes_findings_and_claims() -> None:
    schema = AnalyzeCodeResponse.model_json_schema()

    properties = schema["properties"]

    assert "findings" in properties
    assert "claims" in properties
    assert properties["findings"]["type"] == "array"
    assert properties["claims"]["type"] == "array"


def test_legacy_analysis_payload_still_parses() -> None:
    response = AnalyzeCodeResponse.model_validate(
        {
            "filename": "safe.py",
            "language": "python",
            "model": "not-used",
            "scanner": "semgrep",
            "analysis_status": "skipped",
            "result_source": "scanner",
            "findings": [],
        }
    )

    assert response.findings == []
    assert response.claims == []


def test_claim_order_follows_finding_order() -> None:
    first_finding = make_finding(line=8)
    second_finding = make_finding(line=24)

    claims = SecurityAnalyzer._build_claims(
        findings=[
            first_finding,
            second_finding,
        ],
        filename="app.py",
    )

    assert claims[0].locations[0].line_start == 8
    assert claims[1].locations[0].line_start == 24
