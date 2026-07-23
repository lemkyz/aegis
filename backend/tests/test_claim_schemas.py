import pytest
from pydantic import ValidationError

from aegis.schemas.claims import (
    CodeLocation,
    EvidenceItem,
    EvidenceRelationship,
    EvidenceSource,
    SecurityClaim,
)


def test_security_claim_accepts_canonical_evidence_graph() -> None:
    scanner = EvidenceItem(
        evidence_id="evidence:scanner:1",
        source=EvidenceSource(
            kind="scanner",
            name="Aegis Static Scanner",
            rule_id="aegis.python.command-injection.subprocess-shell",
        ),
        summary="A command injection sink was detected.",
        confidence=0.91,
        locations=[
            CodeLocation(
                file="app.py",
                line_start=8,
                line_end=12,
                symbol="run_command",
            ),
        ],
        details=[
            "Untrusted input reaches subprocess.run.",
        ],
    )

    runtime = EvidenceItem(
        evidence_id="evidence:runtime:1",
        source=EvidenceSource(
            kind="dynamic_probe",
            name="Aegis Dynamic Validator",
        ),
        summary="Authorized replay reproduced the vulnerable behavior.",
        confidence=0.97,
        details=[
            "Expected marker was present in stdout.",
        ],
    )

    claim = SecurityClaim(
        claim_id="claim:command-injection:app.py:run_command",
        statement=(
            "Untrusted input reaches subprocess.run "
            "with shell execution enabled."
        ),
        category="command_injection",
        severity="high",
        confidence=0.96,
        state="confirmed",
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        locations=scanner.locations,
        evidence=[scanner, runtime],
        relationships=[
            EvidenceRelationship(
                relationship_id="relationship:1",
                source_evidence_id=runtime.evidence_id,
                target_evidence_id=scanner.evidence_id,
                kind="corroborates",
                reason="Runtime behavior confirms the static finding.",
            ),
        ],
        remediation="Avoid shell execution and pass an argument list.",
    )

    assert claim.schema_version == "1.0"
    assert claim.state == "confirmed"
    assert len(claim.evidence) == 2
    assert claim.relationships[0].kind == "corroborates"


def test_code_location_rejects_zero_based_lines() -> None:
    with pytest.raises(ValidationError):
        CodeLocation(
            file="app.py",
            line_start=0,
            line_end=1,
        )


def test_claim_rejects_unknown_state() -> None:
    with pytest.raises(ValidationError):
        SecurityClaim(
            claim_id="claim:invalid",
            statement="Invalid state example.",
            category="example",
            severity="medium",
            confidence=0.5,
            state="unknown",
        )


def test_evidence_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        EvidenceItem(
            evidence_id="evidence:invalid",
            source=EvidenceSource(
                kind="scanner",
                name="Scanner",
            ),
            summary="Invalid confidence.",
            confidence=1.1,
        )


def test_code_location_rejects_reversed_range() -> None:
    with pytest.raises(ValidationError):
        CodeLocation(
            file="app.py",
            line_start=12,
            line_end=8,
        )


def test_claim_rejects_duplicate_evidence_ids() -> None:
    evidence = EvidenceItem(
        evidence_id="evidence:duplicate",
        source=EvidenceSource(
            kind="scanner",
            name="Scanner",
        ),
        summary="Duplicate evidence example.",
        confidence=0.8,
    )

    with pytest.raises(ValidationError):
        SecurityClaim(
            claim_id="claim:duplicate-evidence",
            statement="A claim with duplicate evidence.",
            category="example",
            severity="medium",
            confidence=0.8,
            state="supported",
            evidence=[evidence, evidence],
        )


def test_claim_rejects_unknown_relationship_reference() -> None:
    evidence = EvidenceItem(
        evidence_id="evidence:known",
        source=EvidenceSource(
            kind="scanner",
            name="Scanner",
        ),
        summary="Known evidence.",
        confidence=0.8,
    )

    with pytest.raises(ValidationError):
        SecurityClaim(
            claim_id="claim:broken-relationship",
            statement="A claim with an invalid evidence relationship.",
            category="example",
            severity="medium",
            confidence=0.8,
            state="supported",
            evidence=[evidence],
            relationships=[
                EvidenceRelationship(
                    relationship_id="relationship:broken",
                    source_evidence_id="evidence:missing",
                    target_evidence_id="evidence:known",
                    kind="supports",
                ),
            ],
        )
