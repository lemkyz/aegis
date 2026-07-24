from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.security.claim_adapter import (
    finding_to_claim,
)


SEMGREP_RULE = (
    "aegis.python.command-injection."
    "subprocess-shell"
)


def scanner_evidence(
    *,
    tool: str = "Semgrep",
    rule_id: str = SEMGREP_RULE,
    message: str = (
        "Untrusted input reaches subprocess.run "
        "with shell execution enabled."
    ),
    line_start: int = 20,
    line_end: int = 24,
    code: str = (
        "subprocess.run(command, shell=True)"
    ),
) -> ScannerEvidence:
    return ScannerEvidence(
        tool=tool,
        rule_id=rule_id,
        message=message,
        severity="ERROR",
        file="src/app.py",
        line_start=line_start,
        line_end=line_end,
        code=code,
        cwe=["CWE-78"],
        owasp=["A03:2021"],
    )


def finding(
    *,
    title: str = "Command Injection",
    summary: str = (
        "Untrusted input may reach shell execution."
    ),
    severity: str = "high",
    confidence: float = 0.91,
    scanner_items: list[ScannerEvidence] | None = None,
    remediation: str = (
        "Pass arguments as a list and disable shell execution."
    ),
) -> SecurityFinding:
    return SecurityFinding(
        title=title,
        severity=severity,
        confidence=confidence,
        summary=summary,
        evidence=[
            "The command contains attacker-controlled input.",
        ],
        scanner_evidence=(
            scanner_items
            if scanner_items is not None
            else [scanner_evidence()]
        ),
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        vulnerable_lines=[20, 21, 22, 23, 24],
        false_positive_notes=[],
        recommended_fix=remediation,
        proposed_patch=None,
    )


def claim_for(
    item: SecurityFinding,
):
    return finding_to_claim(
        item,
        filename="src/app.py",
    )


def test_identity_ignores_narrative_edits() -> None:
    original = claim_for(finding())

    rewritten = claim_for(
        finding(
            title=(
                "Shell Command Injection Through "
                "subprocess.run"
            ),
            summary=(
                "Attacker-controlled data can be evaluated "
                "by the operating-system shell."
            ),
            severity="critical",
            confidence=0.98,
            remediation=(
                "Remove shell execution and use a fixed "
                "argument vector."
            ),
        )
    )

    assert original.claim_id == rewritten.claim_id


def test_identity_survives_scanner_enrichment() -> None:
    semgrep = scanner_evidence()

    bandit = scanner_evidence(
        tool="Bandit",
        rule_id="bandit.python.B602",
        message=(
            "subprocess call uses shell=True."
        ),
    )

    first = claim_for(
        finding(scanner_items=[semgrep])
    )

    enriched = claim_for(
        finding(scanner_items=[semgrep, bandit])
    )

    assert first.claim_id == enriched.claim_id


def test_existing_evidence_identity_survives_message_change() -> None:
    first = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    message=(
                        "Untrusted input reaches "
                        "subprocess.run."
                    )
                )
            ]
        )
    )

    rewritten = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    message=(
                        "Potential shell command injection "
                        "was detected."
                    )
                )
            ]
        )
    )

    assert (
        first.evidence[0].evidence_id
        == rewritten.evidence[0].evidence_id
    )


def test_identity_survives_small_line_shift() -> None:
    original = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    line_start=20,
                    line_end=24,
                )
            ]
        )
    )

    shifted = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    line_start=23,
                    line_end=27,
                )
            ]
        )
    )

    assert original.claim_id == shifted.claim_id


def test_same_sink_at_distinct_regions_remains_distinct() -> None:
    first = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    line_start=20,
                    line_end=24,
                )
            ]
        )
    )

    second = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    line_start=80,
                    line_end=84,
                )
            ]
        )
    )

    assert first.claim_id != second.claim_id


def test_different_sink_code_remains_distinct() -> None:
    first = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    code=(
                        "subprocess.run("
                        "command, shell=True)"
                    )
                )
            ]
        )
    )

    second = claim_for(
        finding(
            scanner_items=[
                scanner_evidence(
                    code=(
                        "subprocess.Popen("
                        "command, shell=True)"
                    )
                )
            ]
        )
    )

    assert first.claim_id != second.claim_id
