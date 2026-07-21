from aegis.schemas.validation import (
    DynamicValidationEvidenceResponse,
    ValidationReplayCompareRequest,
)
from aegis.security.validation_replay import (
    ValidationReplayComparator,
)


def _evidence(
    *,
    verdict: str,
    threat_id: str = "threat-command-001",
    category: str = "command_injection",
    confidence: float = 0.99,
) -> DynamicValidationEvidenceResponse:
    return DynamicValidationEvidenceResponse(
        evaluator=(
            "aegis-dynamic-validation-evidence-v1"
        ),
        threat_id=threat_id,
        category=category,
        verdict=verdict,
        dynamically_confirmed=(
            verdict == "confirmed"
        ),
        confidence=confidence,
        evidence=[
            f"Dynamic verdict: {verdict}",
        ],
        reasons=[],
        execution_status=(
            "completed"
            if verdict in {
                "confirmed",
                "not_reproduced",
            }
            else (
                "timed_out"
                if verdict == "timed_out"
                else (
                    "rejected"
                    if verdict == "blocked"
                    else "failed"
                )
            )
        ),
        exit_code=0,
        duration_ms=10,
    )


def _compare(
    *,
    before: DynamicValidationEvidenceResponse,
    after: DynamicValidationEvidenceResponse,
):
    return ValidationReplayComparator().compare(
        ValidationReplayCompareRequest(
            before=before,
            after=after,
        )
    )


def test_reports_fixed_when_exploit_stops_reproducing() -> None:
    result = _compare(
        before=_evidence(
            verdict="confirmed",
        ),
        after=_evidence(
            verdict="not_reproduced",
            confidence=0.92,
        ),
    )

    assert result.verdict == "fixed"
    assert result.fixed is True
    assert result.confidence >= 0.92
    assert result.before_verdict == "confirmed"
    assert result.after_verdict == (
        "not_reproduced"
    )


def test_reports_still_exploitable() -> None:
    result = _compare(
        before=_evidence(
            verdict="confirmed",
        ),
        after=_evidence(
            verdict="confirmed",
        ),
    )

    assert result.verdict == "still_exploitable"
    assert result.fixed is False
    assert any(
        "remains" in reason.lower()
        for reason in result.reasons
    )


def test_reports_inconclusive_after_timeout() -> None:
    result = _compare(
        before=_evidence(
            verdict="confirmed",
        ),
        after=_evidence(
            verdict="timed_out",
        ),
    )

    assert result.verdict == "inconclusive"
    assert result.fixed is False


def test_requires_confirmed_baseline() -> None:
    result = _compare(
        before=_evidence(
            verdict="not_reproduced",
        ),
        after=_evidence(
            verdict="not_reproduced",
        ),
    )

    assert result.verdict == "inconclusive"
    assert result.fixed is False
    assert any(
        "baseline" in reason.lower()
        for reason in result.reasons
    )


def test_rejects_different_threat_ids() -> None:
    result = _compare(
        before=_evidence(
            verdict="confirmed",
            threat_id="threat-001",
        ),
        after=_evidence(
            verdict="not_reproduced",
            threat_id="threat-002",
        ),
    )

    assert result.verdict == "inconclusive"
    assert result.fixed is False
    assert result.denials
    assert any(
        "same threat" in denial.lower()
        for denial in result.denials
    )


def test_rejects_different_categories() -> None:
    result = _compare(
        before=_evidence(
            verdict="confirmed",
            category="command_injection",
        ),
        after=_evidence(
            verdict="not_reproduced",
            category="path_traversal",
        ),
    )

    assert result.verdict == "inconclusive"
    assert result.denials
    assert any(
        "same validation category"
        in denial.lower()
        for denial in result.denials
    )
