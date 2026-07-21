from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    ValidationExecutionResult,
    ValidationSuccessCriteria,
)
from aegis.security.validation_evidence import (
    DynamicValidationEvaluator,
)


def _execution(
    **overrides: object,
) -> ValidationExecutionResult:
    values: dict[str, object] = {
        "runner": "aegis-safe-container-runner-v1",
        "status": "completed",
        "runtime_executable": "/usr/bin/podman",
        "started": True,
        "timed_out": False,
        "exit_code": 0,
        "duration_ms": 12,
        "stdout": "AEGIS_EXPLOIT_CONFIRMED\n",
        "stderr": "",
        "argv": [
            "/usr/bin/podman",
            "run",
            "--rm",
        ],
        "reasons": [],
        "denials": [],
    }
    values.update(overrides)

    return ValidationExecutionResult(
        **values,
    )


def _request(
    *,
    execution: ValidationExecutionResult | None = None,
    expected_marker: str = (
        "AEGIS_EXPLOIT_CONFIRMED"
    ),
) -> DynamicValidationEvidenceRequest:
    return DynamicValidationEvidenceRequest(
        threat_id="threat-command-001",
        category="command_injection",
        execution=execution or _execution(),
        success_criteria=ValidationSuccessCriteria(
            expected_exit_code=0,
            stdout_contains=expected_marker,
        ),
    )


def test_confirms_matching_dynamic_evidence() -> None:
    result = DynamicValidationEvaluator().evaluate(
        _request()
    )

    assert result.verdict == "confirmed"
    assert result.dynamically_confirmed is True
    assert result.confidence >= 0.99
    assert result.execution_status == "completed"
    assert any(
        "AEGIS_EXPLOIT_CONFIRMED" in item
        for item in result.evidence
    )


def test_reports_not_reproduced() -> None:
    result = DynamicValidationEvaluator().evaluate(
        _request(
            expected_marker="EXPECTED_MARKER",
        )
    )

    assert result.verdict == "not_reproduced"
    assert result.dynamically_confirmed is False
    assert any(
        "stdout marker" in reason.lower()
        for reason in result.reasons
    )


def test_reports_blocked_execution() -> None:
    result = DynamicValidationEvaluator().evaluate(
        _request(
            execution=_execution(
                status="rejected",
                started=False,
                exit_code=None,
                stdout="",
                denials=[
                    "Authorization was denied.",
                ],
            )
        )
    )

    assert result.verdict == "blocked"
    assert result.dynamically_confirmed is False


def test_reports_timed_out_execution() -> None:
    result = DynamicValidationEvaluator().evaluate(
        _request(
            execution=_execution(
                status="timed_out",
                timed_out=True,
                exit_code=-9,
                stdout="",
            )
        )
    )

    assert result.verdict == "timed_out"
    assert result.confidence == 1.0


def test_reports_runtime_error() -> None:
    result = DynamicValidationEvaluator().evaluate(
        _request(
            execution=_execution(
                status="runtime_unavailable",
                runtime_executable=None,
                started=False,
                exit_code=None,
                stdout="",
            )
        )
    )

    assert result.verdict == "execution_error"
    assert result.dynamically_confirmed is False


def test_rejects_wrong_exit_code_as_reproduction() -> None:
    result = DynamicValidationEvaluator().evaluate(
        _request(
            execution=_execution(
                exit_code=1,
            )
        )
    )

    assert result.verdict == "not_reproduced"
    assert any(
        "exit code" in reason.lower()
        for reason in result.reasons
    )
