from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    DynamicValidationEvidenceResponse,
)


class DynamicValidationEvaluator:
    evaluator = "aegis-dynamic-validation-evidence-v1"

    def evaluate(
        self,
        request: DynamicValidationEvidenceRequest,
    ) -> DynamicValidationEvidenceResponse:
        execution = request.execution
        criteria = request.success_criteria

        evidence = self._collect_evidence(request)
        reasons: list[str] = []

        if execution.status == "timed_out":
            verdict = "timed_out"
            confidence = 1.0
            reasons.append(
                "The isolated validation exceeded the "
                "authorized timeout."
            )

        elif execution.status == "rejected":
            verdict = "blocked"
            confidence = 1.0
            reasons.append(
                "The validation was blocked before "
                "sandbox execution."
            )

        elif execution.status in {
            "failed",
            "runtime_unavailable",
        }:
            verdict = "execution_error"
            confidence = 0.98
            reasons.append(
                "The sandbox could not produce a valid "
                "reproduction result."
            )

        elif self._criteria_match(request):
            verdict = "confirmed"
            confidence = 0.99
            reasons.append(
                "The isolated execution satisfied every "
                "declared success criterion."
            )

        else:
            verdict = "not_reproduced"
            confidence = 0.92
            reasons.append(
                "The isolated execution completed but "
                "did not satisfy every success criterion."
            )

            if execution.exit_code != (
                criteria.expected_exit_code
            ):
                reasons.append(
                    "The observed exit code did not match "
                    "the expected exit code."
                )

            if (
                criteria.stdout_contains is not None
                and criteria.stdout_contains
                not in execution.stdout
            ):
                reasons.append(
                    "The expected stdout marker was not "
                    "observed."
                )

            if (
                criteria.stderr_contains is not None
                and criteria.stderr_contains
                not in execution.stderr
            ):
                reasons.append(
                    "The expected stderr marker was not "
                    "observed."
                )

        return DynamicValidationEvidenceResponse(
            evaluator=self.evaluator,
            threat_id=request.threat_id,
            category=request.category,
            verdict=verdict,
            dynamically_confirmed=(
                verdict == "confirmed"
            ),
            confidence=confidence,
            evidence=evidence,
            reasons=reasons,
            execution_status=execution.status,
            exit_code=execution.exit_code,
            duration_ms=execution.duration_ms,
        )

    @staticmethod
    def _criteria_match(
        request: DynamicValidationEvidenceRequest,
    ) -> bool:
        execution = request.execution
        criteria = request.success_criteria

        if execution.status != "completed":
            return False

        if execution.exit_code != (
            criteria.expected_exit_code
        ):
            return False

        if (
            criteria.stdout_contains is not None
            and criteria.stdout_contains
            not in execution.stdout
        ):
            return False

        if (
            criteria.stderr_contains is not None
            and criteria.stderr_contains
            not in execution.stderr
        ):
            return False

        return True

    @staticmethod
    def _collect_evidence(
        request: DynamicValidationEvidenceRequest,
    ) -> list[str]:
        execution = request.execution
        evidence = [
            (
                "Sandbox status: "
                f"{execution.status}"
            ),
            (
                "Exit code: "
                f"{execution.exit_code}"
            ),
            (
                "Duration: "
                f"{execution.duration_ms} ms"
            ),
        ]

        if execution.runtime_executable:
            evidence.append(
                "Container runtime: "
                f"{execution.runtime_executable}"
            )

        if execution.stdout:
            evidence.append(
                "Captured stdout:\n"
                f"{execution.stdout}"
            )

        if execution.stderr:
            evidence.append(
                "Captured stderr:\n"
                f"{execution.stderr}"
            )

        return evidence
