from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    ValidationExecutionRequest,
    ValidationReplayCompareRequest,
    ValidationReplayRequest,
    ValidationReplayResponse,
)
from aegis.security.validation_evidence import (
    DynamicValidationEvaluator,
)
from aegis.security.validation_replay import (
    ValidationReplayComparator,
)
from aegis.security.validation_runner import (
    ValidationRunner,
)


class ValidationReplayOrchestrator:
    orchestrator = (
        "aegis-dynamic-validation-"
        "replay-orchestrator-v1"
    )

    def __init__(
        self,
        *,
        runner: ValidationRunner | None = None,
        evaluator: DynamicValidationEvaluator | None = None,
        comparator: ValidationReplayComparator | None = None,
    ) -> None:
        self._runner = (
            runner
            if runner is not None
            else ValidationRunner()
        )
        self._evaluator = (
            evaluator
            if evaluator is not None
            else DynamicValidationEvaluator()
        )
        self._comparator = (
            comparator
            if comparator is not None
            else ValidationReplayComparator()
        )

    async def replay(
        self,
        request: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        before_evidence = self._evaluate(
            request=request,
            execution=request.before_execution,
        )

        after_execution = await self._runner.run(
            ValidationExecutionRequest(
                plan=request.plan,
            )
        )

        after_evidence = self._evaluate(
            request=request,
            execution=after_execution,
        )

        comparison = self._comparator.compare(
            ValidationReplayCompareRequest(
                before=before_evidence,
                after=after_evidence,
            )
        )

        return ValidationReplayResponse(
            orchestrator=self.orchestrator,
            threat_id=request.threat_id,
            category=request.category,
            before_execution=(
                request.before_execution
            ),
            before_evidence=before_evidence,
            after_execution=after_execution,
            after_evidence=after_evidence,
            comparison=comparison,
        )

    def _evaluate(
        self,
        *,
        request: ValidationReplayRequest,
        execution,
    ):
        return self._evaluator.evaluate(
            DynamicValidationEvidenceRequest(
                threat_id=request.threat_id,
                category=request.category,
                execution=execution,
                success_criteria=(
                    request.success_criteria
                ),
            )
        )
