from aegis.schemas.validation import (
    ValidationReplayCompareRequest,
    ValidationReplayCompareResponse,
)


class ValidationReplayComparator:
    comparator = "aegis-dynamic-validation-replay-v1"

    def compare(
        self,
        request: ValidationReplayCompareRequest,
    ) -> ValidationReplayCompareResponse:
        before = request.before
        after = request.after

        reasons: list[str] = []
        denials: list[str] = []

        if before.threat_id != after.threat_id:
            denials.append(
                "Before and after evidence must reference "
                "the same threat identifier."
            )

        if before.category != after.category:
            denials.append(
                "Before and after evidence must use the "
                "same validation category."
            )

        if before.claim_id != after.claim_id:
            denials.append(
                "Before and after evidence must reference "
                "the same claim identifier."
            )

        if denials:
            return self._response(
                request=request,
                verdict="inconclusive",
                fixed=False,
                confidence=1.0,
                reasons=[
                    "The replay evidence could not be "
                    "compared safely."
                ],
                denials=denials,
            )

        if before.verdict != "confirmed":
            reasons.append(
                "The vulnerability was not dynamically "
                "confirmed before the fix."
            )
            reasons.append(
                "A successful security replay requires "
                "a confirmed vulnerable baseline."
            )

            return self._response(
                request=request,
                verdict="inconclusive",
                fixed=False,
                confidence=0.99,
                reasons=reasons,
                denials=denials,
            )

        if after.verdict == "not_reproduced":
            reasons.append(
                "The same validation was confirmed before "
                "the fix and did not reproduce afterward."
            )
            reasons.append(
                "Dynamic evidence supports that the "
                "validated exploit path was closed."
            )

            return self._response(
                request=request,
                verdict="fixed",
                fixed=True,
                confidence=min(
                    before.confidence,
                    after.confidence,
                    0.99,
                ),
                reasons=reasons,
                denials=denials,
            )

        if after.verdict == "confirmed":
            reasons.append(
                "The same validation still satisfies its "
                "success criteria after the fix."
            )
            reasons.append(
                "The validated exploit path remains "
                "dynamically reproducible."
            )

            return self._response(
                request=request,
                verdict="still_exploitable",
                fixed=False,
                confidence=min(
                    before.confidence,
                    after.confidence,
                    0.99,
                ),
                reasons=reasons,
                denials=denials,
            )

        reasons.append(
            "The post-fix validation did not produce a "
            "conclusive reproduction result."
        )
        reasons.append(
            "Blocked, timed-out, or failed executions "
            "cannot prove that the vulnerability is fixed."
        )

        return self._response(
            request=request,
            verdict="inconclusive",
            fixed=False,
            confidence=0.98,
            reasons=reasons,
            denials=denials,
        )

    def _response(
        self,
        *,
        request: ValidationReplayCompareRequest,
        verdict: str,
        fixed: bool,
        confidence: float,
        reasons: list[str],
        denials: list[str],
    ) -> ValidationReplayCompareResponse:
        return ValidationReplayCompareResponse(
            comparator=self.comparator,
            threat_id=request.before.threat_id,
            claim_id=request.before.claim_id,
            category=request.before.category,
            verdict=verdict,
            fixed=fixed,
            confidence=confidence,
            before_verdict=request.before.verdict,
            after_verdict=request.after.verdict,
            reasons=reasons,
            denials=denials,
        )
