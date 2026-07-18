from aegis.models.nvidia import NvidiaModelClient
from aegis.security.redaction import SecretRedactor
from aegis.security.secrets import SecretIntelligenceEngine
from aegis.schemas.analysis import (
    AnalyzeCodeRequest,
    AnalyzeCodeResponse,
    ScannerEvidence,
    SecurityFinding,
)
from aegis.security.semgrep import SemgrepScanner


class SecurityAnalyzer:
    def __init__(self) -> None:
        self.model_client = NvidiaModelClient()
        self.scanner = SemgrepScanner()
        self.redactor = SecretRedactor()
        self.secret_engine = SecretIntelligenceEngine()

    async def fast_analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        print("1. Fast Scan: Semgrep starting...")

        scanner_evidence = await self.scanner.scan(
            code=request.code,
            language=request.language,
            filename=request.filename,
        )

        scanner_evidence = (
            self.secret_engine.enrich_evidence_list(
                scanner_evidence
            )
        )

        print(
            f"2. Fast Scan completed. "
            f"{len(scanner_evidence)} evidence item(s) found."
        )

        redaction_session = self.redactor.create_session()

        safe_scanner_evidence = (
            redaction_session.redact_evidence_list(
                scanner_evidence
            )
        )

        findings = [
            self._scanner_evidence_to_finding(evidence)
            for evidence in safe_scanner_evidence
        ]

        findings = redaction_session.redact_findings(
            findings
        )

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model="not-used",
            scanner=self.scanner.name,
            analysis_status="skipped",
            result_source="scanner",
            findings=findings,
        )

    async def deep_analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        print("1. Deep Analysis: Semgrep starting...")

        scanner_evidence = await self.scanner.scan(
            code=request.code,
            language=request.language,
            filename=request.filename,
        )

        scanner_evidence = (
            self.secret_engine.enrich_evidence_list(
                scanner_evidence
            )
        )

        print(
            f"2. Semgrep completed. "
            f"{len(scanner_evidence)} evidence item(s) found."
        )

        if not scanner_evidence:
            print(
                "3. No scanner evidence found. "
                "The NVIDIA model was not called."
            )

            return AnalyzeCodeResponse(
                filename=request.filename,
                language=request.language,
                model="not-used",
                scanner=self.scanner.name,
                analysis_status="skipped",
                result_source="scanner",
                findings=[],
            )

        redaction_session = self.redactor.create_session()

        safe_scanner_evidence = (
            redaction_session.redact_evidence_list(
                scanner_evidence
            )
        )

        relevant_code = self._build_relevant_context(
            code=request.code,
            scanner_evidence=scanner_evidence,
            context_lines=20,
        )

        safe_relevant_code = (
            redaction_session.redact_text(
                relevant_code
            )
            or relevant_code
        )

        original_line_count = len(request.code.splitlines())
        relevant_line_count = len(relevant_code.splitlines())

        print(
            "3. Security context prepared: "
            f"{relevant_line_count}/{original_line_count} lines "
            "will be sent to the NVIDIA model."
        )
        print("4. NVIDIA deep analysis starting...")

        try:
            findings = await self.model_client.analyze_security(
                code=safe_relevant_code,
                language=request.language,
                filename=request.filename,
                scanner_evidence=safe_scanner_evidence,
            )

            findings = redaction_session.redact_findings(
                findings
            )
        except Exception as exc:
            print(
                "5. NVIDIA analysis failed. "
                f"Falling back to scanner findings: {exc}"
            )

            findings = [
                self._scanner_evidence_to_finding(evidence)
                for evidence in safe_scanner_evidence
            ]

            findings = redaction_session.redact_findings(
                findings
            )

            for finding in findings:
                finding.false_positive_notes.append(
                    "AI review was unavailable or returned an invalid response. "
                    "This result is based on deterministic scanner evidence."
                )

            return AnalyzeCodeResponse(
                filename=request.filename,
                language=request.language,
                model=f"{self.model_client.model} (fallback)",
                scanner=self.scanner.name,
                analysis_status="fallback",
                result_source="scanner_fallback",
                findings=findings,
            )

        print(
            f"5. NVIDIA analysis completed. "
            f"{len(findings)} finding(s) returned."
        )

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model=self.model_client.model,
            scanner=self.scanner.name,
            analysis_status="completed",
            result_source="ai",
            findings=findings,
        )

    async def analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        """
        Backward-compatible method used by older extension versions.
        """
        return await self.deep_analyze(request)

    @staticmethod
    def _build_relevant_context(
        *,
        code: str,
        scanner_evidence: list[ScannerEvidence],
        context_lines: int,
    ) -> str:
        source_lines = code.splitlines()

        if not source_lines:
            return code

        ranges: list[tuple[int, int]] = []

        for evidence in scanner_evidence:
            start_index = max(
                evidence.line_start - 1 - context_lines,
                0,
            )
            end_index = min(
                evidence.line_end + context_lines,
                len(source_lines),
            )

            ranges.append((start_index, end_index))

        ranges.sort()

        merged_ranges: list[tuple[int, int]] = []

        for start_index, end_index in ranges:
            if not merged_ranges:
                merged_ranges.append((start_index, end_index))
                continue

            previous_start, previous_end = merged_ranges[-1]

            if start_index <= previous_end:
                merged_ranges[-1] = (
                    previous_start,
                    max(previous_end, end_index),
                )
            else:
                merged_ranges.append((start_index, end_index))

        sections: list[str] = []

        for start_index, end_index in merged_ranges:
            start_line = start_index + 1
            end_line = end_index

            excerpt = "\n".join(
                source_lines[start_index:end_index]
            )

            sections.append(
                f"--- ORIGINAL FILE LINES "
                f"{start_line}-{end_line} ---\n"
                f"{excerpt}"
            )

        return "\n\n".join(sections)

    @staticmethod
    def _scanner_evidence_to_finding(
        evidence: ScannerEvidence,
    ) -> SecurityFinding:
        severity_map = {
            "INFO": "info",
            "WARNING": "medium",
            "ERROR": "high",
        }

        severity = severity_map.get(
            evidence.severity.upper(),
            "medium",
        )

        confidence = 0.85
        recommended_fix = (
            "Review the flagged code and run Deep Analysis "
            "for a context-aware remediation recommendation."
        )
        additional_notes: list[str] = []

        if evidence.secret:
            confidence = evidence.secret.confidence
            recommended_fix = evidence.secret.remediation

            additional_notes.append(
                "Secret classification: "
                f"{evidence.secret.provider} / "
                f"{evidence.secret.secret_type}."
            )

            if evidence.secret.fingerprint:
                additional_notes.append(
                    "Protected fingerprint: "
                    f"{evidence.secret.fingerprint}."
                )

            if evidence.secret.likely_placeholder:
                severity = "low"
                additional_notes.append(
                    "The value appears to be example, test, or "
                    "placeholder data. Confirm that no production "
                    "credential is present."
                )
            elif evidence.secret.rotation_required:
                additional_notes.append(
                    "Credential rotation is recommended."
                )

        rule_parts = evidence.rule_id.split(".")

        if (
            len(rule_parts) >= 3
            and rule_parts[0] == "aegis"
        ):
            rule_parts = rule_parts[2:]

        title = (
            " ".join(rule_parts)
            .replace("-", " ")
            .title()
        )

        return SecurityFinding(
            title=title,
            severity=severity,
            confidence=confidence,
            summary=evidence.message,
            evidence=[
                (
                    f"{evidence.tool} matched rule "
                    f"{evidence.rule_id} on lines "
                    f"{evidence.line_start}-{evidence.line_end}."
                )
            ],
            scanner_evidence=[evidence],
            cwe=evidence.cwe,
            owasp=evidence.owasp,
            vulnerable_lines=list(
                range(
                    evidence.line_start,
                    evidence.line_end + 1,
                )
            ),
            false_positive_notes=[
                (
                    "This is a scanner-only result. "
                    "Run Deep Analysis for AI review, "
                    "context evaluation, and a proposed patch."
                ),
                *additional_notes,
            ],
            recommended_fix=recommended_fix,
            proposed_patch=None,
        )
