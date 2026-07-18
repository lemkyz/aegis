from aegis.models.nvidia import NvidiaModelClient
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

    async def fast_analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        print("1. Fast Scan: Semgrep başlıyor...")

        scanner_evidence = await self.scanner.scan(
            code=request.code,
            language=request.language,
            filename=request.filename,
        )

        print(
            f"2. Fast Scan tamamlandı. "
            f"{len(scanner_evidence)} kanıt bulundu."
        )

        findings = [
            self._scanner_evidence_to_finding(evidence)
            for evidence in scanner_evidence
        ]

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model="not-used",
            scanner=self.scanner.name,
            findings=findings,
        )

    async def deep_analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        print("1. Deep Analysis: Semgrep başlıyor...")

        scanner_evidence = await self.scanner.scan(
            code=request.code,
            language=request.language,
            filename=request.filename,
        )

        print(
            f"2. Semgrep bitti. "
            f"{len(scanner_evidence)} kanıt bulundu."
        )

        if not scanner_evidence:
            print(
                "3. Semgrep bulgusu yok. "
                "NVIDIA modeli çağrılmadan analiz tamamlandı."
            )

            return AnalyzeCodeResponse(
                filename=request.filename,
                language=request.language,
                model="not-used",
                scanner=self.scanner.name,
                findings=[],
            )

        print("3. NVIDIA derin analizi başlıyor...")

        findings = await self.model_client.analyze_security(
            code=request.code,
            language=request.language,
            filename=request.filename,
            scanner_evidence=scanner_evidence,
        )

        print(
            f"4. NVIDIA analizi bitti. "
            f"{len(findings)} bulgu bulundu."
        )

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model=self.model_client.model,
            scanner=self.scanner.name,
            findings=findings,
        )

    async def analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        """
        Backward-compatible method used by the existing VS Code extension.
        """
        return await self.deep_analyze(request)

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

        title = evidence.rule_id.replace(
            "aegis.python.",
            "",
        ).replace(
            ".",
            " ",
        ).replace(
            "-",
            " ",
        ).title()

        return SecurityFinding(
            title=title,
            severity=severity,
            confidence=0.85,
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
                )
            ],
            recommended_fix=(
                "Review the flagged code and run Deep Analysis "
                "for a context-aware remediation recommendation."
            ),
            proposed_patch=None,
        )
