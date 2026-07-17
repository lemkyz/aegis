from aegis.models.nvidia import NvidiaModelClient
from aegis.schemas.analysis import (
    AnalyzeCodeRequest,
    AnalyzeCodeResponse,
)
from aegis.security.semgrep import SemgrepScanner


class SecurityAnalyzer:
    def __init__(self) -> None:
        self.model_client = NvidiaModelClient()
        self.scanner = SemgrepScanner()

    async def analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        print("1. Semgrep başlıyor...")

        scanner_evidence = await self.scanner.scan(
            code=request.code,
            language=request.language,
            filename=request.filename,
        )

        print(
            f"2. Semgrep bitti. "
            f"{len(scanner_evidence)} kanıt bulundu."
        )
        print("3. NVIDIA analizi başlıyor...")

        findings = await self.model_client.analyze_security(
            code=request.code,
            language=request.language,
            filename=request.filename,
            scanner_evidence=scanner_evidence,
        )

        print(f"4. NVIDIA bitti. {len(findings)} bulgu bulundu.")

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model=self.model_client.model,
            scanner=self.scanner.name,
            findings=findings,
        )