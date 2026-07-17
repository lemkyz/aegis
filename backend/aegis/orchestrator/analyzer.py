from aegis.models.nvidia import NvidiaModelClient
from aegis.schemas.analysis import AnalyzeCodeRequest, AnalyzeCodeResponse


class SecurityAnalyzer:
    def __init__(self) -> None:
        self.model_client = NvidiaModelClient()

    async def analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        findings = await self.model_client.analyze_security(
            code=request.code,
            language=request.language,
            filename=request.filename,
        )

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model=self.model_client.model,
            findings=findings,
        )