from fastapi import FastAPI, HTTPException

from aegis.config.settings import get_settings
from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.analysis import AnalyzeCodeRequest, AnalyzeCodeResponse


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-native secure software engineering backend",
)

analyzer = SecurityAnalyzer()


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
    }


@app.post("/v1/analyze", response_model=AnalyzeCodeResponse)
async def analyze_code(
    request: AnalyzeCodeRequest,
) -> AnalyzeCodeResponse:
    """
    Backward-compatible deep analysis endpoint.
    """
    try:
        return await analyzer.deep_analyze(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Security analysis failed: {exc}",
        ) from exc


@app.post("/v1/analyze/fast", response_model=AnalyzeCodeResponse)
async def fast_analyze_code(
    request: AnalyzeCodeRequest,
) -> AnalyzeCodeResponse:
    """
    Fast scanner-only analysis. Does not call an AI model.
    """
    try:
        return await analyzer.fast_analyze(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Fast security scan failed: {exc}",
        ) from exc


@app.post("/v1/analyze/deep", response_model=AnalyzeCodeResponse)
async def deep_analyze_code(
    request: AnalyzeCodeRequest,
) -> AnalyzeCodeResponse:
    """
    Semgrep evidence followed by AI analysis when evidence exists.
    """
    try:
        return await analyzer.deep_analyze(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Deep security analysis failed: {exc}",
        ) from exc
