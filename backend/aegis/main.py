from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, HTTPException

from aegis.config.settings import get_settings
from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.analysis import AnalyzeCodeRequest, AnalyzeCodeResponse
from aegis.schemas.dependencies import (
    DependencyManifestScanRequest,
    DependencyManifestScanResponse,
    DependencyPackage,
    DependencyScanRequest,
    DependencyScanResponse,
)
from aegis.security.dependency_files import parse_dependency_file
from aegis.security.osv import OsvDependencyScanner


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-native secure software engineering backend",
)

analyzer = SecurityAnalyzer()
dependency_scanner = OsvDependencyScanner()


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

@app.post(
    "/v1/dependencies/manifests/scan",
    response_model=DependencyManifestScanResponse,
)
async def scan_dependency_manifests(
    request: DependencyManifestScanRequest,
) -> DependencyManifestScanResponse:
    """
    Parse supported dependency files and query OSV for the
    exact resolved package versions.
    """
    try:
        packages: list[DependencyPackage] = []

        with TemporaryDirectory(
            prefix="aegis-dependencies-",
        ) as directory:
            temporary_root = Path(directory)

            for index, manifest in enumerate(
                request.manifests
            ):
                safe_name = Path(
                    manifest.filename
                ).name

                if not safe_name:
                    continue

                manifest_directory = (
                    temporary_root / str(index)
                )

                manifest_directory.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                temporary_path = (
                    manifest_directory / safe_name
                )

                temporary_path.write_text(
                    manifest.content,
                    encoding="utf-8",
                )

                parsed = parse_dependency_file(
                    temporary_path
                )

                packages.extend(
                    package.model_copy(
                        update={
                            "manifest": manifest.manifest,
                        }
                    )
                    for package in parsed
                )

        deduplicated: dict[
            tuple[str, str, str, str],
            DependencyPackage,
        ] = {}

        for package in packages:
            key = (
                package.ecosystem,
                package.name.lower(),
                package.version,
                package.manifest,
            )

            previous = deduplicated.get(key)

            if (
                previous is None
                or (
                    package.direct
                    and not previous.direct
                )
            ):
                deduplicated[key] = package

        normalized_packages = sorted(
            deduplicated.values(),
            key=lambda package: (
                package.ecosystem,
                package.name.lower(),
                package.version,
                package.manifest,
            ),
        )

        if not normalized_packages:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exact dependency versions were "
                    "found in the supplied manifests."
                ),
            )

        scan = await dependency_scanner.scan(
            normalized_packages
        )

        return DependencyManifestScanResponse(
            packages=normalized_packages,
            scan=scan,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Dependency manifest scan failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/dependencies/scan",
    response_model=DependencyScanResponse,
)
async def scan_dependencies(
    request: DependencyScanRequest,
) -> DependencyScanResponse:
    """
    Query known vulnerabilities for exact dependency versions.
    """
    try:
        return await dependency_scanner.scan(
            request.packages
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Dependency scan failed: {exc}",
        ) from exc

