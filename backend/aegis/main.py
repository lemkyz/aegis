from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, HTTPException

from aegis.config.settings import get_settings
from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.analysis import AnalyzeCodeRequest, AnalyzeCodeResponse
from aegis.schemas.attack_surface import (
    AttackSurfaceScanRequest,
    AttackSurfaceScanResponse,
)
from aegis.schemas.threat_model import (
    ThreatModelScanRequest,
    ThreatModelScanResponse,
)
from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
    ValidationAuthorizationResponse,
    ValidationExecutionPlanResponse,
    ValidationPlanRequest,
)
from aegis.schemas.dependencies import (
    DependencyManifestScanRequest,
    DependencyManifestScanResponse,
    DependencyPackage,
    DependencyScanRequest,
    DependencyScanResponse,
)
from aegis.security.attack_surface import AttackSurfaceMapper
from aegis.security.dependency_files import parse_dependency_file
from aegis.security.osv import OsvDependencyScanner
from aegis.security.threat_model import ThreatModeler
from aegis.security.authorization import (
    ValidationAuthorizer,
)
from aegis.security.validation_plan import (
    ValidationPlanBuilder,
)


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-native secure software engineering backend",
)

analyzer = SecurityAnalyzer()
attack_surface_mapper = AttackSurfaceMapper()
threat_modeler = ThreatModeler(
    mapper=attack_surface_mapper,
)
dependency_scanner = OsvDependencyScanner()
validation_authorizer = ValidationAuthorizer()
validation_plan_builder = ValidationPlanBuilder(
    authorizer=validation_authorizer,
)


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
    "/v1/attack-surface/scan",
    response_model=AttackSurfaceScanResponse,
)
async def scan_attack_surface(
    request: AttackSurfaceScanRequest,
) -> AttackSurfaceScanResponse:
    """
    Build a deterministic static map of exposed routes,
    trust boundaries, and security-sensitive operations.
    """
    try:
        return attack_surface_mapper.scan(
            request.files
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Attack-surface mapping failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/threat-model/scan",
    response_model=ThreatModelScanResponse,
)
async def scan_threat_model(
    request: ThreatModelScanRequest,
) -> ThreatModelScanResponse:
    """
    Build a deterministic threat model from the
    workspace attack surface.
    """
    try:
        return threat_modeler.scan(
            request.files
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Threat modeling failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/authorize",
    response_model=ValidationAuthorizationResponse,
)
async def authorize_validation(
    request: ValidationAuthorizationRequest,
) -> ValidationAuthorizationResponse:
    """
    Validate explicit authorization, target scope,
    and safe resource limits before dynamic execution.
    This endpoint does not execute tests or commands.
    """
    try:
        return validation_authorizer.authorize(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Validation authorization failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/plan",
    response_model=ValidationExecutionPlanResponse,
)
async def plan_validation(
    request: ValidationPlanRequest,
) -> ValidationExecutionPlanResponse:
    """
    Build an inspectable isolated-execution plan.
    This endpoint does not run Docker or any command.
    """
    try:
        return validation_plan_builder.build(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Validation planning failed: "
                f"{exc}"
            ),
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

