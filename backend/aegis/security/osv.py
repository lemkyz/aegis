import asyncio
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from aegis.schemas.dependencies import (
    DependencyPackage,
    DependencyScanResponse,
    DependencySeverity,
    DependencyVulnerability,
)


class OsvDependencyScanner:
    api_url = "https://api.osv.dev/v1/query"

    def __init__(self) -> None:
        self.name = "osv"

    async def scan(
        self,
        packages: list[DependencyPackage],
    ) -> DependencyScanResponse:
        tasks = [
            self._query_package(package)
            for package in packages
        ]

        package_results = await asyncio.gather(
            *tasks,
            return_exceptions=True,
        )

        vulnerabilities: list[DependencyVulnerability] = []

        for package, result in zip(
            packages,
            package_results,
            strict=True,
        ):
            if isinstance(result, Exception):
                print(
                    "OSV dependency query failed for "
                    f"{package.ecosystem}/{package.name}"
                    f"@{package.version}: {result}"
                )
                continue

            vulnerabilities.extend(result)

        vulnerable_packages = len(
            {
                (
                    item.ecosystem,
                    item.package_name,
                    item.installed_version,
                )
                for item in vulnerabilities
            }
        )

        return DependencyScanResponse(
            scanner=self.name,
            packages_scanned=len(packages),
            vulnerable_packages=vulnerable_packages,
            vulnerabilities=vulnerabilities,
        )

    async def _query_package(
        self,
        package: DependencyPackage,
    ) -> list[DependencyVulnerability]:
        payload = {
            "version": package.version,
            "package": {
                "name": package.name,
                "ecosystem": package.ecosystem,
            },
        }

        response = await asyncio.to_thread(
            self._post_json,
            payload,
        )

        return [
            self._normalize_vulnerability(
                vulnerability,
                package,
            )
            for vulnerability in response.get("vulns", [])
        ]

    def _post_json(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")

        request = Request(
            self.api_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Aegis-Security/0.1.0",
            },
        )

        try:
            with urlopen(request, timeout=20) as response:
                return json.loads(
                    response.read().decode("utf-8")
                )
        except HTTPError as exc:
            error_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            raise RuntimeError(
                f"OSV returned HTTP {exc.code}: "
                f"{error_body}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                f"OSV network request failed: {exc.reason}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "OSV returned invalid JSON."
            ) from exc

    @classmethod
    def _normalize_vulnerability(
        cls,
        vulnerability: dict[str, Any],
        package: DependencyPackage,
    ) -> DependencyVulnerability:
        references = [
            str(reference.get("url", "")).strip()
            for reference in vulnerability.get(
                "references",
                [],
            )
            if str(reference.get("url", "")).strip()
        ]

        return DependencyVulnerability(
            id=str(
                vulnerability.get("id", "UNKNOWN")
            ),
            aliases=[
                str(alias)
                for alias in vulnerability.get(
                    "aliases",
                    [],
                )
            ],
            package_name=package.name,
            installed_version=package.version,
            ecosystem=package.ecosystem,
            manifest=package.manifest,
            direct=package.direct,
            summary=str(
                vulnerability.get(
                    "summary",
                    "Known dependency vulnerability",
                )
            ),
            details=str(
                vulnerability.get("details", "")
            ),
            severity=cls._extract_severity(
                vulnerability
            ),
            fixed_versions=cls._extract_fixed_versions(
                vulnerability,
                package,
            ),
            references=references[:10],
            published=vulnerability.get("published"),
            modified=vulnerability.get("modified"),
        )

    @staticmethod
    def _extract_severity(
        vulnerability: dict[str, Any],
    ) -> DependencySeverity:
        database_specific = vulnerability.get(
            "database_specific",
            {},
        )

        raw_severity = str(
            database_specific.get("severity", "")
        ).strip().lower()

        aliases = {
            "moderate": "medium",
            "important": "high",
        }

        normalized = aliases.get(
            raw_severity,
            raw_severity,
        )

        if normalized in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return normalized  # type: ignore[return-value]

        return "unknown"

    @staticmethod
    def _extract_fixed_versions(
        vulnerability: dict[str, Any],
        package: DependencyPackage,
    ) -> list[str]:
        fixed_versions: set[str] = set()

        for affected in vulnerability.get(
            "affected",
            [],
        ):
            affected_package = affected.get(
                "package",
                {},
            )

            if (
                affected_package.get("name")
                != package.name
                or affected_package.get("ecosystem")
                != package.ecosystem
            ):
                continue

            for version_range in affected.get(
                "ranges",
                [],
            ):
                for event in version_range.get(
                    "events",
                    [],
                ):
                    fixed = event.get("fixed")

                    if fixed:
                        fixed_versions.add(str(fixed))

        return sorted(fixed_versions)
