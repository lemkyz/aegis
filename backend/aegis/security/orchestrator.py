import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from aegis.schemas.analysis import ScannerEvidence


class CodeScanner(Protocol):
    name: str

    def supports_language(
        self,
        language: str,
    ) -> bool:
        ...

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        ...


@dataclass(frozen=True)
class ScannerExecution:
    name: str
    status: str
    evidence_count: int
    error: str | None = None


@dataclass(frozen=True)
class ScannerOrchestrationResult:
    evidence: list[ScannerEvidence]
    executions: list[ScannerExecution]


class SecurityScannerOrchestrator:
    def __init__(
        self,
        scanners: Sequence[CodeScanner],
    ) -> None:
        self.scanners = list(scanners)

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> ScannerOrchestrationResult:
        selected = [
            scanner
            for scanner in self.scanners
            if scanner.supports_language(
                language
            )
        ]

        if not selected:
            return ScannerOrchestrationResult(
                evidence=[],
                executions=[],
            )

        results = await asyncio.gather(
            *(
                scanner.scan(
                    code=code,
                    filename=filename,
                    language=language,
                )
                for scanner in selected
            ),
            return_exceptions=True,
        )

        evidence: list[ScannerEvidence] = []
        executions: list[ScannerExecution] = []

        for scanner, result in zip(
            selected,
            results,
            strict=True,
        ):
            if isinstance(result, Exception):
                executions.append(
                    ScannerExecution(
                        name=scanner.name,
                        status="failed",
                        evidence_count=0,
                        error=str(result),
                    )
                )
                continue

            evidence.extend(result)

            executions.append(
                ScannerExecution(
                    name=scanner.name,
                    status="completed",
                    evidence_count=len(result),
                )
            )

        return ScannerOrchestrationResult(
            evidence=self._deduplicate(
                evidence
            ),
            executions=executions,
        )

    @staticmethod
    def _deduplicate(
        evidence: list[ScannerEvidence],
    ) -> list[ScannerEvidence]:
        unique: list[ScannerEvidence] = []

        seen: set[
            tuple[str, int, int, str]
        ] = set()

        for item in evidence:
            identity = (
                item.rule_id,
                item.line_start,
                item.line_end,
                item.code or "",
            )

            if identity in seen:
                continue

            seen.add(identity)
            unique.append(item)

        return unique
