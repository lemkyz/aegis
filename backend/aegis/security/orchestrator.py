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
            evidence=self._correlate(
                evidence
            ),
            executions=executions,
        )

    @classmethod
    def _correlate(
        cls,
        evidence: list[ScannerEvidence],
    ) -> list[ScannerEvidence]:
        groups: list[list[ScannerEvidence]] = []

        for item in evidence:
            matching_group: list[
                ScannerEvidence
            ] | None = None

            for group in groups:
                if any(
                    cls._same_security_claim(
                        item,
                        candidate,
                    )
                    for candidate in group
                ):
                    matching_group = group
                    break

            if matching_group is None:
                groups.append([item])
            else:
                matching_group.append(item)

        return [
            cls._merge_evidence_group(group)
            for group in groups
        ]

    @staticmethod
    def _same_security_claim(
        left: ScannerEvidence,
        right: ScannerEvidence,
    ) -> bool:
        if left.file != right.file:
            return False

        ranges_close = not (
            left.line_end + 1
            < right.line_start
            or right.line_end + 1
            < left.line_start
        )

        if not ranges_close:
            return False

        left_code = (
            " ".join(
                (left.code or "")
                .split()
            )
        )

        right_code = (
            " ".join(
                (right.code or "")
                .split()
            )
        )

        code_matches = bool(
            left_code
            and right_code
            and (
                left_code == right_code
                or left_code in right_code
                or right_code in left_code
            )
        )

        left_cwe = {
            value.upper()
            for value in left.cwe
        }

        right_cwe = {
            value.upper()
            for value in right.cwe
        }

        cwe_matches = bool(
            left_cwe
            and right_cwe
            and left_cwe & right_cwe
        )

        rule_family_matches = (
            SecurityScannerOrchestrator
            ._rule_family(left.rule_id)
            ==
            SecurityScannerOrchestrator
            ._rule_family(right.rule_id)
        )

        return (
            code_matches
            and (
                cwe_matches
                or rule_family_matches
                or left.tool != right.tool
            )
        )

    @staticmethod
    def _rule_family(
        rule_id: str,
    ) -> str:
        normalized = (
            rule_id
            .lower()
            .replace("_", "-")
        )

        families = (
            "sql-injection",
            "command-injection",
            "shell",
            "subprocess",
            "path-traversal",
            "unsafe-eval",
            "ssrf",
            "hardcoded-secret",
            "secret",
        )

        for family in families:
            if family in normalized:
                return family

        return normalized

    @staticmethod
    def _merge_evidence_group(
        group: list[ScannerEvidence],
    ) -> ScannerEvidence:
        severity_rank = {
            "info": 0,
            "low": 1,
            "warning": 2,
            "medium": 2,
            "error": 3,
            "high": 3,
            "critical": 4,
        }

        primary = max(
            group,
            key=lambda item: (
                severity_rank.get(
                    item.severity.lower(),
                    1,
                ),
                len(item.cwe),
                len(item.owasp),
                len(item.message),
            ),
        )

        tools = list(
            dict.fromkeys(
                item.tool
                for item in group
            )
        )

        rule_ids = list(
            dict.fromkeys(
                item.rule_id
                for item in group
            )
        )

        messages = list(
            dict.fromkeys(
                item.message
                for item in group
            )
        )

        cwe = list(
            dict.fromkeys(
                value
                for item in group
                for value in item.cwe
            )
        )

        owasp = list(
            dict.fromkeys(
                value
                for item in group
                for value in item.owasp
            )
        )

        merged_message = primary.message

        if len(messages) > 1:
            merged_message += (
                " Corroborating scanner evidence: "
                + " | ".join(
                    message
                    for message in messages
                    if message != primary.message
                )
            )

        return primary.model_copy(
            update={
                "message": merged_message,
                "line_start": min(
                    item.line_start
                    for item in group
                ),
                "line_end": max(
                    item.line_end
                    for item in group
                ),
                "cwe": cwe,
                "owasp": owasp,
                "corroborated_by": tools,
                "related_rule_ids": rule_ids,
            }
        )
