import asyncio

from aegis.schemas.analysis import ScannerEvidence
from aegis.security.orchestrator import (
    SecurityScannerOrchestrator,
)


class SuccessfulScanner:
    name = "successful"

    def supports_language(
        self,
        language: str,
    ) -> bool:
        return language == "python"

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        return [
            ScannerEvidence(
                tool=self.name,
                rule_id="test.rule",
                message="test finding",
                severity="medium",
                file=filename,
                line_start=1,
                line_end=1,
                code=code.splitlines()[0],
                cwe=[],
                owasp=[],
            )
        ]


class FailingScanner:
    name = "failing"

    def supports_language(
        self,
        language: str,
    ) -> bool:
        return language == "python"

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        raise RuntimeError(
            "scanner exploded"
        )


def test_scanner_failures_are_isolated() -> None:
    async def run_test() -> None:
        orchestrator = (
            SecurityScannerOrchestrator(
                [
                    SuccessfulScanner(),
                    FailingScanner(),
                ]
            )
        )

        result = await orchestrator.scan(
            code="print('hello')",
            filename="example.py",
            language="python",
        )

        assert len(result.evidence) == 1

        assert [
            execution.status
            for execution in result.executions
        ] == [
            "completed",
            "failed",
        ]

    asyncio.run(run_test())
