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


def test_eslint_scanner_routes_javascript_and_typescript() -> None:
    from aegis.security.eslint import (
        EslintSecurityScanner,
    )

    scanner = EslintSecurityScanner()

    assert scanner.supports_language(
        "javascript"
    )
    assert scanner.supports_language(
        "typescript"
    )
    assert scanner.supports_language(
        "javascriptreact"
    )
    assert scanner.supports_language(
        "typescriptreact"
    )

    assert not scanner.supports_language(
        "python"
    )


def test_correlates_matching_cross_scanner_evidence() -> None:
    semgrep = ScannerEvidence(
        tool="semgrep",
        rule_id=(
            "aegis.python."
            "command-injection.subprocess"
        ),
        message="Shell command uses untrusted input.",
        severity="high",
        file="danger.py",
        line_start=2,
        line_end=2,
        code=(
            'subprocess.call("ls " + user_input, '
            "shell=True)"
        ),
        cwe=["CWE-78"],
        owasp=["A03:2021"],
    )

    bandit = ScannerEvidence(
        tool="bandit",
        rule_id=(
            "bandit.python.b602."
            "subprocess-popen-with-shell-equals-true"
        ),
        message="subprocess call with shell=True.",
        severity="medium",
        file="danger.py",
        line_start=2,
        line_end=2,
        code=(
            'subprocess.call("ls " + user_input, '
            "shell=True)"
        ),
        cwe=[],
        owasp=[],
    )

    correlated = (
        SecurityScannerOrchestrator
        ._correlate(
            [
                semgrep,
                bandit,
            ]
        )
    )

    assert len(correlated) == 1

    result = correlated[0]

    assert result.corroborated_by == [
        "semgrep",
        "bandit",
    ]

    assert result.related_rule_ids == [
        semgrep.rule_id,
        bandit.rule_id,
    ]

    assert result.cwe == ["CWE-78"]
    assert result.owasp == ["A03:2021"]


def test_does_not_merge_unrelated_nearby_findings() -> None:
    first = ScannerEvidence(
        tool="semgrep",
        rule_id="aegis.python.sql-injection",
        message="SQL injection",
        severity="high",
        file="example.py",
        line_start=3,
        line_end=3,
        code="db.execute(query)",
        cwe=["CWE-89"],
        owasp=[],
    )

    second = ScannerEvidence(
        tool="bandit",
        rule_id="bandit.python.b105.hardcoded-password",
        message="Hardcoded password",
        severity="medium",
        file="example.py",
        line_start=4,
        line_end=4,
        code='password = "secret"',
        cwe=[],
        owasp=[],
    )

    correlated = (
        SecurityScannerOrchestrator
        ._correlate(
            [
                first,
                second,
            ]
        )
    )

    assert len(correlated) == 2
