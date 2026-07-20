import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from aegis.schemas.analysis import ScannerEvidence


class BanditScanner:
    def __init__(self) -> None:
        self.name = "bandit"

    @staticmethod
    def supports_language(
        language: str,
    ) -> bool:
        return language.lower().strip() == "python"

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        if not self.supports_language(language):
            return []

        suffix = Path(filename).suffix or ".py"

        with tempfile.TemporaryDirectory(
            prefix="aegis-bandit-",
        ) as temp_dir:
            file_path = (
                Path(temp_dir)
                / f"source{suffix}"
            )

            file_path.write_text(
                code,
                encoding="utf-8",
            )

            try:
                process = (
                    await asyncio.create_subprocess_exec(
                        "bandit",
                        "-f",
                        "json",
                        "-q",
                        str(file_path),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                )
            except FileNotFoundError:
                return []

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=45,
                )
            except TimeoutError:
                process.kill()
                await process.communicate()

                raise RuntimeError(
                    "Bandit scan timed out."
                )

            # Bandit returns 1 when findings exist.
            if process.returncode not in (0, 1):
                error_text = stderr.decode(
                    "utf-8",
                    errors="replace",
                ).strip()

                raise RuntimeError(
                    "Bandit failed with exit code "
                    f"{process.returncode}: "
                    f"{error_text}"
                )

            try:
                payload: dict[str, Any] = (
                    json.loads(
                        stdout.decode("utf-8")
                    )
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "Bandit returned invalid JSON."
                ) from exc

            return [
                self._normalize_result(
                    result=result,
                    original_filename=filename,
                    source_code=code,
                )
                for result in payload.get(
                    "results",
                    [],
                )
                if isinstance(result, dict)
            ]

    @staticmethod
    def _normalize_result(
        *,
        result: dict[str, Any],
        original_filename: str,
        source_code: str,
    ) -> ScannerEvidence:
        line_start = int(
            result.get("line_number", 1)
        )

        line_range = result.get(
            "line_range",
            [],
        )

        if (
            isinstance(line_range, list)
            and line_range
        ):
            line_end = max(
                int(value)
                for value in line_range
            )
        else:
            line_end = line_start

        source_lines = source_code.splitlines()

        code = "\n".join(
            source_lines[
                max(line_start - 1, 0):
                min(
                    line_end,
                    len(source_lines),
                )
            ]
        ) or None

        test_id = str(
            result.get(
                "test_id",
                "unknown",
            )
        )

        test_name = str(
            result.get(
                "test_name",
                "bandit-finding",
            )
        )

        severity = str(
            result.get(
                "issue_severity",
                "LOW",
            )
        ).lower()

        confidence = str(
            result.get(
                "issue_confidence",
                "UNDEFINED",
            )
        )

        message = str(
            result.get(
                "issue_text",
                "Bandit security finding",
            )
        )

        more_info = str(
            result.get(
                "more_info",
                "",
            )
        ).strip()

        if more_info:
            message = (
                f"{message} "
                f"More information: {more_info}"
            )

        return ScannerEvidence(
            tool="bandit",
            rule_id=(
                f"bandit.python."
                f"{test_id.lower()}."
                f"{test_name.replace('_', '-')}"
            ),
            message=(
                f"{message} "
                f"Bandit confidence: {confidence}."
            ),
            severity=severity,
            file=original_filename,
            line_start=line_start,
            line_end=line_end,
            code=code,
            cwe=[],
            owasp=[],
        )
