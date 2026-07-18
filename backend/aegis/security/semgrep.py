import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from aegis.schemas.analysis import ScannerEvidence


class SemgrepScanner:
    def __init__(self) -> None:
        self.name = "semgrep"
        self.rules_path = (
            Path(__file__).resolve().parents[3]
            / "security-engine"
            / "rules"
            / "python"
        )

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        suffix = self._suffix_for_language(language, filename)

        with tempfile.TemporaryDirectory(prefix="aegis-semgrep-") as temp_dir:
            file_path = Path(temp_dir) / f"source{suffix}"
            file_path.write_text(code, encoding="utf-8")

            process = await asyncio.create_subprocess_exec(
                "semgrep",
                "scan",
                "--config",
                str(self.rules_path),
                "--json",
                "--quiet",
                "--no-git-ignore",
                str(file_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=45,
                )
            except TimeoutError:
                process.kill()
                await process.communicate()
                raise RuntimeError("Semgrep scan timed out.")

            if process.returncode not in (0, 1):
                error_text = stderr.decode(
                    "utf-8",
                    errors="replace",
                ).strip()

                raise RuntimeError(
                    f"Semgrep failed with exit code "
                    f"{process.returncode}: {error_text}"
                )

            try:
                payload: dict[str, Any] = json.loads(
                    stdout.decode("utf-8")
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "Semgrep returned invalid JSON."
                ) from exc

            return [
                self._normalize_result(result, filename)
                for result in payload.get("results", [])
            ]

    @staticmethod
    def _suffix_for_language(
        language: str,
        filename: str,
    ) -> str:
        existing_suffix = Path(filename).suffix

        if existing_suffix:
            return existing_suffix

        suffixes = {
            "python": ".py",
            "javascript": ".js",
            "typescript": ".ts",
        }

        return suffixes.get(language.lower(), ".txt")

    @staticmethod
    def _normalize_rule_id(rule_id: str) -> str:
        marker = "aegis.python."
        marker_index = rule_id.find(marker)

        if marker_index >= 0:
            return rule_id[marker_index:]

        return rule_id

    @staticmethod
    def _normalize_metadata_list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [
                str(item).strip()
                for item in value
                if str(item).strip()
            ]

        if value is None:
            return []

        normalized = str(value).strip()

        if not normalized:
            return []

        return [normalized]

    @classmethod
    def _normalize_result(
        cls,
        result: dict[str, Any],
        original_filename: str,
    ) -> ScannerEvidence:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        severity = str(
            extra.get("severity", "INFO")
        ).lower()

        code_lines = extra.get("lines")

        if not code_lines or code_lines == "requires login":
            code_lines = None

        message = str(
            extra.get("message", "Semgrep finding")
        )

        raw_rule_id = str(
            result.get("check_id", "unknown-rule")
        )

        return ScannerEvidence(
            tool="semgrep",
            rule_id=cls._normalize_rule_id(raw_rule_id),
            message=message,
            severity=severity,
            file=original_filename,
            line_start=int(
                result.get("start", {}).get("line", 1)
            ),
            line_end=int(
                result.get("end", {}).get("line", 1)
            ),
            code=code_lines,
            cwe=cls._normalize_metadata_list(
                metadata.get("cwe")
            ),
            owasp=cls._normalize_metadata_list(
                metadata.get("owasp")
            ),
        )
