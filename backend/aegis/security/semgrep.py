import asyncio
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from aegis.schemas.analysis import ScannerEvidence


class SemgrepScanner:
    def __init__(self) -> None:
        self.name = "semgrep"
        self.rules_root = (
            Path(__file__).resolve().parents[3]
            / "security-engine"
            / "rules"
        )

    def supports_language(
        self,
        language: str,
    ) -> bool:
        normalized = language.lower().strip()

        aliases = {
            "javascriptreact": "javascript",
            "typescriptreact": "typescript",
        }

        rule_language = aliases.get(
            normalized,
            normalized,
        )

        return (
            self.rules_root / rule_language
        ).exists()

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

            rules_path = self._rules_path_for_language(
                language,
            )

            process = await asyncio.create_subprocess_exec(
                "semgrep",
                "scan",
                "--config",
                str(rules_path),
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
                self._normalize_result(
                    result,
                    filename,
                    code,
                )
                for result in payload.get("results", [])
            ]

    def _rules_path_for_language(
        self,
        language: str,
    ) -> Path:
        normalized = language.lower()

        aliases = {
            "javascriptreact": "javascript",
            "typescriptreact": "typescript",
        }

        rule_language = aliases.get(
            normalized,
            normalized,
        )

        rules_path = self.rules_root / rule_language

        if not rules_path.exists():
            raise RuntimeError(
                f"No Semgrep rules are configured for "
                f"language: {language}"
            )

        return rules_path

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
        matches = list(
            re.finditer(
                r"aegis\.(?:python|javascript|typescript)\.[A-Za-z0-9_.-]+",
                rule_id,
            )
        )

        if matches:
            return matches[-1].group(0)

        generic_index = rule_id.rfind("aegis.")

        if generic_index >= 0:
            return rule_id[generic_index:]

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
        source_code: str,
    ) -> ScannerEvidence:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        severity = str(
            extra.get("severity", "INFO")
        ).lower()

        code_lines = extra.get("lines")

        if not code_lines or code_lines == "requires login":
            line_start = int(
                result.get("start", {}).get("line", 1)
            )
            line_end = int(
                result.get("end", {}).get("line", line_start)
            )

            source_lines = source_code.splitlines()

            code_lines = "\n".join(
                source_lines[
                    max(line_start - 1, 0):
                    min(line_end, len(source_lines))
                ]
            ) or None

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
