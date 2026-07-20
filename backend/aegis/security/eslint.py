import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from aegis.schemas.analysis import ScannerEvidence


class EslintSecurityScanner:
    def __init__(self) -> None:
        self.name = "eslint-security"

        self.scanner_root = (
            Path(__file__).resolve().parents[2]
            / "scanners"
            / "eslint"
        )

        self.executable = (
            self.scanner_root
            / "node_modules"
            / ".bin"
            / "eslint"
        )

        self.config_path = (
            self.scanner_root
            / "aegis-eslint.config.mjs"
        )

    @staticmethod
    def supports_language(
        language: str,
    ) -> bool:
        return language.lower().strip() in {
            "javascript",
            "javascriptreact",
            "typescript",
            "typescriptreact",
        }

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        if not self.supports_language(language):
            return []

        if (
            not self.executable.exists()
            or not self.config_path.exists()
        ):
            return []

        suffix = self._suffix_for_language(
            language,
            filename,
        )

        with tempfile.TemporaryDirectory(
            prefix=".aegis-eslint-",
            dir=self.scanner_root,
        ) as temp_dir:
            file_path = (
                Path(temp_dir)
                / f"source{suffix}"
            )

            file_path.write_text(
                code,
                encoding="utf-8",
            )

            process = (
                await asyncio.create_subprocess_exec(
                    str(self.executable),
                    "--config",
                    str(self.config_path),
                    "--format",
                    "json",
                    "--no-ignore",
                    str(file_path),
                    cwd=str(self.scanner_root),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=45,
                )
            except TimeoutError:
                process.kill()
                await process.communicate()

                raise RuntimeError(
                    "ESLint security scan timed out."
                )

            # ESLint returns 1 when lint findings exist.
            if process.returncode not in (0, 1):
                error_text = stderr.decode(
                    "utf-8",
                    errors="replace",
                ).strip()

                raise RuntimeError(
                    "ESLint security scan failed with "
                    f"exit code {process.returncode}: "
                    f"{error_text}"
                )

            try:
                payload = json.loads(
                    stdout.decode("utf-8")
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "ESLint returned invalid JSON."
                ) from exc

            if not isinstance(payload, list):
                raise RuntimeError(
                    "ESLint returned an unexpected result."
                )

            evidence: list[ScannerEvidence] = []

            for file_result in payload:
                if not isinstance(file_result, dict):
                    continue

                messages = file_result.get(
                    "messages",
                    [],
                )

                if not isinstance(messages, list):
                    continue

                for message in messages:
                    if not isinstance(message, dict):
                        continue

                    normalized = self._normalize_result(
                        message=message,
                        original_filename=filename,
                        source_code=code,
                    )

                    if normalized is not None:
                        evidence.append(normalized)

            return evidence

    @staticmethod
    def _suffix_for_language(
        language: str,
        filename: str,
    ) -> str:
        existing = Path(filename).suffix

        if existing:
            return existing

        suffixes = {
            "javascript": ".js",
            "javascriptreact": ".jsx",
            "typescript": ".ts",
            "typescriptreact": ".tsx",
        }

        return suffixes.get(
            language.lower(),
            ".js",
        )

    @staticmethod
    def _normalize_result(
        *,
        message: dict[str, Any],
        original_filename: str,
        source_code: str,
    ) -> ScannerEvidence | None:
        rule_id = message.get("ruleId")

        if not isinstance(rule_id, str):
            return None

        if not rule_id.startswith("security/"):
            return None

        line_start = int(
            message.get("line", 1)
        )

        line_end = int(
            message.get(
                "endLine",
                line_start,
            )
        )

        source_lines = source_code.splitlines()

        code = "\n".join(
            source_lines[
                max(line_start - 1, 0):
                min(line_end, len(source_lines))
            ]
        ) or None

        severity_number = int(
            message.get("severity", 1)
        )

        severity = (
            "high"
            if severity_number >= 2
            else "medium"
        )

        message_text = str(
            message.get(
                "message",
                "ESLint security finding",
            )
        )

        normalized_rule = (
            rule_id
            .replace("security/", "")
            .replace("_", "-")
        )

        return ScannerEvidence(
            tool="eslint-security",
            rule_id=(
                "eslint.javascript.security."
                f"{normalized_rule}"
            ),
            message=message_text,
            severity=severity,
            file=original_filename,
            line_start=line_start,
            line_end=line_end,
            code=code,
            cwe=[],
            owasp=[],
        )
