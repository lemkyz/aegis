import json
from typing import Any

from openai import AsyncOpenAI

from aegis.config.settings import get_settings
from aegis.utils.text import strip_markdown_code_fence
from aegis.schemas.analysis import ScannerEvidence, SecurityFinding


class NvidiaModelClient:
    def __init__(self) -> None:
        settings = get_settings()

        self.model = settings.nvidia_model
        self.client = AsyncOpenAI(
            api_key=settings.nvidia_api_key,
            base_url=settings.nvidia_base_url,
            timeout=settings.ai_request_timeout_seconds,
            max_retries=settings.ai_max_retries,
        )

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
    ) -> list[SecurityFinding]:
        system_prompt = """
You are Aegis Security Reviewer.

Analyze source code defensively using both the source code and
deterministic scanner evidence.

Rules:
- Do not invent vulnerabilities.
- Scanner results are evidence, not absolute truth.
- Identify false positives where appropriate.
- Tie conclusions to exact code behavior.
- Return only valid JSON.
- Do not use Markdown code fences.
- Do not provide instructions for attacking unauthorized systems.
- Preserve relevant scanner evidence in each final finding.

Return exactly this JSON structure:

{
  "findings": [
    {
      "title": "string",
      "severity": "info | low | medium | high | critical",
      "confidence": 0.0,
      "summary": "string",
      "evidence": ["string"],
      "scanner_evidence": [
        {
          "tool": "string",
          "rule_id": "string",
          "message": "string",
          "severity": "string",
          "file": "string",
          "line_start": 1,
          "line_end": 1,
          "code": "string or null"
        }
      ],
      "cwe": ["CWE-123"],
      "owasp": ["A01:2021"],
      "vulnerable_lines": [1],
      "false_positive_notes": ["string"],
      "recommended_fix": "string",
      "proposed_patch": "string or null"
    }
  ]
}

If no meaningful vulnerability exists, return:

{"findings": []}
""".strip()

        scanner_json = json.dumps(
            [item.model_dump() for item in scanner_evidence],
            ensure_ascii=False,
            indent=2,
        )

        user_prompt = f"""
Filename: {filename}
Language: {language}

Deterministic scanner evidence:

{scanner_json}

Analyze the following source code and determine whether each
scanner result represents a genuine vulnerability.

--- BEGIN SOURCE CODE ---
{code}
--- END SOURCE CODE ---
""".strip()

        response = await self.client.chat.completions.create(
            model=self.model,
            temperature=0.1,
            max_tokens=1600,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
        )

        content = response.choices[0].message.content

        if not content:
            raise RuntimeError("The model returned an empty response.")

        try:
            parsed: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"The model returned invalid JSON: {content[:500]}"
            ) from exc

        raw_findings = parsed.get("findings", [])

        validated_findings: list[SecurityFinding] = []

        for finding in raw_findings:
            validated = SecurityFinding.model_validate(finding)

            validated.proposed_patch = strip_markdown_code_fence(
                validated.proposed_patch
            )

            validated_findings.append(validated)

        return validated_findings