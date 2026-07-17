import json
from typing import Any

from openai import AsyncOpenAI

from aegis.config.settings import get_settings
from aegis.schemas.analysis import SecurityFinding


class NvidiaModelClient:
    def __init__(self) -> None:
        settings = get_settings()

        self.model = settings.nvidia_model
        self.client = AsyncOpenAI(
            api_key=settings.nvidia_api_key,
            base_url=settings.nvidia_base_url,
            timeout=60.0,
            max_retries=2,
        )

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
    ) -> list[SecurityFinding]:
        system_prompt = """
You are Aegis Security Reviewer.

Analyze source code defensively and identify genuine security weaknesses.

Rules:
- Do not invent vulnerabilities.
- Clearly acknowledge uncertainty.
- Prefer evidence tied to exact code behavior.
- Return only valid JSON.
- Do not include Markdown fences.
- Do not provide instructions for attacking unauthorized systems.
- Proposed tests and validation must be suitable for authorized local environments.

Return a JSON object with this exact structure:

{
  "findings": [
    {
      "title": "string",
      "severity": "info | low | medium | high | critical",
      "confidence": 0.0,
      "summary": "string",
      "evidence": ["string"],
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

        user_prompt = f"""
Filename: {filename}
Language: {language}

Analyze the following source code:

--- BEGIN SOURCE CODE ---
{code}
--- END SOURCE CODE ---
""".strip()

        response = await self.client.chat.completions.create(
    model=self.model,
    temperature=0.1,
    max_tokens=2000,
    messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ],
)

        content = response.choices[0].message.content

        if not content:
            raise RuntimeError("The model returned an empty response.")

        parsed: dict[str, Any] = json.loads(content)
        raw_findings = parsed.get("findings", [])

        return [
            SecurityFinding.model_validate(finding)
            for finding in raw_findings
        ]