import os
import hashlib
import hmac
import math
import re
from collections import Counter
from collections.abc import Iterable

from aegis.schemas.analysis import (
    ScannerEvidence,
    SecretClassification,
)


class SecretIntelligenceEngine:
    """
    Classifies secret scanner evidence before redaction.

    Raw secret values are used only in memory for classification and
    fingerprint generation. They are never stored in API responses.
    """

    _fingerprint_key_value = os.getenv(
        "AEGIS_FINGERPRINT_KEY",
        "",
    )

    if len(_fingerprint_key_value) < 32:
        raise RuntimeError(
            "AEGIS_FINGERPRINT_KEY must be configured with at least "
            "32 characters before Aegis starts."
        )

    _fingerprint_key = _fingerprint_key_value.encode("utf-8")

    _assignment_pattern = re.compile(
        r"""(?ix)
        (?P<name>[A-Za-z_][A-Za-z0-9_-]*)
        \s*(?:=|:)\s*
        (?P<quote>["'])
        (?P<value>[^"'\r\n]{4,})
        (?P=quote)
        """,
    )

    _database_url_pattern = re.compile(
        r"""(?ix)
        (?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)
        ://
        [^:\s/@]+
        :
        (?P<password>[^@\s/]+)
        @
        """,
    )

    _placeholder_pattern = re.compile(
        r"""(?ix)
        (?:
            example
            |sample
            |dummy
            |fake
            |test
            |testing
            |changeme
            |change[_-]?me
            |replace[_-]?me
            |your[_-]?
            |insert[_-]?
            |placeholder
            |not[_-]?a[_-]?real
            |development
            |dev[_-]?only
            |xxxx+
        )
        """,
    )

    _provider_patterns: tuple[
        tuple[str, str, re.Pattern[str]],
        ...
    ] = (
        (
            "GitHub",
            "personal_access_token",
            re.compile(
                r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
            ),
        ),
        (
            "AWS",
            "access_key_id",
            re.compile(
                r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
            ),
        ),
        (
            "OpenAI-compatible",
            "api_key",
            re.compile(
                r"\bsk-[A-Za-z0-9_-]{16,}\b"
            ),
        ),
        (
            "JWT",
            "token",
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{8,}"
                r"\.[A-Za-z0-9_-]{8,}"
                r"\.[A-Za-z0-9_-]{8,}\b"
            ),
        ),
        (
            "GitLab",
            "personal_access_token",
            re.compile(
                r"\bglpat-[A-Za-z0-9_-]{20,}\b"
            ),
        ),
        (
            "Slack",
            "access_token",
            re.compile(
                r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"
            ),
        ),
        (
            "Stripe",
            "secret_api_key",
            re.compile(
                r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"
            ),
        ),
        (
            "Google",
            "api_key",
            re.compile(
                r"\bAIza[A-Za-z0-9_-]{35}\b"
            ),
        ),
        (
            "Azure",
            "shared_access_signature",
            re.compile(
                r"(?i)\bsv=[^\s&]+"
                r"(?:&[^\s&=]+=[^\s&]*){2,}"
                r"&sig=[A-Za-z0-9%+/=_-]{12,}"
            ),
        ),
        (
            "Discord",
            "bot_token",
            re.compile(
                r"\b[A-Za-z0-9_-]{23,28}"
                r"\.[A-Za-z0-9_-]{6}"
                r"\.[A-Za-z0-9_-]{27,40}\b"
            ),
        ),
        (
            "Twilio",
            "api_key",
            re.compile(
                r"\bSK[0-9a-fA-F]{32}\b"
            ),
        ),
        (
            "SendGrid",
            "api_key",
            re.compile(
                r"\bSG\.[A-Za-z0-9_-]{16,}"
                r"\.[A-Za-z0-9_-]{20,}\b"
            ),
        ),
    )

    def enrich_evidence_list(
        self,
        evidence_items: Iterable[ScannerEvidence],
    ) -> list[ScannerEvidence]:
        return [
            self.enrich_evidence(evidence)
            for evidence in evidence_items
        ]

    def enrich_evidence(
        self,
        evidence: ScannerEvidence,
    ) -> ScannerEvidence:
        if not self._is_secret_rule(
            evidence.rule_id
        ):
            return evidence

        classification = self.classify(
            rule_id=evidence.rule_id,
            code=evidence.code or "",
        )

        return evidence.model_copy(
            deep=True,
            update={
                "secret": classification,
            },
        )

    @staticmethod
    def _is_secret_rule(
        rule_id: str,
    ) -> bool:
        return (
            ".secrets." in rule_id
            or rule_id.startswith(
                "aegis.config."
            )
        )

    def classify(
        self,
        *,
        rule_id: str,
        code: str,
    ) -> SecretClassification:
        secret_value = self._extract_secret_value(
            rule_id=rule_id,
            code=code,
        )

        provider, secret_type, base_confidence = (
            self._classify_provider(
                rule_id=rule_id,
                secret_value=secret_value,
            )
        )

        likely_placeholder = self._is_likely_placeholder(
            secret_value
        )

        entropy = self._entropy(secret_value)

        confidence = base_confidence

        if secret_value and entropy < 2.5:
            confidence -= 0.15

        if likely_placeholder:
            confidence = min(confidence, 0.25)

        confidence = max(
            0.05,
            min(confidence, 0.99),
        )

        rotation_required = (
            not likely_placeholder
            and secret_type
            not in {"unknown", "password_placeholder"}
        )

        return SecretClassification(
            provider=provider,
            secret_type=secret_type,
            confidence=round(confidence, 2),
            likely_placeholder=likely_placeholder,
            rotation_required=rotation_required,
            fingerprint=(
                self._fingerprint(secret_value)
                if secret_value
                else None
            ),
            entropy=round(entropy, 2),
            remediation=self._remediation(
                provider=provider,
                secret_type=secret_type,
                likely_placeholder=likely_placeholder,
            ),
        )

    def _extract_secret_value(
        self,
        *,
        rule_id: str,
        code: str,
    ) -> str:
        if not code:
            return ""

        if "private-key" in rule_id:
            return "PRIVATE_KEY_MATERIAL"

        if (
            "database-url" in rule_id
            or "database-credential" in rule_id
        ):
            match = self._database_url_pattern.search(code)

            if match:
                return match.group("password")

        for _, _, pattern in self._provider_patterns:
            match = pattern.search(code)

            if match:
                return match.group(0)

        assignment = self._assignment_pattern.search(code)

        if assignment:
            return assignment.group("value")

        return ""

    def _classify_provider(
        self,
        *,
        rule_id: str,
        secret_value: str,
    ) -> tuple[str, str, float]:
        for provider, secret_type, pattern in (
            self._provider_patterns
        ):
            if secret_value and pattern.search(secret_value):
                return provider, secret_type, 0.98

        if "github-token" in rule_id:
            return "GitHub", "personal_access_token", 0.95

        if "aws-access-key" in rule_id:
            return "AWS", "access_key_id", 0.98

        if "private-key" in rule_id:
            return "Cryptography", "private_key", 0.99

        if (
            "database-url" in rule_id
            or "database-credential" in rule_id
        ):
            return "Database", "connection_password", 0.94

        if "config.hardcoded-secret" in rule_id:
            return self._classify_config_assignment(
                secret_value=secret_value,
            )

        if "jwt-secret" in rule_id:
            return "JWT", "signing_secret", 0.88

        if "password" in rule_id:
            return "Generic", "password", 0.72

        if "api-key" in rule_id:
            return "Generic", "api_key", 0.78

        return "Generic", "unknown", 0.60

    def _classify_config_assignment(
        self,
        *,
        secret_value: str,
    ) -> tuple[str, str, float]:
        for provider, secret_type, pattern in (
            self._provider_patterns
        ):
            if (
                secret_value
                and pattern.search(secret_value)
            ):
                return provider, secret_type, 0.98

        return "Generic", "configuration_secret", 0.82

    def _is_likely_placeholder(
        self,
        value: str,
    ) -> bool:
        if not value:
            return False

        normalized = value.strip().lower()

        exact_placeholders = {
            "123456",
            "password",
            "password123",
            "secret",
            "token",
            "api_key",
            "apikey",
        }

        if normalized in exact_placeholders:
            return True

        if self._placeholder_pattern.search(normalized):
            return True

        unique_ratio = (
            len(set(normalized)) / len(normalized)
            if normalized
            else 0.0
        )

        if len(normalized) >= 8 and unique_ratio < 0.25:
            return True

        return False

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0

        counts = Counter(value)
        length = len(value)

        return -sum(
            (count / length)
            * math.log2(count / length)
            for count in counts.values()
        )

    @classmethod
    def _fingerprint(
        cls,
        value: str,
    ) -> str:
        digest = hmac.new(
            cls._fingerprint_key,
            value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return f"hmac-sha256:{digest[:12]}"

    @staticmethod
    def _remediation(
        *,
        provider: str,
        secret_type: str,
        likely_placeholder: bool,
    ) -> str:
        if likely_placeholder:
            return (
                "Confirm that this is intentionally non-production "
                "test data. Keep examples clearly labelled and ensure "
                "real credentials are never committed."
            )

        if provider == "GitHub":
            return (
                "Revoke the exposed GitHub token, create a replacement "
                "with minimum required scopes, and load it from a "
                "protected secret store."
            )

        if provider == "AWS":
            return (
                "Deactivate the exposed AWS access key, investigate its "
                "usage, rotate associated credentials, and prefer an "
                "IAM role with least privilege."
            )

        if provider == "GitLab":
            return (
                "Revoke the exposed GitLab token, issue a replacement "
                "with minimum required scopes, and store it outside "
                "source control."
            )

        if provider == "Slack":
            return (
                "Revoke or rotate the Slack token, inspect recent app "
                "activity, and load the replacement from a protected "
                "secret store."
            )

        if provider == "Stripe":
            return (
                "Roll the exposed Stripe key immediately, review recent "
                "API activity, and use restricted keys wherever possible."
            )

        if provider == "Google":
            return (
                "Rotate the exposed Google API key, restrict it by API "
                "and application, and remove it from repository history."
            )

        if provider == "Azure":
            return (
                "Revoke or regenerate the exposed Azure credential, "
                "review its permissions and expiry, and prefer managed "
                "identity where available."
            )

        if provider == "Discord":
            return (
                "Reset the exposed Discord bot token, investigate bot "
                "activity, and store the replacement in protected "
                "runtime configuration."
            )

        if provider == "Twilio":
            return (
                "Revoke the exposed Twilio API key, create a replacement "
                "with minimum access, and inspect recent account activity."
            )

        if provider == "SendGrid":
            return (
                "Revoke the exposed SendGrid API key, create a restricted "
                "replacement, and review recent sending activity."
            )

        if secret_type == "private_key":
            return (
                "Remove the private key from source control, rotate the "
                "key pair, inspect repository history, and store the "
                "replacement in a managed secret service."
            )

        if provider == "Database":
            return (
                "Rotate the database password, remove credentials from "
                "the connection URL, and load them through protected "
                "runtime configuration."
            )

        if provider == "JWT":
            return (
                "Rotate the signing secret, invalidate affected tokens "
                "where appropriate, and load signing material from a "
                "key-management or secret-management service."
            )

        return (
            "Rotate the credential if it may have been exposed and load "
            "the replacement from an environment variable or approved "
            "secret manager."
        )
