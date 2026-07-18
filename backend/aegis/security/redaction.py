import re
from collections.abc import Iterable

from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)


class RedactionSession:
    """
    Keeps stable placeholders during one analysis request.

    The same secret receives the same placeholder everywhere in that
    request, allowing the model to understand repeated references
    without receiving the original value.
    """

    _private_key_pattern = re.compile(
        r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"
        r".*?"
        r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
        re.DOTALL,
    )

    _private_key_marker_pattern = re.compile(
        r"-----"
        r"(?:BEGIN|END)"
        r"(?: [A-Z0-9]+)? PRIVATE KEY"
        r"-----"
    )

    _assignment_pattern = re.compile(
        r"""(?ix)
        (?P<prefix>
            (?P<name>[A-Za-z_][A-Za-z0-9_-]*)
            \s*
            (?:
                =
                |:
            )
            \s*
        )
        (?P<quote>["'])
        (?P<value>[^"'\r\n]{4,})
        (?P=quote)
        """,
    )

    _secret_name_pattern = re.compile(
        r"""(?ix)
        (?:
            password
            |passwd
            |pwd
            |secret
            |token
            |api[_-]?key
            |access[_-]?key
            |client[_-]?secret
            |jwt[_-]?secret
            |private[_-]?key
        )
        """,
    )


    _authorization_pattern = re.compile(
        r"""(?ix)
        (?P<prefix>
            \bAuthorization\b
            ["']?
            \s*
            (?:
                :
                |=
            )
            \s*
            ["']?
            (?:
                Bearer
                |Basic
            )
            \s+
        )
        (?P<value>[A-Za-z0-9._~+/=-]{8,})
        """,
    )

    _database_url_pattern = re.compile(
        r"""(?ix)
        (?P<scheme>
            (?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)
            ://
        )
        (?P<username>[^:\s/@]+)
        :
        (?P<password>[^@\s/]+)
        @
        """,
    )

    _known_token_patterns = (
        re.compile(
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        ),
        re.compile(
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        ),
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b",
        ),
        re.compile(
            r"\bASIA[0-9A-Z]{16}\b",
        ),
        re.compile(
            r"\bsk-[A-Za-z0-9_-]{16,}\b",
        ),
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}"
            r"\.[A-Za-z0-9_-]{8,}"
            r"\.[A-Za-z0-9_-]{8,}\b",
        ),
    )

    _placeholder_pattern = re.compile(
        r"<AEGIS_REDACTED_[A-Z_]+_\d+>",
    )

    def __init__(self) -> None:
        self._placeholders: dict[str, str] = {}
        self._counter = 0

    def redact_text(
        self,
        value: str | None,
    ) -> str | None:
        if value is None or not value:
            return value

        text = value

        text = self._private_key_pattern.sub(
            self._replace_private_key,
            text,
        )

        text = self._private_key_marker_pattern.sub(
            lambda match: self._placeholder(
                match.group(0),
                "PRIVATE_KEY",
            ),
            text,
        )

        text = self._database_url_pattern.sub(
            self._replace_database_url,
            text,
        )

        text = self._authorization_pattern.sub(
            self._replace_authorization,
            text,
        )

        text = self._assignment_pattern.sub(
            self._replace_assignment,
            text,
        )

        for pattern in self._known_token_patterns:
            text = pattern.sub(
                lambda match: self._placeholder(
                    match.group(0),
                    "SECRET",
                ),
                text,
            )

        return text

    def redact_evidence(
        self,
        evidence: ScannerEvidence,
    ) -> ScannerEvidence:
        return evidence.model_copy(
            deep=True,
            update={
                "message": (
                    self.redact_text(evidence.message)
                    or evidence.message
                ),
                "code": self.redact_text(evidence.code),
            },
        )

    def redact_evidence_list(
        self,
        evidence_items: Iterable[ScannerEvidence],
    ) -> list[ScannerEvidence]:
        return [
            self.redact_evidence(evidence)
            for evidence in evidence_items
        ]

    def redact_finding(
        self,
        finding: SecurityFinding,
    ) -> SecurityFinding:
        redacted_patch = self.redact_text(
            finding.proposed_patch
        )

        notes = [
            self.redact_text(note) or note
            for note in finding.false_positive_notes
        ]

        # Applying a patch containing a secret placeholder could overwrite
        # the user's real source with a fake placeholder. Suppress that patch
        # rather than offering an unsafe Quick Fix.
        if (
            redacted_patch
            and self.contains_placeholder(redacted_patch)
        ):
            redacted_patch = None
            notes.append(
                "A proposed patch was withheld because it contained "
                "redacted secret placeholders. Review and remediate "
                "the secret manually."
            )

        return finding.model_copy(
            deep=True,
            update={
                "summary": (
                    self.redact_text(finding.summary)
                    or finding.summary
                ),
                "evidence": [
                    self.redact_text(item) or item
                    for item in finding.evidence
                ],
                "scanner_evidence": (
                    self.redact_evidence_list(
                        finding.scanner_evidence
                    )
                ),
                "false_positive_notes": notes,
                "recommended_fix": (
                    self.redact_text(
                        finding.recommended_fix
                    )
                    or finding.recommended_fix
                ),
                "proposed_patch": redacted_patch,
            },
        )

    def redact_findings(
        self,
        findings: Iterable[SecurityFinding],
    ) -> list[SecurityFinding]:
        return [
            self.redact_finding(finding)
            for finding in findings
        ]

    @classmethod
    def contains_placeholder(
        cls,
        value: str,
    ) -> bool:
        return bool(
            cls._placeholder_pattern.search(value)
        )

    def _replace_private_key(
        self,
        match: re.Match[str],
    ) -> str:
        return self._placeholder(
            match.group(0),
            "PRIVATE_KEY",
        )

    def _replace_database_url(
        self,
        match: re.Match[str],
    ) -> str:
        password = match.group("password")

        return (
            f"{match.group('scheme')}"
            f"{match.group('username')}:"
            f"{self._placeholder(password, 'DATABASE_PASSWORD')}"
            "@"
        )

    def _replace_authorization(
        self,
        match: re.Match[str],
    ) -> str:
        return (
            f"{match.group('prefix')}"
            f"{self._placeholder(match.group('value'), 'AUTH_TOKEN')}"
        )

    def _replace_assignment(
        self,
        match: re.Match[str],
    ) -> str:
        name = match.group("name")

        if not self._secret_name_pattern.search(name):
            return match.group(0)

        value = match.group("value")
        quote = match.group("quote")

        return (
            f"{match.group('prefix')}"
            f"{quote}"
            f"{self._placeholder(value, 'SECRET')}"
            f"{quote}"
        )

    def _placeholder(
        self,
        secret: str,
        category: str,
    ) -> str:
        existing = self._placeholders.get(secret)

        if existing:
            return existing

        self._counter += 1

        placeholder = (
            f"<AEGIS_REDACTED_{category}_{self._counter}>"
        )

        self._placeholders[secret] = placeholder
        return placeholder


class SecretRedactor:
    def create_session(self) -> RedactionSession:
        return RedactionSession()
