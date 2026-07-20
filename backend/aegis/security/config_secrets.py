import re
from pathlib import Path

from aegis.schemas.analysis import ScannerEvidence


class ConfigSecretScanner:
    """
    Detects credentials in configuration-oriented files.

    Raw values remain only in ScannerEvidence until the existing
    Secret Intelligence and redaction pipeline processes them.
    """

    name = "config-secret-scanner"

    _supported_languages = {
        "dotenv",
        "env",
        "yaml",
        "yml",
        "toml",
        "ini",
        "properties",
        "config",
        "conf",
        "plaintext",
    }

    _supported_suffixes = {
        ".env",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
    }

    _sensitive_name_pattern = re.compile(
        r"""(?ix)
        (?:
            api[_-]?key
            | access[_-]?key
            | secret(?:[_-]?key)?
            | client[_-]?secret
            | private[_-]?key
            | password
            | passwd
            | pwd
            | auth[_-]?token
            | bearer[_-]?token
            | refresh[_-]?token
            | session[_-]?token
            | database[_-]?(?:url|uri)
            | db[_-]?(?:url|uri|password|pass)
            | connection[_-]?string
            | webhook[_-]?(?:secret|token)
            | signing[_-]?key
        )
        """
    )

    _assignment_pattern = re.compile(
        r"""(?x)
        ^\s*
        (?:export\s+)?
        (?P<name>[A-Za-z_][A-Za-z0-9_.-]*)
        \s*(?:=|:)\s*
        (?P<value>.+?)
        \s*$
        """
    )

    _database_url_pattern = re.compile(
        r"""(?ix)
        ^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)
        ://[^/\s:@]+:[^@\s]+@
        """
    )

    _private_key_pattern = re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    )

    _reference_patterns = (
        re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$"),
        re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
        re.compile(r"^process\.env\.[A-Za-z_][A-Za-z0-9_]*$"),
        re.compile(r"^os\.environ(?:\.get)?\("),
        re.compile(r"^env\("),
        re.compile(r"^secret://", re.IGNORECASE),
        re.compile(r"^vault://", re.IGNORECASE),
    )

    def supports(
        self,
        *,
        filename: str,
        language: str,
    ) -> bool:
        normalized_language = language.lower().strip()
        path = Path(filename)
        basename = path.name.lower()
        suffix = path.suffix.lower()

        return (
            normalized_language in self._supported_languages
            or basename == ".env"
            or basename.startswith(".env.")
            or suffix in self._supported_suffixes
        )

    def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        if not self.supports(
            filename=filename,
            language=language,
        ):
            return []

        evidence: list[ScannerEvidence] = []
        seen: set[tuple[int, str]] = set()

        for line_number, raw_line in enumerate(
            code.splitlines(),
            start=1,
        ):
            stripped = raw_line.strip()

            if (
                not stripped
                or stripped.startswith("#")
                or stripped.startswith(";")
                or stripped.startswith("//")
            ):
                continue

            if self._private_key_pattern.search(stripped):
                self._append_evidence(
                    evidence=evidence,
                    seen=seen,
                    filename=filename,
                    line_number=line_number,
                    raw_line=raw_line,
                    rule_id="aegis.config.private-key",
                    message=(
                        "A private key appears to be embedded "
                        "in a configuration file."
                    ),
                    severity="critical",
                )
                continue

            assignment = self._assignment_pattern.match(raw_line)

            if assignment is None:
                continue

            name = assignment.group("name")
            value = self._clean_value(
                assignment.group("value")
            )

            if not value or self._is_reference(value):
                continue

            sensitive_name = bool(
                self._sensitive_name_pattern.search(name)
            )
            database_credential = bool(
                self._database_url_pattern.search(value)
            )

            if not sensitive_name and not database_credential:
                continue

            rule_id = (
                "aegis.config.database-credential"
                if database_credential
                else "aegis.config.hardcoded-secret"
            )

            message = (
                "A database connection string appears to contain "
                "embedded credentials."
                if database_credential
                else (
                    f"Configuration field '{name}' appears to contain "
                    "a hardcoded credential."
                )
            )

            self._append_evidence(
                evidence=evidence,
                seen=seen,
                filename=filename,
                line_number=line_number,
                raw_line=raw_line,
                rule_id=rule_id,
                message=message,
                severity="high",
            )

        return evidence

    @staticmethod
    def _clean_value(value: str) -> str:
        cleaned = value.strip()

        if (
            len(cleaned) >= 2
            and cleaned[0] == cleaned[-1]
            and cleaned[0] in {"'", '"'}
        ):
            cleaned = cleaned[1:-1].strip()
        else:
            cleaned = re.split(
                r"\s+(?:#|;|//)",
                cleaned,
                maxsplit=1,
            )[0].strip()

        return cleaned

    def _is_reference(self, value: str) -> bool:
        normalized = value.strip()

        return any(
            pattern.search(normalized)
            for pattern in self._reference_patterns
        )

    def _append_evidence(
        self,
        *,
        evidence: list[ScannerEvidence],
        seen: set[tuple[int, str]],
        filename: str,
        line_number: int,
        raw_line: str,
        rule_id: str,
        message: str,
        severity: str,
    ) -> None:
        identity = (line_number, rule_id)

        if identity in seen:
            return

        seen.add(identity)

        evidence.append(
            ScannerEvidence(
                tool=self.name,
                rule_id=rule_id,
                message=message,
                severity=severity,
                file=filename,
                line_start=line_number,
                line_end=line_number,
                code=raw_line,
                cwe=["CWE-798"],
                owasp=["A07:2021"],
            )
        )
