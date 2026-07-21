import re
from pathlib import Path
from urllib.parse import urlparse

from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
    ValidationAuthorizationResponse,
    ValidationLimits,
    ValidationScope,
)


class ValidationAuthorizer:
    contract = "aegis-validation-authorization-v1"

    _container_image_pattern = re.compile(
        r"^(?:"
        r"[a-z0-9.-]+(?::[0-9]+)?/"
        r")?"
        r"[a-z0-9._-]+"
        r"(?:/[a-z0-9._-]+)*"
        r"(?::[A-Za-z0-9._-]+)?"
        r"(?:@sha256:[a-fA-F0-9]{64})?$"
    )

    def authorize(
        self,
        request: ValidationAuthorizationRequest,
    ) -> ValidationAuthorizationResponse:
        reasons: list[str] = []
        denials: list[str] = []

        normalized_target = self._normalize_target(
            request=request,
            denials=denials,
        )

        if request.authorization_confirmed:
            reasons.append(
                "Explicit authorization was supplied."
            )
        else:
            denials.append(
                "Explicit authorization is required."
            )

        if request.dry_run:
            reasons.append(
                "Dry-run mode prevents execution."
            )

        if (
            request.target_type == "local_repository"
            and request.network_policy != "disabled"
        ):
            denials.append(
                "Local repository validation must begin "
                "with networking disabled."
            )

        if (
            request.target_type == "local_service"
            and request.network_policy != "loopback"
        ):
            denials.append(
                "Local service validation requires the "
                "loopback-only network policy."
            )

        if (
            request.target_type == "container_image"
            and request.network_policy != "disabled"
        ):
            denials.append(
                "Container image validation must begin "
                "with networking disabled."
            )

        authorized = not denials
        execution_allowed = (
            authorized
            and not request.dry_run
        )

        if authorized:
            reasons.append(
                "The requested scope satisfies the "
                "initial validation policy."
            )

        if execution_allowed:
            reasons.append(
                "Execution may be planned within the "
                "declared scope and limits."
            )

        return ValidationAuthorizationResponse(
            contract=self.contract,
            authorized=authorized,
            execution_allowed=execution_allowed,
            dry_run=request.dry_run,
            normalized_scope=ValidationScope(
                target_type=request.target_type,
                target=normalized_target,
                allowed_test_types=list(
                    dict.fromkeys(
                        request.allowed_test_types
                    )
                ),
            ),
            limits=ValidationLimits(
                timeout_seconds=(
                    request.timeout_seconds
                ),
                memory_limit_mb=(
                    request.memory_limit_mb
                ),
                cpu_limit=request.cpu_limit,
                network_policy=(
                    request.network_policy
                ),
            ),
            reasons=reasons,
            denials=denials,
        )

    def _normalize_target(
        self,
        *,
        request: ValidationAuthorizationRequest,
        denials: list[str],
    ) -> str:
        target = request.target.strip()

        if "\x00" in target:
            denials.append(
                "The target contains an invalid null byte."
            )
            return target.replace("\x00", "")

        if request.target_type == "local_repository":
            return self._normalize_repository(
                target=target,
                denials=denials,
            )

        if request.target_type == "local_service":
            return self._normalize_local_service(
                target=target,
                denials=denials,
            )

        return self._normalize_container_image(
            target=target,
            denials=denials,
        )

    @staticmethod
    def _normalize_repository(
        *,
        target: str,
        denials: list[str],
    ) -> str:
        path = Path(target).expanduser()

        if not path.is_absolute():
            denials.append(
                "Local repository targets must use an "
                "absolute path."
            )
            return str(path)

        normalized = path.resolve(
            strict=False
        )

        if normalized == Path("/"):
            denials.append(
                "The filesystem root cannot be used as "
                "a validation target."
            )

        return str(normalized)

    @staticmethod
    def _normalize_local_service(
        *,
        target: str,
        denials: list[str],
    ) -> str:
        parsed = urlparse(target)

        if parsed.scheme not in {"http", "https"}:
            denials.append(
                "Local service targets must use HTTP "
                "or HTTPS."
            )

        hostname = (
            parsed.hostname.lower()
            if parsed.hostname
            else ""
        )

        if hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            denials.append(
                "Only loopback local-service targets "
                "are permitted."
            )

        if parsed.username or parsed.password:
            denials.append(
                "Credentials must not be embedded in "
                "the validation target URL."
            )

        return target

    def _normalize_container_image(
        self,
        *,
        target: str,
        denials: list[str],
    ) -> str:
        normalized = target.lower()

        if not self._container_image_pattern.fullmatch(
            target
        ):
            denials.append(
                "The container image reference is invalid."
            )

        if target.startswith("-"):
            denials.append(
                "Container image references cannot begin "
                "with an option prefix."
            )

        return normalized
