from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
)
from aegis.security.authorization import (
    ValidationAuthorizer,
)


def _request(
    **overrides: object,
) -> ValidationAuthorizationRequest:
    values: dict[str, object] = {
        "authorization_confirmed": True,
        "target_type": "local_repository",
        "target": "/tmp/aegis-project",
        "allowed_test_types": [
            "command_injection",
        ],
        "dry_run": True,
        "timeout_seconds": 10,
        "memory_limit_mb": 256,
        "cpu_limit": 0.5,
        "network_policy": "disabled",
    }
    values.update(overrides)

    return ValidationAuthorizationRequest(
        **values,
    )


def test_authorizes_repository_dry_run() -> None:
    result = ValidationAuthorizer().authorize(
        _request()
    )

    assert result.authorized is True
    assert result.execution_allowed is False
    assert result.dry_run is True
    assert result.denials == []
    assert result.normalized_scope.target == (
        "/tmp/aegis-project"
    )


def test_rejects_missing_explicit_authorization() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            authorization_confirmed=False,
        )
    )

    assert result.authorized is False
    assert result.execution_allowed is False
    assert any(
        "explicit authorization"
        in denial.lower()
        for denial in result.denials
    )


def test_allows_execution_only_outside_dry_run() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            dry_run=False,
        )
    )

    assert result.authorized is True
    assert result.execution_allowed is True


def test_rejects_relative_repository_target() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            target="relative/project",
        )
    )

    assert result.authorized is False
    assert result.execution_allowed is False
    assert any(
        "absolute path" in denial.lower()
        for denial in result.denials
    )


def test_rejects_filesystem_root() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            target="/",
        )
    )

    assert result.authorized is False
    assert any(
        "filesystem root" in denial.lower()
        for denial in result.denials
    )


def test_rejects_repository_network_access() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            network_policy="loopback",
        )
    )

    assert result.authorized is False
    assert any(
        "networking disabled"
        in denial.lower()
        for denial in result.denials
    )


def test_authorizes_loopback_service() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            target_type="local_service",
            target="http://127.0.0.1:8000",
            network_policy="loopback",
        )
    )

    assert result.authorized is True
    assert result.normalized_scope.target == (
        "http://127.0.0.1:8000"
    )


def test_rejects_remote_service() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            target_type="local_service",
            target="https://example.com",
            network_policy="loopback",
        )
    )

    assert result.authorized is False
    assert any(
        "loopback" in denial.lower()
        for denial in result.denials
    )


def test_deduplicates_allowed_test_types() -> None:
    result = ValidationAuthorizer().authorize(
        _request(
            allowed_test_types=[
                "command_injection",
                "command_injection",
                "path_traversal",
            ],
        )
    )

    assert result.normalized_scope.allowed_test_types == [
        "command_injection",
        "path_traversal",
    ]
