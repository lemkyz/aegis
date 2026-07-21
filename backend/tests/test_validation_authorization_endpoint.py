import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import app


client = TestClient(app)


def _payload(
    **overrides: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
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
    payload.update(overrides)
    return payload


def test_authorization_endpoint_returns_safe_plan() -> None:
    response = client.post(
        "/v1/validation/authorize",
        json=_payload(),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["contract"] == (
        "aegis-validation-authorization-v1"
    )
    assert payload["authorized"] is True
    assert payload["execution_allowed"] is False
    assert payload["dry_run"] is True
    assert payload["denials"] == []
    assert payload["limits"]["network_policy"] == (
        "disabled"
    )


def test_authorization_endpoint_reports_denial() -> None:
    response = client.post(
        "/v1/validation/authorize",
        json=_payload(
            authorization_confirmed=False,
        ),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["authorized"] is False
    assert payload["execution_allowed"] is False
    assert payload["denials"]


def test_authorization_endpoint_validates_limits() -> None:
    response = client.post(
        "/v1/validation/authorize",
        json=_payload(
            timeout_seconds=600,
        ),
    )

    assert response.status_code == 422


def test_authorization_endpoint_rejects_unknown_test_type() -> None:
    response = client.post(
        "/v1/validation/authorize",
        json=_payload(
            allowed_test_types=[
                "unrestricted_shell",
            ],
        ),
    )

    assert response.status_code == 422
