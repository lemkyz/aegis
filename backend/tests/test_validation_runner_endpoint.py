import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import app
from aegis.schemas.validation import (
    ValidationExecutionResult,
)
from aegis.security.validation_runner import (
    ValidationRunner,
)


client = TestClient(app)


def _payload(
    *,
    dry_run: bool = False,
) -> dict[str, object]:
    return {
        "plan": {
            "authorization": {
                "authorization_confirmed": True,
                "target_type": "local_repository",
                "target": "/tmp/aegis-project",
                "allowed_test_types": [
                    "command_injection",
                ],
                "dry_run": dry_run,
                "timeout_seconds": 10,
                "memory_limit_mb": 256,
                "cpu_limit": 0.5,
                "network_policy": "disabled",
            },
            "runtime": "python",
            "entrypoint": "validation.py",
            "test_type": "command_injection",
        }
    }


def test_validation_run_endpoint_returns_result(
    monkeypatch,
) -> None:
    async def fake_run(
        self: ValidationRunner,
        request: object,
    ) -> ValidationExecutionResult:
        return ValidationExecutionResult(
            runner=self.runner,
            status="completed",
            runtime_executable="/usr/bin/podman",
            started=True,
            timed_out=False,
            exit_code=0,
            duration_ms=12,
            stdout="AEGIS_SANDBOX_OK\n",
            stderr="",
            argv=[
                "/usr/bin/podman",
                "run",
                "--rm",
            ],
            reasons=[
                "Authorized sandbox execution completed.",
            ],
            denials=[],
        )

    monkeypatch.setattr(
        ValidationRunner,
        "run",
        fake_run,
    )

    response = client.post(
        "/v1/validation/run",
        json=_payload(),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["runner"] == (
        "aegis-safe-container-runner-v1"
    )
    assert payload["status"] == "completed"
    assert payload["started"] is True
    assert payload["timed_out"] is False
    assert payload["exit_code"] == 0
    assert payload["stdout"] == (
        "AEGIS_SANDBOX_OK\n"
    )


def test_validation_run_endpoint_rejects_dry_run() -> None:
    response = client.post(
        "/v1/validation/run",
        json=_payload(
            dry_run=True,
        ),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "rejected"
    assert payload["started"] is False
    assert payload["argv"] == []


def test_validation_run_endpoint_validates_request() -> None:
    payload = _payload()
    payload["plan"]["runtime"] = "shell"

    response = client.post(
        "/v1/validation/run",
        json=payload,
    )

    assert response.status_code == 422
