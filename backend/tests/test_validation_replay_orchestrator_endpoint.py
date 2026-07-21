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


def _payload() -> dict[str, object]:
    return {
        "threat_id": "threat-command-001",
        "category": "command_injection",
        "plan": {
            "authorization": {
                "authorization_confirmed": True,
                "target_type": "local_repository",
                "target": "/tmp/aegis-project",
                "allowed_test_types": [
                    "command_injection",
                ],
                "dry_run": False,
                "timeout_seconds": 10,
                "memory_limit_mb": 256,
                "cpu_limit": 0.5,
                "network_policy": "disabled",
            },
            "runtime": "python",
            "entrypoint": "validation.py",
            "test_type": "command_injection",
        },
        "success_criteria": {
            "expected_exit_code": 0,
            "stdout_contains": (
                "AEGIS_EXPLOIT_CONFIRMED"
            ),
        },
        "before_execution": {
            "runner": (
                "aegis-safe-container-runner-v1"
            ),
            "status": "completed",
            "runtime_executable": (
                "/usr/bin/podman"
            ),
            "started": True,
            "timed_out": False,
            "exit_code": 0,
            "duration_ms": 10,
            "stdout": (
                "AEGIS_EXPLOIT_CONFIRMED\n"
            ),
            "stderr": "",
            "argv": [
                "/usr/bin/podman",
                "run",
                "--rm",
            ],
            "reasons": [],
            "denials": [],
        },
    }


def test_replay_endpoint_reports_fixed(
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
            stdout="SAFE_BEHAVIOR\n",
            stderr="",
            argv=[
                "/usr/bin/podman",
                "run",
                "--rm",
            ],
            reasons=[],
            denials=[],
        )

    monkeypatch.setattr(
        ValidationRunner,
        "run",
        fake_run,
    )

    response = client.post(
        "/v1/validation/replay",
        json=_payload(),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["orchestrator"] == (
        "aegis-dynamic-validation-"
        "replay-orchestrator-v1"
    )
    assert payload["before_evidence"][
        "verdict"
    ] == "confirmed"
    assert payload["after_evidence"][
        "verdict"
    ] == "not_reproduced"
    assert payload["comparison"][
        "verdict"
    ] == "fixed"
    assert payload["comparison"]["fixed"] is True


def test_replay_endpoint_validates_payload() -> None:
    payload = _payload()
    payload["category"] = "unrestricted_shell"

    response = client.post(
        "/v1/validation/replay",
        json=payload,
    )

    assert response.status_code == 422
