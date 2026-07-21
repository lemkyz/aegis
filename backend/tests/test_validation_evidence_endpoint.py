import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import app


client = TestClient(app)


def _payload() -> dict[str, object]:
    return {
        "threat_id": "threat-command-001",
        "category": "command_injection",
        "execution": {
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
            "duration_ms": 15,
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
        "success_criteria": {
            "expected_exit_code": 0,
            "stdout_contains": (
                "AEGIS_EXPLOIT_CONFIRMED"
            ),
        },
    }


def test_validation_evidence_endpoint_confirms() -> None:
    response = client.post(
        "/v1/validation/evidence",
        json=_payload(),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["evaluator"] == (
        "aegis-dynamic-validation-evidence-v1"
    )
    assert payload["threat_id"] == (
        "threat-command-001"
    )
    assert payload["verdict"] == "confirmed"
    assert payload["dynamically_confirmed"] is True
    assert payload["confidence"] >= 0.99


def test_validation_evidence_endpoint_not_reproduced() -> None:
    payload = _payload()
    payload["success_criteria"][
        "stdout_contains"
    ] = "MISSING_MARKER"

    response = client.post(
        "/v1/validation/evidence",
        json=payload,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["verdict"] == "not_reproduced"
    assert body["dynamically_confirmed"] is False


def test_validation_evidence_endpoint_validates_category() -> None:
    payload = _payload()
    payload["category"] = "unrestricted_shell"

    response = client.post(
        "/v1/validation/evidence",
        json=payload,
    )

    assert response.status_code == 422
