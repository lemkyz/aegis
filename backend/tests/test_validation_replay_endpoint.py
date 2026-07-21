import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import app


client = TestClient(app)


def _evidence(
    verdict: str,
) -> dict[str, object]:
    status = (
        "completed"
        if verdict in {
            "confirmed",
            "not_reproduced",
        }
        else "failed"
    )

    return {
        "evaluator": (
            "aegis-dynamic-validation-evidence-v1"
        ),
        "threat_id": "threat-command-001",
        "category": "command_injection",
        "verdict": verdict,
        "dynamically_confirmed": (
            verdict == "confirmed"
        ),
        "confidence": 0.99,
        "evidence": [
            f"Dynamic verdict: {verdict}",
        ],
        "reasons": [],
        "execution_status": status,
        "exit_code": 0,
        "duration_ms": 10,
    }


def test_replay_endpoint_reports_fixed() -> None:
    response = client.post(
        "/v1/validation/replay/compare",
        json={
            "before": _evidence("confirmed"),
            "after": _evidence(
                "not_reproduced"
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["comparator"] == (
        "aegis-dynamic-validation-replay-v1"
    )
    assert payload["verdict"] == "fixed"
    assert payload["fixed"] is True
    assert payload["before_verdict"] == (
        "confirmed"
    )
    assert payload["after_verdict"] == (
        "not_reproduced"
    )


def test_replay_endpoint_reports_still_exploitable() -> None:
    response = client.post(
        "/v1/validation/replay/compare",
        json={
            "before": _evidence("confirmed"),
            "after": _evidence("confirmed"),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["verdict"] == (
        "still_exploitable"
    )
    assert payload["fixed"] is False


def test_replay_endpoint_validates_verdict() -> None:
    after = _evidence("not_reproduced")
    after["verdict"] = "unknown_result"

    response = client.post(
        "/v1/validation/replay/compare",
        json={
            "before": _evidence("confirmed"),
            "after": after,
        },
    )

    assert response.status_code == 422
