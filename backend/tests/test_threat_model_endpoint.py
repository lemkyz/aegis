import os

from fastapi.testclient import TestClient

os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import app


client = TestClient(app)


def test_threat_model_endpoint_returns_model() -> None:
    response = client.post(
        "/v1/threat-model/scan",
        json={
            "files": [
                {
                    "filename": "app.py",
                    "language": "python",
                    "code": (
                        "import os\n\n"
                        "def run(command: str):\n"
                        "    return os.system(command)\n"
                    ),
                }
            ]
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["modeler"] == (
        "aegis-deterministic-threat-model"
    )
    assert payload["summary"]["files_scanned"] == 1
    assert payload["summary"]["critical"] >= 1
    assert payload["threats"][0]["category"] == (
        "command_injection"
    )


def test_threat_model_endpoint_validates_empty_files() -> None:
    response = client.post(
        "/v1/threat-model/scan",
        json={
            "files": [],
        },
    )

    assert response.status_code == 422


def test_threat_model_endpoint_returns_exploitability_fields() -> None:
    response = client.post(
        "/v1/threat-model/scan",
        json={
            "files": [
                {
                    "filename": "app.py",
                    "language": "python",
                    "code": """
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
""".strip(),
                }
            ]
        },
    )

    assert response.status_code == 200

    payload = response.json()
    threat = next(
        item
        for item in payload["threats"]
        if item["category"] == "command_injection"
    )

    assert threat["exploitability"] == "confirmed"
    assert threat["exploitability_confidence"] >= 0.9
    assert threat["exploitability_reasons"]
    assert threat["prerequisites"]
    assert threat["blocking_controls"] == []
