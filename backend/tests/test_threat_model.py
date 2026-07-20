from aegis.schemas.attack_surface import AttackSurfaceFile
from aegis.security.threat_model import ThreatModeler


def test_threat_modeler_builds_deterministic_threats() -> None:
    files = [
        AttackSurfaceFile(
            filename="app.py",
            language="python",
            code="""
import os
import requests

def run_command(command: str):
    return os.system(command)

def find_user(db, user_id: str):
    return db.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    ).fetchone()

def fetch_url(request):
    url = request.args.get("url")
    return requests.get(url)
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    categories = {
        threat.category
        for threat in result.threats
    }

    assert "command_injection" in categories
    assert "sql_injection" in categories
    assert "ssrf" in categories
    assert "unsafe_data_flow" in categories

    assert result.summary.files_scanned == 1
    assert result.summary.threats_found == len(
        result.threats
    )
    assert result.summary.critical >= 1
    assert result.summary.high >= 2

    assert result.assets
    assert result.trust_boundaries


def test_threat_ids_are_stable() -> None:
    files = [
        AttackSurfaceFile(
            filename="worker.py",
            language="python",
            code="""
import subprocess

def run_job(name: str):
    return subprocess.run(
        ["worker", name],
        check=True,
    )
""".strip(),
        ),
    ]

    modeler = ThreatModeler()

    first = modeler.scan(files)
    second = modeler.scan(files)

    assert [
        threat.id
        for threat in first.threats
    ] == [
        threat.id
        for threat in second.threats
    ]


def test_empty_supported_surface_returns_empty_model() -> None:
    files = [
        AttackSurfaceFile(
            filename="plain.py",
            language="python",
            code="""
def add(left: int, right: int) -> int:
    return left + right
""".strip(),
        ),
    ]

    result = ThreatModeler().scan(files)

    assert result.threats == []
    assert result.assets == []
    assert result.trust_boundaries == []
    assert result.summary.threats_found == 0
