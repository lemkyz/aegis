from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)


def test_maps_python_fastapi_surface() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="api.py",
                language="python",
                code="""
from fastapi import Depends, FastAPI
import os
import requests
import subprocess

app = FastAPI()

@app.post("/users/{user_id}")
def update_user(
    user_id: str,
    current_user=Depends(require_auth),
):
    token = os.getenv("SERVICE_TOKEN")
    db.execute(
        "UPDATE users SET active = 1 WHERE id = ?",
        (user_id,),
    )
    requests.post("https://audit.example/events")
    subprocess.run(["echo", user_id])
    return {"ok": True}
""".strip(),
            )
        ]
    )

    kinds = {
        node.kind
        for node in result.nodes
    }

    assert "http_route" in kinds
    assert "authentication" in kinds
    assert "database" in kinds
    assert "outbound_request" in kinds
    assert "process_execution" in kinds
    assert "secret_access" in kinds

    route = next(
        node
        for node in result.nodes
        if node.kind == "http_route"
    )

    assert route.method == "POST"
    assert route.path == "/users/{user_id}"
    assert route.authenticated is True

    assert result.summary.routes == 1
    assert result.summary.authenticated_routes == 1
    assert result.summary.process_executions == 1

    assert any(
        edge.source == route.id
        and edge.relationship
        == "route_reaches_database"
        for edge in result.edges
    )


def test_maps_express_unauthenticated_route() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="server.js",
                language="javascript",
                code="""
const fs = require("fs");
const { exec } = require("child_process");

app.get("/download/:name", (req, res) => {
  const name = req.params.name;
  const content = fs.readFileSync("./data/" + name);
  exec("audit " + name);
  res.send(content);
});
""".strip(),
            )
        ]
    )

    route = next(
        node
        for node in result.nodes
        if node.kind == "http_route"
    )

    assert route.method == "GET"
    assert route.path == "/download/:name"
    assert route.authenticated is False
    assert route.risk == "high"

    assert result.summary.filesystems == 1
    assert result.summary.process_executions == 1
    assert result.summary.unauthenticated_routes == 1


def test_ignores_unsupported_language() -> None:
    mapper = AttackSurfaceMapper()

    result = mapper.scan(
        [
            AttackSurfaceFile(
                filename="main.go",
                language="go",
                code='fmt.Println("hello")',
            )
        ]
    )

    assert result.nodes == []
    assert result.edges == []
    assert result.summary.nodes_found == 0
