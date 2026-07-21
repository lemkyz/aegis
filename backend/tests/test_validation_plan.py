from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
    ValidationPlanRequest,
)
from aegis.security.validation_plan import (
    ValidationPlanBuilder,
)


def _authorization(
    **overrides: object,
) -> ValidationAuthorizationRequest:
    values: dict[str, object] = {
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
    }
    values.update(overrides)

    return ValidationAuthorizationRequest(
        **values,
    )


def _request(
    **overrides: object,
) -> ValidationPlanRequest:
    values: dict[str, object] = {
        "authorization": _authorization(),
        "runtime": "python",
        "entrypoint": "validation.py",
        "test_type": "command_injection",
    }
    values.update(overrides)

    return ValidationPlanRequest(**values)


def test_builds_hardened_python_plan() -> None:
    result = ValidationPlanBuilder().build(
        _request()
    )

    assert result.ready is True
    assert result.image == "python:3.14-slim"
    assert result.command == [
        "python",
        "-I",
        "/workspace/validation.py",
    ]

    assert result.sandbox.read_only_root is True
    assert result.sandbox.network == "none"
    assert result.sandbox.drop_capabilities == [
        "ALL"
    ]
    assert result.sandbox.no_new_privileges is True
    assert result.sandbox.user == "65532:65532"
    assert result.sandbox.pids_limit == 64

    assert len(result.mounts) == 1
    assert result.mounts[0].read_only is True
    assert result.mounts[0].target == "/workspace"


def test_dry_run_does_not_emit_executable_plan() -> None:
    result = ValidationPlanBuilder().build(
        _request(
            authorization=_authorization(
                dry_run=True,
            )
        )
    )

    assert result.authorized is True
    assert result.execution_allowed is False
    assert result.ready is False
    assert result.image is None
    assert result.command == []
    assert result.mounts == []


def test_rejects_test_outside_authorized_scope() -> None:
    result = ValidationPlanBuilder().build(
        _request(
            test_type="path_traversal",
        )
    )

    assert result.ready is False
    assert any(
        "outside" in denial.lower()
        for denial in result.denials
    )


def test_rejects_parent_directory_entrypoint() -> None:
    result = ValidationPlanBuilder().build(
        _request(
            entrypoint="../validation.py",
        )
    )

    assert result.ready is False
    assert result.command == []
    assert any(
        "escape" in denial.lower()
        for denial in result.denials
    )


def test_builds_node_plan_without_shell() -> None:
    result = ValidationPlanBuilder().build(
        _request(
            runtime="node",
            entrypoint="scripts/validate.js",
        )
    )

    assert result.ready is True
    assert result.image == "node:24-slim"
    assert result.command == [
        "node",
        "--disable-proto=throw",
        "/workspace/scripts/validate.js",
    ]

    assert all(
        token not in {"sh", "bash", "-c"}
        for token in result.command
    )


def test_rejects_non_repository_target() -> None:
    result = ValidationPlanBuilder().build(
        _request(
            authorization=_authorization(
                target_type="local_service",
                target="http://127.0.0.1:8000",
                network_policy="loopback",
            )
        )
    )

    assert result.ready is False
    assert any(
        "local repository" in denial.lower()
        for denial in result.denials
    )
