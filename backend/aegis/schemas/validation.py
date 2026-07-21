from typing import Literal

from pydantic import BaseModel, Field


ValidationTargetType = Literal[
    "local_repository",
    "local_service",
    "container_image",
]

ValidationTestType = Literal[
    "command_injection",
    "sql_injection",
    "path_traversal",
    "ssrf",
    "authentication_bypass",
    "unsafe_data_flow",
]

ValidationNetworkPolicy = Literal[
    "disabled",
    "loopback",
]


class ValidationAuthorizationRequest(BaseModel):
    authorization_confirmed: bool

    target_type: ValidationTargetType
    target: str = Field(
        min_length=1,
        max_length=1_000,
    )

    allowed_test_types: list[
        ValidationTestType
    ] = Field(
        min_length=1,
        max_length=20,
    )

    dry_run: bool = True

    timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=60,
    )
    memory_limit_mb: int = Field(
        default=256,
        ge=64,
        le=2_048,
    )
    cpu_limit: float = Field(
        default=0.5,
        ge=0.1,
        le=2.0,
    )

    network_policy: ValidationNetworkPolicy = (
        "disabled"
    )


class ValidationScope(BaseModel):
    target_type: ValidationTargetType
    target: str
    allowed_test_types: list[
        ValidationTestType
    ]


class ValidationLimits(BaseModel):
    timeout_seconds: int
    memory_limit_mb: int
    cpu_limit: float
    network_policy: ValidationNetworkPolicy


class ValidationAuthorizationResponse(BaseModel):
    contract: str

    authorized: bool
    execution_allowed: bool
    dry_run: bool

    normalized_scope: ValidationScope
    limits: ValidationLimits

    reasons: list[str] = Field(
        default_factory=list,
    )
    denials: list[str] = Field(
        default_factory=list,
    )


ValidationRuntime = Literal[
    "python",
    "node",
]


class ValidationPlanRequest(BaseModel):
    authorization: ValidationAuthorizationRequest

    runtime: ValidationRuntime
    entrypoint: str = Field(
        min_length=1,
        max_length=500,
    )
    test_type: ValidationTestType


class ValidationSandboxPolicy(BaseModel):
    read_only_root: bool
    network: Literal[
        "none",
        "loopback",
    ]
    drop_capabilities: list[str]
    no_new_privileges: bool
    user: str
    memory_limit_mb: int
    cpu_limit: float
    timeout_seconds: int
    pids_limit: int
    writable_tmpfs: list[str]


class ValidationMount(BaseModel):
    source: str
    target: str
    read_only: bool


class ValidationExecutionPlanResponse(BaseModel):
    planner: str

    authorized: bool
    execution_allowed: bool
    ready: bool

    runtime: ValidationRuntime
    image: str | None = None
    command: list[str] = Field(
        default_factory=list,
    )

    sandbox: ValidationSandboxPolicy
    mounts: list[ValidationMount] = Field(
        default_factory=list,
    )

    reasons: list[str] = Field(
        default_factory=list,
    )
    denials: list[str] = Field(
        default_factory=list,
    )
