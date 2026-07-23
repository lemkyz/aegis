# Contributing to Aegis

Aegis is built around a simple rule:

> A security result should be supported by inspectable evidence.

Contributions are welcome when they preserve that rule and keep the verification pipeline understandable.

## Before opening a pull request

For substantial changes, open an issue first and describe:

- the problem being solved
- the affected component
- the proposed behavior
- the security assumptions involved
- how the change will be verified

Small documentation fixes, test improvements, and narrowly scoped bug fixes may be submitted directly.

Security vulnerabilities should not be reported through public issues. See [SECURITY.md](SECURITY.md).

## Development principles

### Keep generation and verification separate

Code that proposes a patch must not be the only code deciding whether that patch is correct.

Verification should rely on independent checks such as syntax checks, project tests, static rescans, dependency checks, deterministic validation replay, and explicit evidence comparison.

### Do not silently weaken a verdict

Missing or inconclusive evidence must not become `VERIFIED`.

Use the existing verdict model:

- `VERIFIED` when the required evidence supports the fix
- `PARTIAL` when some checks pass but complete proof is unavailable
- `FAILED` when the issue remains, checks fail, or a regression appears

### Preserve explicit authorization

Dynamic validation must remain opt-in and scoped.

Changes involving validation execution must preserve explicit user authorization, repository and entrypoint validation, resource limits, read-only mounts where possible, restricted networking, unprivileged execution, bounded output, and deterministic evidence criteria.

### Avoid hidden behavior

Security-relevant decisions should be visible in code, schemas, reports, or tests.

Do not introduce silent fallback behavior that changes authorization scope, execution policy, finding identity, evidence requirements, or verification results.

## Repository layout

    backend/
      aegis/
        orchestrator/   analysis and workflow coordination
        schemas/        request and response contracts
        security/       authorization, planning, execution, and verification
      tests/            backend test suite

    extension/
      src/              VS Code extension source
      dist/             compiled extension output

    docs/               architecture and design records
    examples/           local fixtures and smoke tests

## Backend setup

    cd backend
    python -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"

Set a local fingerprint key before starting the service:

    export AEGIS_FINGERPRINT_KEY="$(
      python -c 'import secrets; print(secrets.token_urlsafe(48))'
    )"

Run the backend:

    uvicorn aegis.main:app --reload

## Extension setup

    cd extension
    npm install
    npm run compile

Open the `extension` directory in VS Code and launch the Extension Development Host.

## Tests

Run the backend suite:

    cd backend
    source .venv/bin/activate
    python -m pytest -q

Compile the extension:

    cd extension
    npm run compile

Before committing, also run:

    git diff --check

Changes to security-sensitive behavior should include regression coverage.

## Code style

Keep changes focused.

Prefer small functions with explicit inputs and outputs, typed request and response models, deterministic behavior, clear failure states, tests that assert security boundaries, and comments explaining why a restriction exists.

Avoid unrelated refactors, broad exception swallowing, shell command construction from untrusted strings, implicit authorization, fabricated evidence, success states based only on the absence of an error, and dependencies without a clear need.

## Commit messages

Use a concise conventional form:

    feat: add validation replay comparison
    fix: reject repository escape paths
    test: cover blocked dynamic execution
    docs: explain verification verdicts
    refactor: isolate evidence evaluation

A commit should describe one coherent change.

## Pull requests

A useful pull request explains:

- what changed
- why it changed
- which security boundary is affected
- how it was tested
- whether schemas or public behavior changed
- any remaining limitations

Include screenshots for visible extension changes and example request and response data when changing API behavior.

Do not include API keys, access tokens, private repository content, production logs containing secrets, or generated files unrelated to the change.

## Architecture changes

Major changes should be documented before implementation.

Architecture records should describe the problem, proposed design, trust boundaries, rejected alternatives, migration impact, and verification strategy.

## Responsible use

Contributions must support defensive and authorized security work.

Do not submit features designed to bypass authorization, conceal execution, target third-party systems without permission, collect credentials, establish persistence, perform destructive actions, or weaken sandbox restrictions without a documented reason.

Aegis should make security decisions easier to inspect, not easier to hide.
