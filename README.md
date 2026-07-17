# Aegis

Aegis is an experimental AI security assistant built directly into VS Code.

The project started with a simple question:

> Can an AI security assistant do more than merely warn that code looks suspicious?

Aegis aims to detect security weaknesses, show concrete scanner evidence, explain the risk, suggest a safer implementation, apply the fix with the developer's approval, and then verify the result by scanning the code again.

It is currently an early working prototype, not a complete security product.

## What works today

The current prototype supports an end-to-end Python SQL injection workflow.

Aegis can:

- analyze code selected inside VS Code
- send the code to a local FastAPI backend
- scan it with Semgrep
- use NVIDIA-hosted GPT-OSS 120B for deeper analysis
- produce structured security findings
- show severity, confidence, CWE and OWASP information
- display the exact scanner evidence
- generate a proposed secure patch
- preview the patch before changing the file
- apply the patch only after user approval
- scan the corrected code again
- skip the AI request entirely when Semgrep finds no evidence

That final optimization is important. Safe code can now return a result within seconds instead of waiting several minutes for a large language model.

## How the analysis works

The current flow is:

    Selected code
        |
        v
    Semgrep scan
        |
        +-- No evidence found
        |       |
        |       v
        |   Return Findings: 0
        |
        +-- Evidence found
                |
                v
          AI security analysis
                |
                v
          Structured finding
                |
                v
          Secure patch preview
                |
                v
          User approval
                |
                v
          Apply and re-scan

Aegis follows an evidence-first approach. The language model should not be treated as proof on its own. Scanner results, source lines and later dynamic validation results should support every important conclusion.

## Project structure

    aegis/
    ├── backend/            FastAPI backend and analysis orchestration
    ├── extension/          VS Code extension
    ├── security-engine/    Semgrep rules and security tooling
    ├── docs/               Vision and architecture RFCs
    ├── examples/           Vulnerable test files
    ├── agents/             Future specialist agents
    ├── knowledge/          Future project security memory
    └── tests/              Automated tests

## Starting the backend

Open a terminal and run:

    cd ~/aegis/backend
    source .venv/bin/activate

    set -a
    source .env
    set +a

    uvicorn aegis.main:app --host 127.0.0.1 --port 8000 --reload

Keep this terminal open while using the VS Code extension.

The health endpoint is available at:

    http://127.0.0.1:8000/health

You can test it with:

    curl http://127.0.0.1:8000/health

## Running backend tests

    cd ~/aegis/backend
    source .venv/bin/activate
    python -m pytest -q

## Building the VS Code extension

Open another terminal:

    cd ~/aegis/extension
    npm install
    npm run compile

Then open the project:

    cd ~/aegis
    code .

Press F5 and choose:

    Run Aegis Extension

A separate Extension Development Host window will open.

Inside that window:

1. Open a Python file.
2. Select the code you want to inspect.
3. Right-click the selection.
4. Choose "Aegis: Analyze Selected Code".
5. Review the generated report.
6. Apply the proposed secure fix when available.
7. Select the corrected code and analyze it again.

## Example

Vulnerable code:

    import sqlite3


    def get_user(user_id):
        db = sqlite3.connect("app.db")
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return db.execute(query).fetchone()

Aegis currently detects this as a possible SQL injection and reports information such as:

    Severity: HIGH
    CWE: CWE-89
    OWASP: A03:2021
    Scanner: Semgrep

A safer version is:

    import sqlite3


    def get_user(user_id):
        db = sqlite3.connect("app.db")
        query = "SELECT * FROM users WHERE id = ?"
        return db.execute(query, (user_id,)).fetchone()

When the corrected code is scanned again, the current Semgrep rule returns:

    Findings: 0

This does not mean the entire application is guaranteed to be secure. It only means the active scanner did not find evidence covered by the current rules.

## Security principles

Aegis is being designed around the following principles:

- evidence before conclusions
- language model output is not proof
- findings must use a structured and validated format
- code changes always require user approval
- secrets must never be committed to Git
- attack simulation must only run in authorized and isolated environments
- real private data must never be used during exploit testing
- a fix should be re-tested after it is applied
- normal application behavior should still work after a security fix

## Current limitations

Aegis is still a small prototype.

At the moment:

- the main workflow is focused on Python
- SQL injection is the primary custom Semgrep rule
- analysis operates on selected code
- suspicious code still requires a slow GPT-OSS 120B request
- repository-wide analysis is not implemented
- analysis caching is not implemented
- dynamic exploit validation is not implemented
- red-team, blue-team and judge agents are not implemented
- project-wide security memory is not implemented
- JavaScript and TypeScript support is not implemented

## Next milestones

The next development steps are:

1. Send only scanner-relevant code sections to the AI model.
2. Add more Python security rules.
3. Cache unchanged analysis results.
4. Scan entire files and repositories.
5. Show scanner findings immediately while AI analysis continues.
6. Build an isolated exploit validation environment.
7. Re-run the same attack simulation after applying a fix.
8. Add regression checks so security fixes do not break normal behavior.
9. Add multiple specialist models and evidence-based consensus.
10. Add JavaScript and TypeScript support.

## Documentation

The main design documents are:

- docs/RFC-0001-VISION.md
- docs/RFC-0002-ARCHITECTURE.md

## Status

Aegis is an early-stage research and development project.

It currently demonstrates a working security loop:

    Detect
    Explain
    Fix
    Apply
    Re-scan
    Verify

The long-term goal is to evolve this into a security-native development environment that can reason about a project, test security assumptions safely, and help developers prevent real vulnerabilities before software reaches production.
