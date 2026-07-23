# Aegis Backend

Backend service for Aegis evidence-first secure fix verification.

For project documentation, architecture, setup, and usage, see the repository root [README](../README.md).

## Development setup

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -e ".[dev]"

Run the service:

    uvicorn aegis.main:app --reload

Run the test suite:

    python -m pytest -q
