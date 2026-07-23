from aegis.orchestrator.analyzer import SecurityAnalyzer


VULNERABLE_SOURCE = '''\
from __future__ import annotations

import subprocess


def run_command(
    user_input: str,
) -> subprocess.CompletedProcess[str]:
    command = f'printf "%s" {user_input}'

    return subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
'''


def test_builds_subprocess_shell_patch() -> None:
    patched = SecurityAnalyzer._build_local_scanner_patch(
        rule_id=(
            "aegis.python.command-injection."
            "subprocess-shell"
        ),
        source_code=VULNERABLE_SOURCE,
    )

    assert patched is not None
    assert (
        'command = ["printf", "%s", user_input]'
        in patched
    )
    assert "shell=False" in patched
    assert "shell=True" not in patched


def test_rejects_unrelated_command_pattern() -> None:
    patched = SecurityAnalyzer._build_local_scanner_patch(
        rule_id=(
            "aegis.python.command-injection."
            "subprocess-shell"
        ),
        source_code=(
            "import subprocess\n"
            "subprocess.run('whoami', shell=True)\n"
        ),
    )

    assert patched is None


def test_rejects_unsupported_rule() -> None:
    patched = SecurityAnalyzer._build_local_scanner_patch(
        rule_id="unknown.rule",
        source_code=VULNERABLE_SOURCE,
    )

    assert patched is None
