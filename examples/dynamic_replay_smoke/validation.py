from __future__ import annotations

import subprocess

from app import run_command


MARKER = "AEGIS_EXPLOIT_CONFIRMED"

PAYLOAD = (
    r"hello; printf "
    r"'\101\105\107\111\123\137"
    r"\105\130\120\114\117\111\124\137"
    r"\103\117\116\106\111\122\115\105\104'"
)


def run_validation() -> bool:
    try:
        completed = run_command(PAYLOAD)
    except subprocess.TimeoutExpired:
        return False

    return (
        completed.returncode == 0
        and MARKER in completed.stdout
    )


def main() -> int:
    if run_validation():
        print(MARKER)
        return 0

    print("AEGIS_SAFE_BEHAVIOR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
