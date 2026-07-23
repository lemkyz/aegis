from __future__ import annotations

import subprocess

from app import build_command


MARKER = "AEGIS_EXPLOIT_CONFIRMED"

# The marker is deliberately encoded as shell octal escapes.
#
# In the vulnerable implementation, the injected second command runs
# and emits MARKER.
#
# In a safely quoted implementation, the payload is treated as one
# literal argument or command token. Its text does not contain MARKER,
# so merely echoing or reporting the payload cannot create false proof.
PAYLOAD = (
    r"hello; printf "
    r"'\101\105\107\111\123\137"
    r"\105\130\120\114\117\111\124\137"
    r"\103\117\116\106\111\122\115\105\104'"
)


def run_validation() -> bool:
    generated_command = build_command(PAYLOAD)

    try:
        completed = subprocess.run(
            generated_command,
            shell=True,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
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
