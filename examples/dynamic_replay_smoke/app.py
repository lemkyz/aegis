from __future__ import annotations

import subprocess


def run_command(
    user_input: str,
) -> subprocess.CompletedProcess[str]:
    """
    Intentionally vulnerable training fixture.

    Untrusted input is interpolated into a command string
    and executed through a shell.
    """
    command = f'printf "%s" {user_input}'

    return subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )


def main() -> None:
    value = input("Value: ")
    completed = run_command(value)
    print(completed.stdout, end="")


if __name__ == "__main__":
    main()
