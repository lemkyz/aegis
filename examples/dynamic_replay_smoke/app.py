from __future__ import annotations


def build_command(user_input: str) -> str:
    """
    Intentionally vulnerable training fixture.

    This returns a shell-like command string but never
    executes it.
    """
    return "printf SAFE && " + user_input


def main() -> None:
    value = input("Value: ")
    print(build_command(value))


if __name__ == "__main__":
    main()
