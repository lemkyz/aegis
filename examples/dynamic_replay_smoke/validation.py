from __future__ import annotations

from app import build_command


MARKER = "AEGIS_EXPLOIT_CONFIRMED"
PAYLOAD = "hello; printf AEGIS_EXPLOIT_CONFIRMED"


def main() -> int:
    generated = build_command(PAYLOAD)

    unsafe_chaining_present = any(
        operator in generated
        for operator in (";", "||")
    )

    if unsafe_chaining_present and MARKER in generated:
        print(MARKER)
        return 0

    print("AEGIS_SAFE_BEHAVIOR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
