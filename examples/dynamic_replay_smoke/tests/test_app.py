from app import build_command


def test_build_command_preserves_safe_value() -> None:
    assert build_command("hello") == (
        "printf SAFE && hello"
    )


def test_build_command_returns_string() -> None:
    assert isinstance(build_command("hello"), str)
