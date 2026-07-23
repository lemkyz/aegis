from app import run_command


def test_run_command_handles_safe_value() -> None:
    completed = run_command("hello")

    assert completed.returncode == 0
    assert completed.stdout == "hello"


def test_run_command_captures_output() -> None:
    completed = run_command("world")

    assert isinstance(completed.stdout, str)
