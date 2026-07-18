import re
import subprocess


def ping_host(host):
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError("Invalid host")

    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.returncode
