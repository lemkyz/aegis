import subprocess


def ping_host(host):
    # Simple whitelist validation: allow only letters, numbers, dots and hyphens
    import re
    if not re.fullmatch(r'[A-Za-z0-9.-]+', host):
        raise ValueError('Invalid host')
    # Use subprocess.run with a list to avoid shell interpretation
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
    return result.returncode