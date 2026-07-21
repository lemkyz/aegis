# Aegis Dynamic Replay Smoke Fixture

This intentionally vulnerable fixture tests Aegis dynamic
replay without executing a real shell command.

The vulnerable implementation should print:

    AEGIS_EXPLOIT_CONFIRMED

After a secure fix, it should print:

    AEGIS_SAFE_BEHAVIOR

The validator only inspects the generated command string.
It never invokes a shell.
