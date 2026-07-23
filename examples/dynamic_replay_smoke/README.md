# Aegis Dynamic Replay Smoke Fixture

This intentionally vulnerable local fixture exercises the full
Aegis fix-verification flow.

The vulnerable implementation constructs a command from untrusted
input and executes it through a shell.

The authorized sandbox validator should initially print:

    AEGIS_EXPLOIT_CONFIRMED

After Aegis applies the secure patch, the same replay should print:

    AEGIS_SAFE_BEHAVIOR

The fixture must only be used in the isolated, no-network Aegis
validation container.
