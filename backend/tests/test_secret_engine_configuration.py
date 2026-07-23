import pytest

from aegis.security.secrets import (
    SecretIntelligenceEngine,
)


def test_rejects_short_fingerprint_key() -> None:
    with pytest.raises(
        ValueError,
        match="at least 32 characters",
    ):
        SecretIntelligenceEngine(
            fingerprint_key="too-short",
        )


def test_fingerprint_is_stable_for_same_key() -> None:
    first = SecretIntelligenceEngine(
        fingerprint_key="a" * 32,
    )
    second = SecretIntelligenceEngine(
        fingerprint_key="a" * 32,
    )

    assert first._fingerprint("secret-value") == (
        second._fingerprint("secret-value")
    )


def test_fingerprint_changes_with_key() -> None:
    first = SecretIntelligenceEngine(
        fingerprint_key="a" * 32,
    )
    second = SecretIntelligenceEngine(
        fingerprint_key="b" * 32,
    )

    assert first._fingerprint("secret-value") != (
        second._fingerprint("secret-value")
    )
