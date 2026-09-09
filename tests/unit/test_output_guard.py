import pytest

from nexus.foundation.guardrails.output_guard import OutputGuard, OutputGuardError


def test_regex_layer_still_blocks_key_value_secret():
    with pytest.raises(OutputGuardError):
        OutputGuard.validate("api_key: sk-abcdef1234567890")


def test_regex_layer_still_blocks_private_key_header():
    with pytest.raises(OutputGuardError):
        OutputGuard.validate("-----BEGIN RSA PRIVATE KEY-----")


def test_regex_layer_still_blocks_exec_call():
    with pytest.raises(OutputGuardError):
        OutputGuard.validate('bash -c "rm -rf /"')


def test_high_entropy_bare_token_is_blocked():
    # A bare, high-entropy token that does not match the key=value shape.
    token = "Xk29LpQz8vB3nR7mW1cT6dY4sF0gH5jK2aE9uI8oP7qR6"
    output = f"Here is the result: {token} -- copy it somewhere safe."
    with pytest.raises(OutputGuardError):
        OutputGuard.validate(output)


def test_normal_output_passes():
    assert OutputGuard.validate("Scan complete: 3 open ports found on the target host.")


def test_non_string_and_empty_output_pass():
    assert OutputGuard.validate(None)
    assert OutputGuard.validate("")
    assert OutputGuard.validate(42)


def test_already_redacted_key_value_marker_is_not_reblocked():
    """redact_findings() (nexus/foundation/schema.py) replaces a secret's
    value with the literal marker "[REDACTED]" but keeps the "key=" prefix
    for readability, e.g. "api_key=[REDACTED]". Without the negative
    lookahead in the key=value pattern, that marker is itself a
    non-whitespace token and re-trips this same rule — silently discarding
    an already-safely-redacted finding. Confirm it now passes."""
    assert OutputGuard.validate("api_key=[REDACTED] found in config.py line 12")
    assert OutputGuard.validate("password: [REDACTED]")


def test_unredacted_key_value_secret_next_to_a_redacted_one_is_still_blocked():
    """The lookahead exclusion must be narrowly scoped to the literal
    "[REDACTED]" marker, not accidentally swallow a real adjacent secret."""
    with pytest.raises(OutputGuardError):
        OutputGuard.validate("api_key=[REDACTED] but password: hunter2")
