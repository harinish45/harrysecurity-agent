"""nexus.advanced.adversarial_ml is an honest documented stub: it must
import cleanly and fail loud (NotImplementedError with a specific,
non-generic message) rather than silently pretending to work."""
import pytest

from nexus.advanced.adversarial_ml import AdversarialMLDefense


def test_detect_evasion_raises_specific_not_implemented_error():
    defense = AdversarialMLDefense()
    with pytest.raises(NotImplementedError) as exc_info:
        defense.detect_evasion({"some": "input"})

    message = str(exc_info.value)
    assert "first-party ML classifier" in message
    assert "adversarial evasion" in message
