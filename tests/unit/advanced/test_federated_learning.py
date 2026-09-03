"""nexus.advanced.federated_learning is an honest documented stub: it must
import cleanly and fail loud (NotImplementedError with a specific,
non-generic message) rather than mislabeling centralized training as
federated learning."""
import pytest

from nexus.advanced.federated_learning import FederatedThreatLearning


def test_train_round_raises_specific_not_implemented_error():
    fed = FederatedThreatLearning()
    with pytest.raises(NotImplementedError) as exc_info:
        fed.train_round()

    message = str(exc_info.value)
    assert "multiple real, independent participants" in message
    assert "aggregation server" in message
