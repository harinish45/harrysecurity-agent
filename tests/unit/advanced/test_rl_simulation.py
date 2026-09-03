"""nexus.advanced.rl_simulation is an honest documented stub: it must
import cleanly and fail loud (NotImplementedError with a specific,
non-generic message) rather than faking a simulation."""
import pytest

from nexus.advanced.rl_simulation import AdversarialSimulation


def test_run_simulation_raises_specific_not_implemented_error():
    sim = AdversarialSimulation()
    with pytest.raises(NotImplementedError) as exc_info:
        sim.run_simulation()

    message = str(exc_info.value)
    assert "training loop" in message
    assert "red/blue" in message
