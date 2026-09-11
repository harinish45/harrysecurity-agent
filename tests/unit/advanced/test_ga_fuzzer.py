"""Tests for nexus.advanced.ga_fuzzer.

Real correctness tests with synthetic fitness functions: assert evolve()
actually improves the best fitness found over generations relative to the
initial (generation-0) population, not just "it returns something".
"""
import random

import pytest

from nexus.advanced.ga_fuzzer import GeneticFuzzer, MUTATION_ALPHABET


def _reward_special_chars(candidate: str) -> float:
    """Synthetic fitness: reward strings containing fuzzing-relevant
    special characters (quotes/angle-brackets), lightly rewarding length
    too so there's a real gradient to climb."""
    targets = set("'\";<>")
    return sum(1 for c in candidate if c in targets) + 0.01 * len(candidate)


def test_evolve_improves_over_initial_population():
    rng = random.Random(1234)
    fuzzer = GeneticFuzzer(seed_inputs=["admin", "test", "hello"], fitness_fn=_reward_special_chars, rng=rng)

    gen0_population = fuzzer._initial_population(30)
    gen0_best = max(_reward_special_chars(c) for c in gen0_population)

    best = fuzzer.evolve(generations=20, population_size=30, mutation_rate=0.2, top_n=10)

    assert best, "evolve() must return at least one candidate"
    assert best[0][1] >= gen0_best, (
        f"best fitness after evolution ({best[0][1]}) should be >= initial "
        f"population's best ({gen0_best})"
    )


def test_evolve_returns_sorted_descending_by_fitness():
    rng = random.Random(7)
    fuzzer = GeneticFuzzer(seed_inputs=["a", "b"], fitness_fn=_reward_special_chars, rng=rng)
    best = fuzzer.evolve(generations=10, population_size=20, mutation_rate=0.25, top_n=5)

    fitnesses = [f for _, f in best]
    assert fitnesses == sorted(fitnesses, reverse=True)


def test_evolve_respects_top_n():
    rng = random.Random(99)
    fuzzer = GeneticFuzzer(seed_inputs=["x"], fitness_fn=_reward_special_chars, rng=rng)
    best = fuzzer.evolve(generations=5, population_size=15, mutation_rate=0.1, top_n=3)
    assert len(best) <= 3


def test_evolve_bounds_candidate_length():
    """A fitness function that purely rewards length must not cause
    candidates to grow without bound."""
    rng = random.Random(5)
    fuzzer = GeneticFuzzer(seed_inputs=["seed"], fitness_fn=lambda s: len(s), rng=rng)
    best = fuzzer.evolve(generations=15, population_size=20, mutation_rate=0.3, top_n=5)
    assert all(len(c) <= GeneticFuzzer.MAX_CANDIDATE_LENGTH for c, _ in best)


def test_mutation_alphabet_is_fuzzing_relevant():
    # Sanity check the mutation alphabet actually contains fuzzing-relevant
    # characters (quotes, path separators, format tokens) rather than being
    # generic ASCII.
    alphabet = set(MUTATION_ALPHABET)
    for ch in ["'", '"', ";", "/", "\\", "%"]:
        assert ch in alphabet


def test_constructor_rejects_empty_seed_inputs():
    with pytest.raises(ValueError):
        GeneticFuzzer(seed_inputs=[], fitness_fn=lambda s: 0.0)


def test_evolve_rejects_invalid_mutation_rate():
    fuzzer = GeneticFuzzer(seed_inputs=["a"], fitness_fn=lambda s: 0.0)
    with pytest.raises(ValueError):
        fuzzer.evolve(mutation_rate=1.5)


def test_evolve_rejects_nonpositive_generations():
    fuzzer = GeneticFuzzer(seed_inputs=["a"], fitness_fn=lambda s: 0.0)
    with pytest.raises(ValueError):
        fuzzer.evolve(generations=0)
