"""
NEXUS-STRIKE — Genetic algorithm for fuzzing INPUT DISCOVERY.

What this does
---------------
A real, working genetic algorithm (GA) that searches an input-string space
for candidates that score highly against a caller-supplied fitness
function. It is generically useful for fuzzing: point it at "response
time delta from baseline," "HTTP status-code anomaly score," "length of
an error message reflected back," "number of distinct exception types
seen," or any other numeric signal that goes up when an input is doing
something interesting to the target — and it will evolve a population of
candidate strings toward whatever that signal rewards.

What this does NOT do
----------------------
- It does NOT generate working exploits. It has no concept of "exploit,"
  "payload," "vulnerability class," or any specific target protocol/API —
  those all live entirely in the fitness function the CALLER writes and
  supplies. This module only does the search: mutate, recombine, select,
  repeat.
- It does NOT talk to a target itself. It never makes an HTTP request,
  opens a socket, or touches a filesystem. ``fitness_fn`` is the only
  thing that can do that, and it is entirely the caller's code — this
  module treats it as an opaque ``str -> float`` callable.
- It does NOT interpret or validate its own output. Whatever strings it
  returns as "highest fitness" are exactly that and nothing more — it is
  up to the caller to inspect them, decide whether they represent a real
  finding, and handle them per their own authorization/scope rules (see
  ``nexus.foundation.guardrails.audit_guard.AuditGuard`` for logging any
  actual use of discovered inputs against a target).

Algorithm (documented, not hidden)
------------------------------------
- Initial population: ``seed_inputs`` repeated/truncated to
  ``population_size``. If fewer seeds than population_size are given,
  seeds are cycled to fill the population (not padded with junk), so
  every member of generation 0 is still a real seed the caller chose.
- Selection: tournament selection (default size 3) — repeatedly sample a
  small random subset of the population and keep its fittest member as a
  parent. Chosen over pure fitness-proportionate (roulette-wheel)
  selection because it doesn't require fitness values to be non-negative
  or degrade to random selection when one candidate dominates early,
  which is common with fuzzing signals like "did it crash" (0/1).
- Crossover: single split-point string crossover — pick a random index
  in each of two parents, splice ``parent1[:i] + parent2[i:]`` for one
  child, ``parent2[:i] + parent1[i:]`` for the other.
- Mutation: per character, with probability ``mutation_rate``, apply one
  of: substitute with a random character from a fuzzing-relevant
  alphabet (not general ASCII — see ``MUTATION_ALPHABET`` below), insert
  a random such character, or delete the character. The alphabet is
  deliberately biased toward characters that matter for fuzzing:
  quotes, path separators, format-string tokens, SQL/shell metacharacters,
  null/control bytes, and common overflow-probing repeats — not "any
  printable ASCII," which wastes most mutations on characters unlikely to
  perturb parser/interpreter behavior.
- Elitism: the single best candidate of each generation is always carried
  into the next generation unmutated, so ``evolve()`` never regresses in
  best-fitness-found from one generation to the next.

Usage
-----
    from nexus.advanced.ga_fuzzer import GeneticFuzzer

    def fitness_fn(candidate: str) -> float:
        # caller-defined: e.g. probe a target and score the response
        return my_probe(candidate)

    fuzzer = GeneticFuzzer(seed_inputs=["admin", "test"], fitness_fn=fitness_fn)
    best = fuzzer.evolve(generations=20, population_size=30)
    # best: list[tuple[str, float]], sorted by fitness descending
"""
from __future__ import annotations

import random
from typing import Callable, Optional


# Fuzzing-relevant mutation alphabet: quotes/escapes, path separators,
# format-string tokens, SQL/shell/template metacharacters, whitespace and
# control-ish characters, and simple overflow-probing repeats — not
# generic printable ASCII, which mostly wastes mutation budget.
MUTATION_ALPHABET = list(
    "'\"`;|&$(){}[]<>\\/%#\n\r\t\0"
    "%s%n%x%d"
    "../"
    "=+-*"
    "0123456789"
    "AAAA"
)


class GeneticFuzzer:
    """Genetic-algorithm search over a string input space for a
    caller-defined fitness signal. See module docstring for exactly what
    this discovers (interesting fuzzing inputs) versus what it explicitly
    does not do (generate exploits, touch a target, interpret results)."""

    MAX_CANDIDATE_LENGTH = 2048
    """Soft cap: mutation stops inserting (only substitutes/deletes) once a
    candidate reaches this length, so a fitness function that rewards raw
    length can't drive candidates to unbounded size."""

    def __init__(
        self,
        seed_inputs: list[str],
        fitness_fn: Callable[[str], float],
        *,
        tournament_size: int = 3,
        rng: Optional[random.Random] = None,
    ) -> None:
        if not seed_inputs:
            raise ValueError("seed_inputs must be non-empty")
        self._seed_inputs = list(seed_inputs)
        self._fitness_fn = fitness_fn
        self._tournament_size = max(2, tournament_size)
        self._rng = rng or random.Random()

    # ── population setup ─────────────────────────────────────────────
    def _initial_population(self, population_size: int) -> list[str]:
        if population_size <= 0:
            raise ValueError("population_size must be positive")
        seeds = self._seed_inputs
        return [seeds[i % len(seeds)] for i in range(population_size)]

    # ── genetic operators ────────────────────────────────────────────
    def _mutate(self, candidate: str, mutation_rate: float) -> str:
        if not candidate:
            # Nothing to mutate positionally; occasionally seed a char in.
            if self._rng.random() < mutation_rate:
                return self._rng.choice(MUTATION_ALPHABET)
            return candidate

        # Each character independently has a mutation_rate chance of being
        # touched at all; when touched, exactly one of substitute/insert/
        # delete happens (each an equal 1/3 share of mutation_rate), so
        # insertions and deletions roughly balance out and candidates don't
        # runaway-grow purely from mutation pressure. Above MAX_CANDIDATE_LENGTH,
        # insertion is skipped in favor of substitution to keep candidates bounded.
        out: list[str] = []
        for ch in candidate:
            r = self._rng.random()
            if r >= mutation_rate:
                out.append(ch)  # unchanged
                continue
            action = self._rng.random()
            if action < 1 / 3:
                continue  # delete
            elif action < 2 / 3 or len(candidate) >= self.MAX_CANDIDATE_LENGTH:
                out.append(self._rng.choice(MUTATION_ALPHABET))  # substitute
            else:
                out.append(ch)
                out.append(self._rng.choice(MUTATION_ALPHABET))  # insert after
        return "".join(out)

    def _crossover(self, parent1: str, parent2: str) -> tuple[str, str]:
        if not parent1 or not parent2:
            return parent1, parent2
        i = self._rng.randint(1, len(parent1) - 1) if len(parent1) > 1 else 1
        j = self._rng.randint(1, len(parent2) - 1) if len(parent2) > 1 else 1
        child1 = parent1[:i] + parent2[j:]
        child2 = parent2[:j] + parent1[i:]
        return child1, child2

    def _tournament_select(self, scored: list[tuple[str, float]]) -> str:
        contenders = [scored[self._rng.randrange(len(scored))] for _ in range(self._tournament_size)]
        return max(contenders, key=lambda item: item[1])[0]

    # ── main loop ────────────────────────────────────────────────────
    def evolve(
        self,
        generations: int = 20,
        population_size: int = 30,
        mutation_rate: float = 0.15,
        *,
        top_n: int = 10,
    ) -> list[tuple[str, float]]:
        """Run the GA for ``generations`` generations over a population of
        ``population_size`` candidates, mutating characters at
        ``mutation_rate`` probability. Returns the best ``top_n``
        (candidate, fitness) pairs found across ALL generations (not just
        the last one), sorted by fitness descending.
        """
        if generations <= 0:
            raise ValueError("generations must be positive")
        if not (0.0 <= mutation_rate <= 1.0):
            raise ValueError("mutation_rate must be between 0 and 1")

        population = self._initial_population(population_size)
        best_seen: dict[str, float] = {}

        for _generation in range(generations):
            scored = [(cand, self._fitness_fn(cand)) for cand in population]
            for cand, fit in scored:
                if cand not in best_seen or fit > best_seen[cand]:
                    best_seen[cand] = fit

            scored.sort(key=lambda item: item[1], reverse=True)
            elite = scored[0][0]

            next_population = [elite]  # elitism: never lose the best
            while len(next_population) < population_size:
                parent1 = self._tournament_select(scored)
                parent2 = self._tournament_select(scored)
                child1, child2 = self._crossover(parent1, parent2)
                next_population.append(self._mutate(child1, mutation_rate)[: self.MAX_CANDIDATE_LENGTH])
                if len(next_population) < population_size:
                    next_population.append(self._mutate(child2, mutation_rate)[: self.MAX_CANDIDATE_LENGTH])

            population = next_population

        ranked = sorted(best_seen.items(), key=lambda item: item[1], reverse=True)
        return ranked[:top_n]
