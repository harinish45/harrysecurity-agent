"""Real behavioral tests for the 6 agent coordination patterns in
nexus/agents/patterns/ — these were at literal 0% test coverage despite
existing as full BaseAgent implementations with real (if simplistic)
deterministic logic.

Note for whoever picks this up next: `pattern_selector_agent.py` only
*names* a pattern (a string in its metadata) — nothing in the codebase
actually imports or dispatches to these 6 classes (`grep -rl "from
nexus.agents.patterns" nexus/` returns nothing outside this test file and
`__init__.py`). They are real, working, unit-testable code, but dead code
from the perspective of any live mission — a real wiring gap, not a bug
these tests can fix. Also: auction.py's `_generate_bids` never reads its
own `requirements` argument, so `AuctionPattern.run()`'s winner is
deterministic regardless of task content (always `reporter_agent`, the
best capability/cost ratio in the hardcoded 5-agent roster) — that's
tested explicitly below as documented behavior, not asserted as ideal
design.
"""
import asyncio

import pytest

from nexus.agents.patterns.auction import AuctionPattern
from nexus.agents.patterns.chain_of_thought import ChainOfThoughtPattern
from nexus.agents.patterns.hierarchical import HierarchicalPattern
from nexus.agents.patterns.hybrid import HybridPattern
from nexus.agents.patterns.recursive import RecursivePattern
from nexus.agents.patterns.swarm import SwarmPattern


def run_async(coro):
    return asyncio.run(coro)


# ── shared: empty-task contract ─────────────────────────────────────────

@pytest.mark.parametrize("pattern_cls", [
    AuctionPattern, ChainOfThoughtPattern, HierarchicalPattern,
    HybridPattern, RecursivePattern, SwarmPattern,
])
def test_pattern_fails_cleanly_on_empty_task(pattern_cls):
    result = run_async(pattern_cls().run(""))
    assert result["status"] == "failed"
    assert result["error"]


# ── AuctionPattern ───────────────────────────────────────────────────────

def test_auction_parses_capability_keywords_from_task():
    pattern = AuctionPattern()
    reqs = pattern._parse_requirements("scan the network and exploit any vulnerabilities, then report")
    assert "reconnaissance" in reqs["capabilities_needed"]
    assert "offensive" in reqs["capabilities_needed"]
    assert "support" in reqs["capabilities_needed"]
    assert reqs["complexity"] == "high"  # >2 capabilities needed


def test_auction_low_complexity_for_single_keyword():
    pattern = AuctionPattern()
    reqs = pattern._parse_requirements("just scan it")
    assert reqs["capabilities_needed"] == ["reconnaissance"]
    assert reqs["complexity"] == "medium"


def test_auction_winner_is_deterministic_best_ratio():
    """_generate_bids ignores its requirements argument entirely — the
    hardcoded 5-agent roster always produces the same winner regardless of
    task content. reporter_agent (0.7 capability / 40 cost = 0.0175) beats
    every other hardcoded bid's ratio."""
    result = run_async(AuctionPattern().run("scan and exploit and analyze the target"))
    assert result["status"] == "completed"
    assert result["metadata"]["winner"]["agent"] == "reporter_agent"
    assert len(result["findings"]) == 5  # one per bid


def test_auction_bids_sorted_by_capability_cost_ratio_descending():
    pattern = AuctionPattern()
    bids = pattern._generate_bids({})
    ratios = [b["ratio"] for b in bids]
    assert ratios == sorted(ratios, reverse=True)


def test_auction_select_winner_handles_empty_bids():
    assert AuctionPattern()._select_winner([]) == {}


# ── ChainOfThoughtPattern ────────────────────────────────────────────────

def test_chain_of_thought_splits_on_sentence_boundaries():
    pattern = ChainOfThoughtPattern()
    steps = pattern._decompose_task("First, scan the host. Then check for open ports. Finally report findings.")
    assert len(steps) == 3
    assert steps[0].startswith("First")


def test_chain_of_thought_single_short_task_stays_one_step():
    pattern = ChainOfThoughtPattern()
    assert pattern._decompose_task("scan it") == ["scan it"]


def test_chain_of_thought_expands_long_single_sentence_into_template_questions():
    pattern = ChainOfThoughtPattern()
    steps = pattern._decompose_task("perform a comprehensive security assessment of the target infrastructure")
    assert steps == [
        "What is the core question?",
        "What evidence is relevant?",
        "What is the answer?",
    ]


def test_chain_of_thought_full_run_produces_one_finding_per_step():
    result = run_async(ChainOfThoughtPattern().run("How do we scan it. Why does it matter."))
    assert result["status"] == "completed"
    assert len(result["findings"]) == result["metadata"]["step_count"] == 2
    assert "Final conclusion derived from all 2 steps" in result["metadata"]["final_conclusion"]


def test_chain_of_thought_reasoning_branches_on_question_word():
    pattern = ChainOfThoughtPattern()
    how_step = pattern._reason_step("How does this work", 1, 2)
    why_step = pattern._reason_step("Why did this happen", 2, 2)
    assert "methods and approaches" in how_step["reasoning"]
    assert "root causes" in why_step["reasoning"]
    assert "Final conclusion" in why_step["conclusion"]  # step_num == total


# ── HierarchicalPattern ──────────────────────────────────────────────────

def test_hierarchical_depth_scales_with_conjunction_count():
    pattern = HierarchicalPattern()
    assert pattern._determine_depth("scan the host") == 1
    assert pattern._determine_depth("scan the host and check ports") == 2
    assert pattern._determine_depth("scan and check and report; verify") == 3


def test_hierarchical_depth1_tree_has_root_plus_one_child():
    result = run_async(HierarchicalPattern().run("scan the host"))
    assert result["status"] == "completed"
    assert result["metadata"]["depth"] == 1
    assert len(result["metadata"]["nodes"]) == 2  # root + 1 child, no grandchildren


def test_hierarchical_depth2_tree_includes_grandchildren():
    result = run_async(HierarchicalPattern().run("scan the host and check ports"))
    assert result["metadata"]["depth"] == 2
    # root(1) + 2 children (min(3, max(1,2))) + 2 grandchildren each = 1 + 2 + 4 = 7
    assert len(result["metadata"]["nodes"]) == 7


def test_hierarchical_all_nodes_get_a_result():
    result = run_async(HierarchicalPattern().run("scan and check and report; verify"))
    assert all(node.get("result", "").startswith("Executed:") for node in result["metadata"]["nodes"])
    assert result["metadata"]["aggregated_result"] != "No results"


# ── HybridPattern ─────────────────────────────────────────────────────────

def test_hybrid_short_focused_task_only_gets_auction_phase():
    result = run_async(HybridPattern().run("scan it"))
    assert result["status"] == "completed"
    phases = [p["pattern"] for p in result["metadata"]["selected_patterns"]]
    assert phases == ["auction"]


def test_hybrid_long_broad_parallel_task_gets_all_four_phases():
    long_task = "scan the target and exploit vulnerabilities and " + "analyze results deeply " * 9
    result = run_async(HybridPattern().run(long_task))
    phases = [p["pattern"] for p in result["metadata"]["selected_patterns"]]
    assert phases == ["chain_of_thought", "hierarchical", "swarm", "auction"]
    assert result["metadata"]["task_characteristics"]["complexity"] == "high"
    assert result["metadata"]["task_characteristics"]["parallelism"] is True


def test_hybrid_task_characteristics_reflect_real_word_count():
    pattern = HybridPattern()
    chars = pattern._analyze_task(" ".join(["word"] * 20))
    assert chars["word_count"] == 20
    assert chars["complexity"] == "medium"


# ── RecursivePattern ──────────────────────────────────────────────────────

def test_recursive_short_task_is_a_single_base_case_node():
    result = run_async(RecursivePattern().run("scan it now"))
    assert result["status"] == "completed"
    assert result["metadata"]["total_nodes"] == 1
    assert "Base case" in result["metadata"]["solution_tree"]["nodes"][0]["result"]


def test_recursive_comma_separated_task_splits_into_subproblems():
    pattern = RecursivePattern()
    subs = pattern._split_task("scan the host, check open ports, enumerate services")
    assert len(subs) == 3


def test_recursive_long_task_produces_multiple_nodes_and_respects_max_depth():
    long_task = ", ".join([f"do meaningful step number {i} thoroughly" for i in range(6)])
    result = run_async(RecursivePattern().run(long_task))
    assert result["metadata"]["total_nodes"] > 1
    assert result["metadata"]["max_depth"] <= 3  # max_depth cap enforced


# ── SwarmPattern ───────────────────────────────────────────────────────────

def test_swarm_spawns_requested_agent_count():
    result = run_async(SwarmPattern().run("explore the target", swarm_size=3))
    assert result["status"] == "completed"
    assert result["metadata"]["swarm_size"] == 3
    assert len(result["metadata"]["agents"]) == 3
    assert len(result["metadata"]["individual_contributions"]) == 3


def test_swarm_default_size_is_five():
    result = run_async(SwarmPattern().run("explore the target"))
    assert result["metadata"]["swarm_size"] == 5
    assert len(result["metadata"]["agents"]) == 5


def test_swarm_findings_include_individual_and_emergent():
    result = run_async(SwarmPattern().run("explore the target", swarm_size=4))
    individual = [f for f in result["findings"] if f["id"].startswith("SWARM-") and "-EM-" not in f["id"]]
    emergent = [f for f in result["findings"] if "-EM-" in f["id"]]
    assert len(individual) == 4
    # every contribution's finding text starts with "Agent ..." (>4 chars) so
    # the emergent-pattern set collapses to exactly one shared pattern
    assert len(emergent) == 1
    assert result["metadata"]["aggregated_results"]["consensus_count"] == 1
