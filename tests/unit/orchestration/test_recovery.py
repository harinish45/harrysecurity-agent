import hashlib
import json
import threading

import pytest

from nexus.orchestration.recovery.checkpoint import Checkpoint
from nexus.orchestration.recovery.error_handler import ErrorHandler
from nexus.orchestration.recovery.fallback import Fallback
from nexus.orchestration.recovery.retry_logic import RetryExhausted, RetryLogic


@pytest.mark.asyncio
async def test_retry_logic_succeeds_after_transient_failures():
    calls = {"n": 0}

    async def _flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("simulated timeout")
        return "ok"

    retry = RetryLogic(max_attempts=5, base_delay=0.01, max_delay=0.02)
    result = await retry.run(_flaky)

    assert result == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_retry_logic_gives_up_after_max_attempts():
    async def _always_fails():
        raise TimeoutError("nope")

    retry = RetryLogic(max_attempts=2, base_delay=0.01, max_delay=0.02)
    with pytest.raises(RetryExhausted):
        await retry.run(_always_fails)


def test_error_handler_classifies_guardrail_vs_transient_vs_permanent():
    assert ErrorHandler.classify("Guardrail blocked: out of scope") == "guardrail"
    assert ErrorHandler.classify("Tool exceeded timeout of 30s") == "transient"
    assert ErrorHandler.classify("connection reset by peer") == "transient"
    assert ErrorHandler.classify("KeyError: no such thing") == "permanent"


def test_error_handler_should_retry_only_transient():
    assert ErrorHandler.should_retry("rate limit exceeded (429)") is True
    assert ErrorHandler.should_retry("Guardrail blocked: scope") is False
    assert ErrorHandler.should_retry("ValueError: bad input") is False


def test_fallback_agent_for_known_and_unknown():
    assert Fallback.agent_for("webapp_agent") == "recon_agent"
    assert Fallback.agent_for("recon_agent") is None


def test_fallback_degraded_result_is_truthfully_failed():
    result = Fallback.degraded_result("exploit_agent", "10.0.0.1", "pwn it", "no fallback available")
    assert result["status"] == "failed"
    assert result["metadata"]["degraded"] is True


def test_checkpoint_save_load_and_clear_round_trip(tmp_path):
    cp = Checkpoint(checkpoint_dir=tmp_path)
    assert cp.load("mission-x") is None
    assert cp.exists("mission-x") is False

    cp.save("mission-x", {"batch": 1, "completed": ["A"]})
    assert cp.exists("mission-x") is True
    assert cp.load("mission-x") == {"batch": 1, "completed": ["A"]}

    cp.clear("mission-x")
    assert cp.exists("mission-x") is False


def test_checkpoint_slugs_unsafe_mission_ids(tmp_path):
    cp = Checkpoint(checkpoint_dir=tmp_path)
    cp.save("../../etc/passwd", {"batch": 1})
    # Must have written *inside* tmp_path, not escaped it. save() now also
    # creates a sidecar `<slug>.json.lock` file (the cross-process advisory
    # lock used to serialize concurrent saves) alongside the checkpoint
    # itself, so assert containment/naming rather than an exact count.
    written = list(tmp_path.iterdir())
    assert written
    assert all(p.parent == tmp_path for p in written)
    names = {p.name for p in written}
    assert "etc_passwd.json" in names
    assert names <= {"etc_passwd.json", "etc_passwd.json.lock"}


def test_checkpoint_concurrent_saves_never_produce_torn_or_corrupt_state(tmp_path):
    """Regression test for the cross-instance checkpoint race: two separate
    FlowController/Checkpoint instances (here modeled as threads, the same
    mechanism a second OS process racing on the same NEXUS_CHECKPOINT_DIR
    would hit) hammering save() for the SAME mission_id must never let a
    concurrent load() observe invalid JSON or a torn write that mixes bytes
    from two different saves — save() must be atomic.
    """
    cp = Checkpoint(checkpoint_dir=tmp_path)
    mission_id = "race-mission"
    payload_size = 200_000  # large enough to span multiple write() syscalls
    iterations = 25
    stop = threading.Event()
    corruption: list[str] = []
    errors: list[BaseException] = []

    def writer(marker: str) -> None:
        try:
            blob = marker * payload_size
            for i in range(iterations):
                cp.save(mission_id, {"batch": i, "marker": marker, "blob": blob})
        except BaseException as exc:  # noqa: BLE001 - surfaced via `errors`, not swallowed
            errors.append(exc)

    def reader() -> None:
        try:
            while not stop.is_set():
                data = cp.load(mission_id)
                if data is None:
                    continue
                blob = data.get("blob", "")
                marker = data.get("marker", "")
                if len(blob) != payload_size or set(blob) != {marker}:
                    corruption.append(f"torn/invalid read: marker={marker!r} blob_len={len(blob)}")
        except BaseException as exc:  # noqa: BLE001 - surfaced via `errors`, not swallowed
            errors.append(exc)

    writers = [threading.Thread(target=writer, args=(m,)) for m in ("A", "B", "C", "D")]
    readers = [threading.Thread(target=reader) for _ in range(4)]
    for t in writers + readers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    for t in readers:
        t.join()

    # Both invariants matter: no thread crashed (e.g. os.replace() choking
    # on a concurrent reader's open handle) AND no reader ever observed a
    # torn/invalid write.
    assert errors == []
    assert corruption == []


def test_checkpoint_load_rejects_wrong_typed_batch(tmp_path):
    # A checkpoint hand-edited (or written by an incompatible version) so
    # "batch" is a string instead of an int is syntactically valid JSON but
    # would blow up FlowController._run's `batch_num <= already_done_through_batch`
    # (int <= str -> TypeError) if handed back as-is. load() must treat it
    # the same as a missing/corrupt checkpoint: return None.
    cp = Checkpoint(checkpoint_dir=tmp_path)
    path = cp._path("mission-x")
    path.write_text('{"batch": "5", "tasks": [{"id": "T1"}]}', encoding="utf-8")

    assert cp.load("mission-x") is None


def test_checkpoint_load_rejects_task_with_non_hashable_id(tmp_path):
    # A "tasks" entry whose "id" is a list (unhashable) would blow up
    # FlowController._run's `{t["id"]: t for t in batch}`.
    cp = Checkpoint(checkpoint_dir=tmp_path)
    path = cp._path("mission-y")
    path.write_text('{"batch": 1, "tasks": [{"id": ["not", "a", "string"]}]}', encoding="utf-8")

    assert cp.load("mission-y") is None


def test_checkpoint_load_rejects_wrong_typed_completed_and_context(tmp_path):
    cp = Checkpoint(checkpoint_dir=tmp_path)

    path_a = cp._path("mission-completed")
    path_a.write_text('{"batch": 1, "completed": "not-a-list"}', encoding="utf-8")
    assert cp.load("mission-completed") is None

    path_b = cp._path("mission-context")
    path_b.write_text('{"batch": 1, "context": "not-a-dict"}', encoding="utf-8")
    assert cp.load("mission-context") is None


def test_checkpoint_load_rejects_non_object_json(tmp_path):
    # Valid JSON, but not a JSON object at all (e.g. a list) -- must
    # degrade to None rather than handing back something callers can't
    # even call .get() on reliably as the expected shape.
    cp = Checkpoint(checkpoint_dir=tmp_path)
    path = cp._path("mission-list")
    path.write_text('[1, 2, 3]', encoding="utf-8")

    assert cp.load("mission-list") is None


def test_checkpoint_load_accepts_well_formed_checkpoint(tmp_path):
    cp = Checkpoint(checkpoint_dir=tmp_path)
    state = {
        "batch": 2,
        "total_batches": 4,
        "completed": [{"agent": "recon_agent", "status": "completed", "findings": []}],
        "context": {"recon_agent": {"status": "completed"}},
        "tasks": [{"id": "T1", "agent": "recon_agent"}, {"id": "T2", "agent": "network_agent"}],
    }
    cp.save("mission-good", state)

    assert cp.load("mission-good") == state


def test_checkpoint_load_accepts_missing_optional_fields(tmp_path):
    # save()/load() must keep working for a minimal checkpoint that omits
    # keys entirely (e.g. an older writer, or a caller that never sets
    # total_batches/context) -- the validation must only check *type* when
    # a field is present, never require every field to exist.
    cp = Checkpoint(checkpoint_dir=tmp_path)
    cp.save("mission-minimal", {"batch": 1})
    assert cp.load("mission-minimal") == {"batch": 1}


def test_checkpoint_load_rejects_file_not_written_by_save(tmp_path, monkeypatch):
    # Regression for the missing-integrity-check bug: load() used to trust
    # ANY syntactically-valid JSON found at the checkpoint path, so an actor
    # with filesystem write access to the checkpoint file (no code-execution
    # needed) could hand-craft one from scratch and have it accepted as a
    # genuine, signed checkpoint. save() always writes a signed envelope, so
    # a file that never went through save() -- however well-formed its
    # content looks -- must never come back as trusted state.
    monkeypatch.setenv("NEXUS_VAULT_DIR", str(tmp_path / "vault"))
    cp = Checkpoint(checkpoint_dir=tmp_path / "checkpoints")
    path = cp._path("mission-forged")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"batch": 5, "total_batches": 5, "completed": [], "context": {}, "tasks": [{"id": "T1"}]}),
        encoding="utf-8",
    )

    assert cp.load("mission-forged") is None


def test_checkpoint_load_rejects_tampered_batch_matching_the_exploit_scenario(tmp_path, monkeypatch):
    # Regression for the exact attack described in the report: a genuine
    # checkpoint mid-mission (batch 1 of 2 done) is hand-edited on disk to
    # set "batch" == "total_batches" so FlowController's resume path would
    # skip every remaining batch and hand back fabricated results. The
    # signature was computed over the original payload, so tampering the
    # payload string (even by one character) must be caught and load() must
    # degrade to None -- exactly as if there were no checkpoint at all.
    monkeypatch.setenv("NEXUS_VAULT_DIR", str(tmp_path / "vault"))
    cp = Checkpoint(checkpoint_dir=tmp_path / "checkpoints")
    genuine_state = {
        "batch": 1,
        "total_batches": 2,
        "completed": [{"agent": "recon_agent", "status": "completed", "findings": []}],
        "context": {},
        "tasks": [{"id": "P1", "agent": "recon_agent"}, {"id": "P2", "agent": "network_agent"}],
    }
    path = cp.save("mission-exploit", genuine_state)
    assert cp.load("mission-exploit") == genuine_state  # sanity: genuine checkpoint verifies fine

    envelope = json.loads(path.read_text(encoding="utf-8"))
    tampered_payload = envelope["payload"].replace('"batch": 1', '"batch": 2')
    assert tampered_payload != envelope["payload"]
    envelope["payload"] = tampered_payload  # attacker edits the payload but can't re-sign it
    path.write_text(json.dumps(envelope), encoding="utf-8")

    # Without the fix, this would come back as the attacker's edited state
    # (batch == total_batches), causing FlowController to skip every batch.
    assert cp.load("mission-exploit") is None


def test_checkpoint_load_rejects_forged_signature_over_forged_payload(tmp_path, monkeypatch):
    # A more capable attacker who also edits/recomputes the "hmac" field
    # themselves (rather than re-using the genuine one) still can't produce
    # a signature this process will accept, because doing so requires the
    # server-side key -- which never lives in the checkpoint directory the
    # attacker was assumed to have write access to.
    monkeypatch.setenv("NEXUS_VAULT_DIR", str(tmp_path / "vault"))
    cp = Checkpoint(checkpoint_dir=tmp_path / "checkpoints")
    path = cp._path("mission-forged-sig")
    path.parent.mkdir(parents=True, exist_ok=True)
    forged_payload = json.dumps({"batch": 99, "total_batches": 99, "tasks": [{"id": "T1"}]})
    path.write_text(
        json.dumps({"payload": forged_payload, "hmac": hashlib.sha256(forged_payload.encode()).hexdigest()}),
        encoding="utf-8",
    )

    assert cp.load("mission-forged-sig") is None
