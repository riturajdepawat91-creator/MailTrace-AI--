
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from services.analysis_provenance import (
    AnalysisProvenanceEngine,
    DependencySnapshot,
    ProvenanceValidationError,
)
from services.analysis_provenance.process_lock import ProcessSafeRLock
from services.analysis_provenance.rules import DETERMINISTIC


def new_engine(tmp):
    return AnalysisProvenanceEngine(storage_dir=tmp, actor="v11-test")


def execution(engine, **kwargs):
    values = dict(
        investigation_id="INV-V11",
        evidence_id="EV-V11",
        input_sha256="a" * 64,
        input_size_bytes=100,
        engine_id="mailtrace",
        engine_version="1.1",
        analysis_version="1.1",
        determinism_class=DETERMINISTIC,
    )
    values.update(kwargs)
    return engine.create_execution(**values)


def test_01_explicit_finding_binding():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        artifact = engine.register_artifact(
            artifact_type="finding",
            payload={
                "finding_id": "F-EXPLICIT",
                "severity": "HIGH",
            },
            finding_ids=("F-EXPLICIT",),
        )
        exe = execution(engine)
        engine.finalize_execution(
            exe.execution_id,
            output_artifact_ids=(artifact.artifact_id,),
            finding_ids=("F-EXPLICIT",),
        )
        stored = engine.get_execution(exe.execution_id)
        assert stored["finding_lineage"]["F-EXPLICIT"]["binding_state"] == "BOUND"
        assert stored["finding_lineage"]["F-EXPLICIT"]["artifact_ids"] == [artifact.artifact_id]
        assert engine.verify_chain().valid


def test_02_legacy_finding_reference_remains_compatible():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        artifact = engine.register_artifact(
            artifact_type="derived",
            payload={"value": 1},
        )
        exe = execution(engine)
        engine.finalize_execution(
            exe.execution_id,
            output_artifact_ids=(artifact.artifact_id,),
            finding_ids=("F-LEGACY",),
        )
        stored = engine.get_execution(exe.execution_id)
        assert stored["finding_lineage"]["F-LEGACY"]["binding_state"] == "UNBOUND_LEGACY"
        assert engine.verify_chain().valid


def test_03_finding_binding_tamper_detected():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        artifact = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-TAMPER"},
        )
        exe = execution(engine)
        engine.finalize_execution(
            exe.execution_id,
            output_artifact_ids=(artifact.artifact_id,),
            finding_ids=("F-TAMPER",),
        )
        engine._state["finding_bindings"]["F-TAMPER"] = []
        result = engine.verify_chain()
        assert not result.valid
        assert result.conflict_count >= 1


def test_04_replay_is_observational():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        exe = execution(engine)
        engine.finalize_execution(exe.execution_id)
        before = engine.get_execution(exe.execution_id)
        result = engine.compare_replay(
            exe.execution_id,
            replay_execution_fingerprint=before["execution_fingerprint"],
        )
        after = engine.get_execution(exe.execution_id)
        assert result.state == "MATCHED"
        assert before == after


def test_05_replay_output_semantics():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        original = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-ORIGINAL", "severity": "HIGH"},
        )
        replay = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-REPLAY", "severity": "LOW"},
        )
        exe = execution(engine)
        engine.finalize_execution(
            exe.execution_id,
            output_artifact_ids=(original.artifact_id,),
        )
        result = engine.compare_replay(
            exe.execution_id,
            replay_execution_fingerprint=(
                engine.get_execution(exe.execution_id)["execution_fingerprint"]
            ),
            replay_output_artifact_ids=(replay.artifact_id,),
        )
        assert result.state == "MISMATCHED"
        assert result.output_mismatches


def test_06_dependency_drift():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        dep = DependencySnapshot(
            dependency_id="DNS-V11",
            dependency_type="dns",
            provider="test",
            observed_at_utc="2026-09-08T00:00:00+00:00",
            request_fingerprint="b" * 64,
            response_fingerprint="c" * 64,
            version="1",
            status="OBSERVED",
        )
        engine.register_dependency(dep)
        exe = execution(
            engine,
            dependency_ids=("DNS-V11",),
        )
        engine.finalize_execution(exe.execution_id)
        result = engine.compare_replay(
            exe.execution_id,
            replay_execution_fingerprint="f" * 64,
            dependency_fingerprints={"DNS-V11": "d" * 64},
        )
        assert result.state == "DEPENDENCY_DRIFT"
        assert result.dependency_drift == ("DNS-V11",)


def test_07_torn_tail_recovered():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        exe = execution(engine)
        engine.finalize_execution(exe.execution_id)
        events = Path(d) / "events.jsonl"
        with events.open("ab") as handle:
            handle.write(b'{"torn":true')
            handle.flush()
            os.fsync(handle.fileno())

        recovered = new_engine(d)
        assert len(recovered.list_records()) == 1
        assert (Path(d) / "events.jsonl.recovery_torn_tail").exists()


def test_08_uncommitted_tail_quarantined():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        exe = execution(engine)
        engine.finalize_execution(exe.execution_id)
        events = Path(d) / "events.jsonl"
        records = engine.list_records()
        extra = dict(records[0])
        extra["sequence"] = 9999

        with events.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(extra, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        recovered = new_engine(d)
        assert len(recovered.list_records()) == 1
        assert (Path(d) / "events.jsonl.recovery_uncommitted_tail").exists()
        result = recovered.verify_chain()
        assert not result.valid
        assert any("uncommitted journal tail" in x for x in result.issues)


def test_09_state_journal_divergence_is_reported_on_verify():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        exe = execution(engine)
        engine.finalize_execution(exe.execution_id)

        state_path = Path(d) / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["records"][0]["status"] = "ATTACKER_MODIFIED"
        state_path.write_text(
            json.dumps(state),
            encoding="utf-8",
        )

        reopened = new_engine(d)
        result = reopened.verify_chain()
        assert not result.valid
        assert not result.chain_valid
        assert any("diverges from persisted state" in x for x in result.issues)


def test_10_hash_schema_tamper():
    with tempfile.TemporaryDirectory() as d:
        engine = new_engine(d)
        exe = execution(engine)
        engine.finalize_execution(exe.execution_id)

        state = json.loads(
            (Path(d) / "state.json").read_text(encoding="utf-8")
        )
        state["records"][0]["record_hash_schema_version"] = 999
        (Path(d) / "state.json").write_text(
            json.dumps(state),
            encoding="utf-8",
        )

        result = new_engine(d).verify_chain()
        assert not result.valid
        assert any("Unsupported record hash schema" in x for x in result.issues)


def test_11_lock_reentrant():
    with tempfile.TemporaryDirectory() as d:
        lock = ProcessSafeRLock(Path(d) / "lock")
        lock.acquire()
        lock.acquire()
        lock.release()
        lock.release()


def test_12_lock_cross_process():
    with tempfile.TemporaryDirectory() as d:
        lock_path = str(Path(d) / "lock")
        code = f"""
import sys, time
from services.analysis_provenance.process_lock import ProcessSafeRLock
lock = ProcessSafeRLock({lock_path!r}, timeout_seconds=5)
with lock:
    print("LOCK_HELD", flush=True)
    time.sleep(1.5)
"""
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(Path.cwd()),
        )
        line = proc.stdout.readline().strip()
        assert line == "LOCK_HELD"

        contender = ProcessSafeRLock(
            lock_path,
            timeout_seconds=0.25,
        )
        blocked = False
        try:
            contender.acquire()
            contender.release()
        except TimeoutError:
            blocked = True

        proc.wait(timeout=5)
        assert blocked
        assert proc.returncode == 0


def test_13_legacy_state_migrates():
    with tempfile.TemporaryDirectory() as d:
        state = {
            "schema_version": 1,
            "sequence": 0,
            "last_record_hash": None,
            "executions": {},
            "artifacts": {},
            "dependencies": {},
            "records": [],
        }
        Path(d, "state.json").write_text(
            json.dumps(state),
            encoding="utf-8",
        )
        engine = new_engine(d)
        assert engine._state["finding_bindings"] == {}


TESTS = [
    test_01_explicit_finding_binding,
    test_02_legacy_finding_reference_remains_compatible,
    test_03_finding_binding_tamper_detected,
    test_04_replay_is_observational,
    test_05_replay_output_semantics,
    test_06_dependency_drift,
    test_07_torn_tail_recovered,
    test_08_uncommitted_tail_quarantined,
    test_09_state_journal_divergence_is_reported_on_verify,
    test_10_hash_schema_tamper,
    test_11_lock_reentrant,
    test_12_lock_cross_process,
    test_13_legacy_state_migrates,
]


if __name__ == "__main__":
    failures = []
    for test in TESTS:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:
            failures.append((test.__name__, type(exc).__name__, str(exc)))
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")

    print("V11_TESTS=" + str(len(TESTS)))
    print("V11_FAILS=" + str(len(failures)))

    if failures:
        raise SystemExit(1)

    print("V11_HIGH_ASSURANCE=PASS")
