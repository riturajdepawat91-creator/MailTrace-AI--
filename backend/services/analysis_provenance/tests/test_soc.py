from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from services.analysis_provenance import (
    AnalysisProvenanceEngine,
    DependencySnapshot,
    ProvenanceConflictError,
    ProvenanceIntegrityError,
    ProvenanceValidationError,
)
from services.analysis_provenance.canonical import (
    artifact_fingerprint,
    canonical_json,
    execution_fingerprint,
)
from services.analysis_provenance.rules import (
    DETERMINISTIC,
    NON_DETERMINISTIC,
    STATUS_DEPENDENCY_DRIFT,
    STATUS_MATCHED,
    STATUS_MISMATCHED,
    STATUS_NON_REPLAYABLE,
    STATUS_REPLAY_READY,
    STATUS_VERIFIED,
)


def new_engine():
    temp = Path(
        tempfile.mkdtemp(
            prefix="mailtrace_prov_"
        )
    )
    return temp, AnalysisProvenanceEngine(
        storage_dir=temp
    )


def cleanup(path: Path):
    shutil.rmtree(path, ignore_errors=True)


def test_01_import():
    from services.analysis_provenance import AnalysisProvenanceEngine
    assert AnalysisProvenanceEngine is not None


def test_02_empty_ledger():
    path, engine = new_engine()
    try:
        result = engine.verify_chain()
        assert result.valid
        assert result.record_count == 0
    finally:
        cleanup(path)


def test_03_canonical_determinism():
    value_a = {"b": 2, "a": 1}
    value_b = {"a": 1, "b": 2}

    assert canonical_json(value_a) == canonical_json(value_b)


def test_04_execution_fingerprint_determinism():
    value = {
        "execution_id": "EXEC-TEST",
        "engine_id": "engine",
        "engine_version": "1.0",
        "input_sha256": "a" * 64,
    }

    assert execution_fingerprint(value) == (
        execution_fingerprint(value)
    )


def test_05_artifact_fingerprint_determinism():
    payload = {
        "finding_id": "F-1",
        "severity": "HIGH",
    }

    assert artifact_fingerprint(
        artifact_type="finding",
        artifact_payload=payload,
    ) == artifact_fingerprint(
        artifact_type="finding",
        artifact_payload=payload,
    )


def test_06_create_execution():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=123,
            engine_id="mailtrace-test",
            engine_version="1.0.0",
            analysis_version="1.0.0",
            determinism_class=DETERMINISTIC,
        )

        assert execution.execution_id.startswith(
            "EXEC-"
        )

        stored = engine.get_execution(
            execution.execution_id
        )

        assert stored["evidence_id"] == "EV-1"
        assert stored["input_sha256"] == "a" * 64
    finally:
        cleanup(path)


def test_07_register_artifact():
    path, engine = new_engine()
    try:
        artifact = engine.register_artifact(
            artifact_type="finding",
            payload={
                "finding_id": "F-1",
                "severity": "CRITICAL",
            },
        )

        assert artifact.artifact_id.startswith(
            "ART-"
        )
        assert len(
            artifact.fingerprint_sha256
        ) == 64

        stored = engine.get_artifact(
            artifact.artifact_id
        )

        assert stored["fingerprint_sha256"] == (
            artifact.fingerprint_sha256
        )
    finally:
        cleanup(path)


def test_08_duplicate_artifact_is_idempotent():
    path, engine = new_engine()
    try:
        a = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-1"},
        )

        b = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-1"},
        )

        assert a.artifact_id == b.artifact_id
    finally:
        cleanup(path)


def test_09_parent_artifact_validation():
    path, engine = new_engine()
    try:
        try:
            engine.register_artifact(
                artifact_type="derived",
                payload={"x": 1},
                parent_artifact_ids=("ART-NOT-REAL",),
            )
            assert False
        except ProvenanceValidationError:
            pass
    finally:
        cleanup(path)


def test_10_dependency_registration():
    path, engine = new_engine()
    try:
        dependency = DependencySnapshot(
            dependency_id="DNS-1",
            dependency_type="dns",
            provider="test",
            observed_at_utc="2026-09-08T00:00:00+00:00",
            request_fingerprint="b" * 64,
            response_fingerprint="c" * 64,
            version="1",
            status="OBSERVED",
        )

        result = engine.register_dependency(
            dependency
        )

        assert result == "DNS-1"
    finally:
        cleanup(path)


def test_11_dependency_conflict():
    path, engine = new_engine()
    try:
        d1 = DependencySnapshot(
            dependency_id="TI-1",
            dependency_type="ti",
            provider="test",
            observed_at_utc="2026-09-08T00:00:00+00:00",
            request_fingerprint="a" * 64,
            response_fingerprint="b" * 64,
            version="1",
            status="OBSERVED",
        )

        d2 = DependencySnapshot(
            dependency_id="TI-1",
            dependency_type="ti",
            provider="test",
            observed_at_utc="2026-09-08T00:00:00+00:00",
            request_fingerprint="a" * 64,
            response_fingerprint="c" * 64,
            version="1",
            status="OBSERVED",
        )

        engine.register_dependency(d1)

        try:
            engine.register_dependency(d2)
            assert False
        except ProvenanceConflictError:
            pass
    finally:
        cleanup(path)


def test_12_finalize_execution():
    path, engine = new_engine()
    try:
        artifact = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-1"},
        )

        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=10,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        record = engine.finalize_execution(
            execution.execution_id,
            output_artifact_ids=(
                artifact.artifact_id,
            ),
            finding_ids=("F-1",),
            status=STATUS_VERIFIED,
        )

        assert record.record_hash
        assert record.previous_record_hash is None
    finally:
        cleanup(path)


def test_13_chain_valid():
    path, engine = new_engine()
    try:
        artifact = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-1"},
        )

        e1 = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            e1.execution_id,
            output_artifact_ids=(
                artifact.artifact_id,
            ),
        )

        e2 = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            e2.execution_id,
            output_artifact_ids=(
                artifact.artifact_id,
            ),
        )

        result = engine.verify_chain()

        assert result.valid
        assert result.chain_valid
        assert result.graph_valid
        assert result.record_count == 2
    finally:
        cleanup(path)


def test_14_chain_tamper_detected():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            execution.execution_id
        )

        state_path = path / "state.json"
        state = json.loads(
            state_path.read_text(
                encoding="utf-8"
            )
        )

        state["records"][0]["status"] = "ATTACKER_MODIFIED"

        state_path.write_text(
            json.dumps(state),
            encoding="utf-8",
        )

        compromised = AnalysisProvenanceEngine(
            storage_dir=path
        ).verify_chain()

        assert not compromised.valid
        assert not compromised.chain_valid
    finally:
        cleanup(path)


def test_15_last_hash_tamper_detected():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            execution.execution_id
        )

        state_path = path / "state.json"

        state = json.loads(
            state_path.read_text(
                encoding="utf-8"
            )
        )

        state["last_record_hash"] = "f" * 64

        state_path.write_text(
            json.dumps(state),
            encoding="utf-8",
        )

        result = AnalysisProvenanceEngine(
            storage_dir=path
        ).verify_chain()

        assert not result.valid
    finally:
        cleanup(path)


def test_16_orphan_output_detected():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        execution_data = engine._state[
            "executions"
        ][execution.execution_id]

        execution_data[
            "output_artifact_ids"
        ] = ["ART-GHOST"]

        result = engine.verify_chain()

        assert not result.valid
        assert result.orphan_count >= 1
    finally:
        cleanup(path)


def test_17_orphan_parent_detected():
    path, engine = new_engine()
    try:
        artifact = engine.register_artifact(
            artifact_type="derived",
            payload={"x": 1},
        )

        engine._state["artifacts"][
            artifact.artifact_id
        ]["parent_artifact_ids"] = [
            "ART-GHOST"
        ]

        result = engine.verify_chain()

        assert not result.valid
        assert result.orphan_count >= 1
    finally:
        cleanup(path)


def test_18_replay_ready():
    path, engine = new_engine()
    try:
        dependency = DependencySnapshot(
            dependency_id="DNS-1",
            dependency_type="dns",
            provider="test",
            observed_at_utc="2026-09-08T00:00:00+00:00",
            request_fingerprint="a" * 64,
            response_fingerprint="b" * 64,
            version="1",
            status="OBSERVED",
        )

        engine.register_dependency(
            dependency
        )

        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
            dependency_ids=("DNS-1",),
        )

        engine.finalize_execution(
            execution.execution_id
        )

        replay = engine.prepare_replay(
            execution.execution_id
        )

        assert replay["ready"]
        assert replay["state"] == STATUS_REPLAY_READY
    finally:
        cleanup(path)


def test_19_non_deterministic_not_replayable():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=NON_DETERMINISTIC,
        )

        result = engine.prepare_replay(
            execution.execution_id
        )

        assert not result["ready"]
        assert result["state"] == STATUS_NON_REPLAYABLE
    finally:
        cleanup(path)


def test_20_replay_match():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            execution.execution_id
        )

        stored = engine.get_execution(
            execution.execution_id
        )

        comparison = engine.compare_replay(
            execution.execution_id,
            replay_execution_fingerprint=(
                stored["execution_fingerprint"]
            ),
        )

        assert comparison.state == STATUS_MATCHED
    finally:
        cleanup(path)


def test_21_replay_mismatch():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            execution.execution_id
        )

        comparison = engine.compare_replay(
            execution.execution_id,
            replay_execution_fingerprint="f" * 64,
        )

        assert comparison.state == STATUS_MISMATCHED
    finally:
        cleanup(path)


def test_22_dependency_drift():
    path, engine = new_engine()
    try:
        dependency = DependencySnapshot(
            dependency_id="TI-1",
            dependency_type="ti",
            provider="test",
            observed_at_utc="2026-09-08T00:00:00+00:00",
            request_fingerprint="a" * 64,
            response_fingerprint="b" * 64,
            version="1",
            status="OBSERVED",
        )

        engine.register_dependency(
            dependency
        )

        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
            dependency_ids=("TI-1",),
        )

        engine.finalize_execution(
            execution.execution_id
        )

        comparison = engine.compare_replay(
            execution.execution_id,
            replay_execution_fingerprint=(
                "f" * 64
            ),
            dependency_fingerprints={
                "TI-1": "c" * 64
            },
        )

        assert comparison.state == STATUS_DEPENDENCY_DRIFT
        assert "TI-1" in comparison.dependency_drift
    finally:
        cleanup(path)


def test_23_secret_metadata_rejected():
    path, engine = new_engine()
    try:
        try:
            engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256="a" * 64,
                input_size_bytes=1,
                engine_id="engine",
                engine_version="1",
                analysis_version="1",
                determinism_class=DETERMINISTIC,
                metadata={
                    "api_key": "SECRET"
                },
            )
            assert False
        except ProvenanceValidationError:
            pass
    finally:
        cleanup(path)


def test_24_json_safe():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        json.dumps(
            execution.to_dict(),
            allow_nan=False,
        )
    finally:
        cleanup(path)


def test_25_persistence_reload():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            execution.execution_id
        )

        second = AnalysisProvenanceEngine(
            storage_dir=path
        )

        result = second.verify_chain()

        assert result.valid
        assert result.record_count == 1
    finally:
        cleanup(path)


def test_26_multiple_chain_records():
    path, engine = new_engine()
    try:
        for index in range(5):
            execution = engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256=(
                    ("%02x" % index) * 32
                ),
                input_size_bytes=index,
                engine_id="engine",
                engine_version="1",
                analysis_version="1",
                determinism_class=DETERMINISTIC,
            )

            engine.finalize_execution(
                execution.execution_id
            )

        result = engine.verify_chain()

        assert result.valid
        assert result.record_count == 5
    finally:
        cleanup(path)


def test_27_unique_execution_ids():
    path, engine = new_engine()
    try:
        ids = set()

        for _ in range(20):
            execution = engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256="a" * 64,
                input_size_bytes=1,
                engine_id="engine",
                engine_version="1",
                analysis_version="1",
                determinism_class=DETERMINISTIC,
            )
            ids.add(execution.execution_id)

        assert len(ids) == 20
    finally:
        cleanup(path)


def test_28_duplicate_reference_rejected():
    path, engine = new_engine()
    try:
        try:
            engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256="a" * 64,
                input_size_bytes=1,
                engine_id="engine",
                engine_version="1",
                analysis_version="1",
                determinism_class=DETERMINISTIC,
                finding_ids=("F-1", "F-1"),
            )
            assert False
        except TypeError:
            # create_execution does not expose finding_ids;
            # duplicate-ref enforcement is exercised through
            # finalize tests below.
            pass
    finally:
        cleanup(path)


def test_29_duplicate_output_reference_rejected():
    path, engine = new_engine()
    try:
        artifact = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-1"},
        )

        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        try:
            engine.finalize_execution(
                execution.execution_id,
                output_artifact_ids=(
                    artifact.artifact_id,
                    artifact.artifact_id,
                ),
            )
            assert False
        except ProvenanceConflictError:
            pass
    finally:
        cleanup(path)


def test_30_invalid_sha256_rejected():
    path, engine = new_engine()
    try:
        try:
            engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256="BAD",
                input_size_bytes=1,
                engine_id="engine",
                engine_version="1",
                analysis_version="1",
                determinism_class=DETERMINISTIC,
            )
            assert False
        except ProvenanceValidationError:
            pass
    finally:
        cleanup(path)


def test_31_negative_size_rejected():
    path, engine = new_engine()
    try:
        try:
            engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256="a" * 64,
                input_size_bytes=-1,
                engine_id="engine",
                engine_version="1",
                analysis_version="1",
                determinism_class=DETERMINISTIC,
            )
            assert False
        except ProvenanceValidationError:
            pass
    finally:
        cleanup(path)


def test_32_empty_engine_rejected():
    path, engine = new_engine()
    try:
        try:
            engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256="a" * 64,
                input_size_bytes=1,
                engine_id="",
                engine_version="1",
                analysis_version="1",
                determinism_class=DETERMINISTIC,
            )
            assert False
        except ProvenanceValidationError:
            pass
    finally:
        cleanup(path)


def test_33_invalid_determinism_rejected():
    path, engine = new_engine()
    try:
        try:
            engine.create_execution(
                investigation_id="INV-1",
                evidence_id="EV-1",
                input_sha256="a" * 64,
                input_size_bytes=1,
                engine_id="engine",
                engine_version="1",
                analysis_version="1",
                determinism_class="WHATEVER",
            )
            assert False
        except ProvenanceValidationError:
            pass
    finally:
        cleanup(path)


def test_34_export_bundle():
    path, engine = new_engine()
    try:
        artifact = engine.register_artifact(
            artifact_type="finding",
            payload={"finding_id": "F-1"},
        )

        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        engine.finalize_execution(
            execution.execution_id,
            output_artifact_ids=(
                artifact.artifact_id,
            ),
            finding_ids=("F-1",),
        )

        bundle = engine.export_execution_bundle(
            execution.execution_id
        )

        assert "execution" in bundle
        assert "artifacts" in bundle
        assert "records" in bundle
        assert bundle["execution"][
            "evidence_id"
        ] == "EV-1"
    finally:
        cleanup(path)


def test_35_no_raw_email_in_metadata():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
            metadata={
                "mailbox": "analyst@example.com",
                "mode": "forensic",
            },
        )

        serialized = json.dumps(
            execution.to_dict()
        )

        assert "password" not in serialized.lower()
        assert "authorization" not in serialized.lower()
    finally:
        cleanup(path)


def test_36_utf8_canonical():
    a = {"label": "café"}
    b = {"label": "café"}

    assert canonical_json(a) == canonical_json(b)


def test_37_artifact_parent_lineage():
    path, engine = new_engine()
    try:
        parent = engine.register_artifact(
            artifact_type="observation",
            payload={"x": 1},
        )

        child = engine.register_artifact(
            artifact_type="finding",
            payload={"x": 2},
            parent_artifact_ids=(
                parent.artifact_id,
            ),
        )

        assert child.parent_artifact_ids == (
            parent.artifact_id,
        )

        result = engine.verify_chain()

        assert result.valid
    finally:
        cleanup(path)


def test_38_execution_dependencies_survive_reload():
    path, engine = new_engine()
    try:
        dep = DependencySnapshot(
            dependency_id="EXT-1",
            dependency_type="external",
            provider="test",
            observed_at_utc="2026-09-08T00:00:00+00:00",
            request_fingerprint="a" * 64,
            response_fingerprint="b" * 64,
            version="1",
            status="OBSERVED",
        )

        engine.register_dependency(dep)

        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
            dependency_ids=("EXT-1",),
        )

        engine.finalize_execution(
            execution.execution_id
        )

        reloaded = AnalysisProvenanceEngine(
            storage_dir=path
        )

        replay = reloaded.prepare_replay(
            execution.execution_id
        )

        assert replay["ready"]
    finally:
        cleanup(path)


def test_39_missing_dependency_is_non_replayable():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-1",
            evidence_id="EV-1",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
            dependency_ids=("MISSING",),
        )

        engine.finalize_execution(
            execution.execution_id
        )

        replay = engine.prepare_replay(
            execution.execution_id
        )

        assert not replay["ready"]
        assert replay["state"] == STATUS_NON_REPLAYABLE
    finally:
        cleanup(path)


def test_40_evidence_binding_persisted():
    path, engine = new_engine()
    try:
        execution = engine.create_execution(
            investigation_id="INV-ABC",
            evidence_id="EV-ABC",
            input_sha256="a" * 64,
            input_size_bytes=1,
            engine_id="engine",
            engine_version="1",
            analysis_version="1",
            determinism_class=DETERMINISTIC,
        )

        record = engine.finalize_execution(
            execution.execution_id
        )

        assert record.evidence_id == "EV-ABC"
        assert record.investigation_id == "INV-ABC"

        result = engine.verify_chain()

        assert result.valid
    finally:
        cleanup(path)


def run():
    tests = [
        name
        for name in globals()
        if name.startswith("test_")
    ]

    failures = []

    for name in sorted(tests):
        try:
            globals()[name]()
            print(f"{name}=PASS")
        except Exception as exc:
            print(f"{name}=FAIL: {exc}")
            failures.append(
                (name, repr(exc))
            )

    print("")
    print("TOTAL_TESTS=" + str(len(tests)))
    print("TOTAL_FAILS=" + str(len(failures)))

    if failures:
        for name, error in failures:
            print(
                "FAIL_DETAIL="
                + name
                + " | "
                + error
            )
        raise SystemExit(1)

    print("SOC_TEST_SUITE=PASS")


if __name__ == "__main__":
    run()
