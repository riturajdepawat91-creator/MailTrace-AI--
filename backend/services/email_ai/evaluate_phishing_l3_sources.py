"""Evaluate phishing detection across held-out dataset sources.

The existing random row split measures in-source performance. This evaluator
holds out each source corpus in turn so reports expose cross-source domain
shift. It writes metrics only and never replaces a production model artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .train_phishing_l3 import DATASET, build_uncalibrated_pipeline


def _load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSONL at line {line_number}.") from error
            if not isinstance(row, dict):
                raise ValueError(f"JSONL line {line_number} must be an object.")
            text = str(row.get("text") or "").strip()
            label = str(row.get("label") or "").strip().upper()
            source = str(row.get("source") or "").strip()
            if text and label in {"LEGITIMATE", "PHISHING"} and source:
                rows.append({"text": text, "label": label, "source": source})
    if not rows:
        raise ValueError("No labeled rows with source metadata were found.")
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate_source_holdouts(
    rows: list[dict[str, Any]],
    dataset_sha256: str,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    available_sources = sorted({row["source"] for row in rows})
    selected_sources = sources or available_sources
    unknown_sources = sorted(set(selected_sources) - set(available_sources))
    if unknown_sources:
        raise ValueError(f"Unknown source(s): {', '.join(unknown_sources)}")

    folds = []
    for held_out_source in selected_sources:
        train_rows = [row for row in rows if row["source"] != held_out_source]
        test_rows = [row for row in rows if row["source"] == held_out_source]
        train_labels = [row["label"] for row in train_rows]
        test_labels = [row["label"] for row in test_rows]
        train_classes = set(train_labels)
        test_classes = set(test_labels)
        if train_classes != {"LEGITIMATE", "PHISHING"}:
            raise ValueError(f"Training data lacks both classes when holding out {held_out_source}.")
        if test_classes != {"LEGITIMATE", "PHISHING"}:
            raise ValueError(f"Held-out source {held_out_source} lacks both classes.")

        model = build_uncalibrated_pipeline()
        model.fit([row["text"] for row in train_rows], train_labels)
        phishing_index = list(model.classes_).index("PHISHING")
        probabilities = model.predict_proba([row["text"] for row in test_rows])[:, phishing_index]
        predictions = ["PHISHING" if score >= 0.5 else "LEGITIMATE" for score in probabilities]
        tn, fp, fn, tp = confusion_matrix(
            test_labels,
            predictions,
            labels=["LEGITIMATE", "PHISHING"],
        ).ravel()
        test_counts = Counter(test_labels)
        train_counts = Counter(train_labels)

        folds.append({
            "held_out_source": held_out_source,
            "training_sources": [source for source in available_sources if source != held_out_source],
            "train_rows": len(train_rows),
            "test_rows": len(test_rows),
            "train_class_counts": dict(sorted(train_counts.items())),
            "test_class_counts": dict(sorted(test_counts.items())),
            "threshold": 0.5,
            "metrics": {
                "accuracy": float(accuracy_score(test_labels, predictions)),
                "precision": float(precision_score(test_labels, predictions, pos_label="PHISHING", zero_division=0)),
                "recall": float(recall_score(test_labels, predictions, pos_label="PHISHING", zero_division=0)),
                "f1": float(f1_score(test_labels, predictions, pos_label="PHISHING", zero_division=0)),
                "roc_auc": float(roc_auc_score([label == "PHISHING" for label in test_labels], probabilities)),
                "pr_auc": float(average_precision_score([label == "PHISHING" for label in test_labels], probabilities)),
                "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
                "specificity": float(tn / (tn + fp)) if tn + fp else 0.0,
                "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            },
        })

    return {
        "evaluation": "leave_one_source_out",
        "model": "email-phishing-l3 uncalibrated pipeline",
        "threshold_selection": "fixed at 0.5; held-out labels were not used to tune threshold",
        "dataset": {"path": str(DATASET), "sha256": dataset_sha256, "rows": len(rows)},
        "available_sources": available_sources,
        "folds": folds,
        "production_ready": False,
        "limitations": [
            "This public-corpus evaluation is not organization-specific validation.",
            "The source holdout is not a temporal holdout and may not represent modern phishing.",
            "Calibration and operational alert thresholds require a separate untouched validation set.",
        ],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument(
        "--source",
        action="append",
        dest="sources",
        help="Hold out only this source. Repeat the option for multiple folds; default evaluates every source.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON output path. No model artifact is written.",
    )
    args = parser.parse_args()

    started = time.perf_counter()
    rows = _load_rows(args.dataset)
    report = evaluate_source_holdouts(rows, _sha256(args.dataset), args.sources)
    report["runtime_seconds"] = round(time.perf_counter() - started, 2)
    serialized = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
