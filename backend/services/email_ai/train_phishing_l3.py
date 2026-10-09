from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

import joblib

from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET = PROJECT_ROOT / "data" / "email_ai" / "normalized" / "meajor_phishing_binary.jsonl"

MODEL_ROOT = PROJECT_ROOT / "models" / "email_ai"
REPORT_ROOT = PROJECT_ROOT / "data" / "email_ai" / "metadata"

RAW_SPLIT_SEED = 42


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def load_dataset(path: Path):
    texts = []
    labels = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line_number, line in enumerate(
            handle,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            row = json.loads(line)

            text = str(
                row.get("text", "")
            ).strip()

            label = str(
                row.get("label", "")
            ).strip().upper()

            if not text:
                continue

            if label not in {
                "LEGITIMATE",
                "PHISHING",
            }:
                continue

            texts.append(text)
            labels.append(label)

    if len(texts) < 10000:
        raise RuntimeError(
            f"Too few training records: {len(texts)}"
        )

    return texts, labels


def build_uncalibrated_pipeline():
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                    min_df=2,
                    max_df=0.995,
                    max_features=100000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2500,
                    class_weight="balanced",
                    random_state=RAW_SPLIT_SEED,
                    solver="liblinear",
                ),
            ),
        ]
    )


def main():

    started = time.time()

    MODEL_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("LOADING_DATASET")

    texts, labels = load_dataset(
        DATASET
    )

    print(
        "TOTAL_USABLE_ROWS:",
        len(texts)
    )

    distribution = Counter(labels)

    print(
        "CLASS_DISTRIBUTION:",
        dict(distribution)
    )

    # --------------------------------------------------------
    # Final untouched test set = 15%
    # Remaining 85% split into train/validation
    # --------------------------------------------------------
    (
        train_val_texts,
        test_texts,
        train_val_labels,
        test_labels,
    ) = train_test_split(
        texts,
        labels,
        test_size=0.15,
        random_state=RAW_SPLIT_SEED,
        stratify=labels,
    )

    (
        train_texts,
        validation_texts,
        train_labels,
        validation_labels,
    ) = train_test_split(
        train_val_texts,
        train_val_labels,
        test_size=0.1764705882,
        random_state=RAW_SPLIT_SEED,
        stratify=train_val_labels,
    )

    print(
        "TRAIN_ROWS:",
        len(train_texts)
    )

    print(
        "VALIDATION_ROWS:",
        len(validation_texts)
    )

    print(
        "TEST_ROWS:",
        len(test_texts)
    )

    # --------------------------------------------------------
    # Stage A: train base model
    # --------------------------------------------------------
    print("TRAINING_BASE_MODEL")

    base = build_uncalibrated_pipeline()

    base.fit(
        train_texts,
        train_labels,
    )

    validation_predictions = base.predict(
        validation_texts
    )

    validation_probabilities = (
        base.predict_proba(
            validation_texts
        )[:, list(base.classes_).index("PHISHING")]
    )

    validation_metrics = {
        "accuracy": float(
            accuracy_score(
                validation_labels,
                validation_predictions,
            )
        ),
        "precision": float(
            precision_score(
                validation_labels,
                validation_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                validation_labels,
                validation_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                validation_labels,
                validation_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                [
                    1 if x == "PHISHING" else 0
                    for x in validation_labels
                ],
                validation_probabilities,
            )
        ),
        "pr_auc": float(
            average_precision_score(
                [
                    1 if x == "PHISHING" else 0
                    for x in validation_labels
                ],
                validation_probabilities,
            )
        ),
    }

    print(
        "VALIDATION_METRICS:",
        json.dumps(
            validation_metrics,
            indent=2,
        )
    )

    # --------------------------------------------------------
    # Stage B: calibration
    # --------------------------------------------------------
    #
    # CalibratedClassifierCV is trained against the training
    # partition. Validation and test remain separate.
    # --------------------------------------------------------
    print("TRAINING_CALIBRATED_MODEL")

    calibrated = CalibratedClassifierCV(
        base,
        method="sigmoid",
        cv=3,
    )

    calibrated.fit(
        train_texts,
        train_labels,
    )

    # --------------------------------------------------------
    # Validation after calibration
    # --------------------------------------------------------
    validation_calibrated_probabilities = (
        calibrated.predict_proba(
            validation_texts
        )[
            :,
            list(calibrated.classes_).index(
                "PHISHING"
            ),
        ]
    )

    validation_calibrated_predictions = (
        [
            "PHISHING"
            if probability >= 0.5
            else "LEGITIMATE"
            for probability in (
                validation_calibrated_probabilities
            )
        ]
    )

    validation_calibrated_metrics = {
        "accuracy": float(
            accuracy_score(
                validation_labels,
                validation_calibrated_predictions,
            )
        ),
        "precision": float(
            precision_score(
                validation_labels,
                validation_calibrated_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                validation_labels,
                validation_calibrated_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                validation_labels,
                validation_calibrated_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                [
                    1 if x == "PHISHING" else 0
                    for x in validation_labels
                ],
                validation_calibrated_probabilities,
            )
        ),
        "pr_auc": float(
            average_precision_score(
                [
                    1 if x == "PHISHING" else 0
                    for x in validation_labels
                ],
                validation_calibrated_probabilities,
            )
        ),
    }

    print(
        "VALIDATION_CALIBRATED_METRICS:",
        json.dumps(
            validation_calibrated_metrics,
            indent=2,
        )
    )

    # --------------------------------------------------------
    # Final holdout test
    # --------------------------------------------------------
    print(
        "EVALUATING_FINAL_HOLDOUT_TEST"
    )

    test_probabilities = (
        calibrated.predict_proba(
            test_texts
        )[
            :,
            list(calibrated.classes_).index(
                "PHISHING"
            ),
        ]
    )

    test_predictions = (
        [
            "PHISHING"
            if probability >= 0.5
            else "LEGITIMATE"
            for probability in test_probabilities
        ]
    )

    y_test_binary = [
        1 if label == "PHISHING" else 0
        for label in test_labels
    ]

    test_metrics = {
        "accuracy": float(
            accuracy_score(
                test_labels,
                test_predictions,
            )
        ),
        "precision": float(
            precision_score(
                test_labels,
                test_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                test_labels,
                test_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                test_labels,
                test_predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                y_test_binary,
                test_probabilities,
            )
        ),
        "pr_auc": float(
            average_precision_score(
                y_test_binary,
                test_probabilities,
            )
        ),
        "confusion_matrix": (
            confusion_matrix(
                test_labels,
                test_predictions,
                labels=[
                    "LEGITIMATE",
                    "PHISHING",
                ],
            ).tolist()
        ),
        "classification_report": (
            classification_report(
                test_labels,
                test_predictions,
                output_dict=True,
                zero_division=0,
            )
        ),
    }

    print(
        "FINAL_TEST_METRICS:",
        json.dumps(
            test_metrics,
            indent=2,
        )
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------
    print("SAVING_MODEL")

    artifact_path = (
        MODEL_ROOT
        / "email_phishing_l3_calibrated.joblib"
    )

    manifest_path = (
        MODEL_ROOT
        / "manifest.json"
    )

    report_path = (
        REPORT_ROOT
        / "email_phishing_l3_training_report.json"
    )

    joblib.dump(
        calibrated,
        artifact_path,
    )

    dataset_hash = sha256_file(
        DATASET
    )

    model_manifest = {
        "engine": "mailtrace-email-ai",
        "model_name": "email-phishing-l3",
        "model_type": (
            "tfidf_logistic_regression_calibrated"
        ),
        "model_version": "1.1.0",
        "task": "binary_email_phishing_detection",
        "classes": [
            "LEGITIMATE",
            "PHISHING",
        ],
        "positive_class": "PHISHING",
        "dataset": {
            "path": str(DATASET),
            "sha256": dataset_hash,
            "usable_rows": len(texts),
            "distribution": dict(distribution),
        },
        "split": {
            "train": len(train_texts),
            "validation": len(validation_texts),
            "test": len(test_texts),
            "seed": RAW_SPLIT_SEED,
        },
        "calibration": {
            "method": "sigmoid",
            "status": "VALIDATED_ON_HOLDOUT",
        },
        "metrics": {
            "validation_base": validation_metrics,
            "validation_calibrated": (
                validation_calibrated_metrics
            ),
            "final_holdout_test": test_metrics,
        },
        "production_ready": False,
        "production_status": (
            "REQUIRES_ORGANIZATION_SPECIFIC_VALIDATION"
        ),
        "training_seconds": round(
            time.time() - started,
            2,
        ),
    }

    manifest_path.write_text(
        json.dumps(
            model_manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    report_path.write_text(
        json.dumps(
            model_manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print("")
    print("TRAINING_COMPLETE")
    print(
        "MODEL:",
        artifact_path
    )
    print(
        "MANIFEST:",
        manifest_path
    )
    print(
        "REPORT:",
        report_path
    )
    print(
        "FINAL_F1:",
        test_metrics["f1"]
    )
    print(
        "FINAL_RECALL:",
        test_metrics["recall"]
    )
    print(
        "FINAL_PR_AUC:",
        test_metrics["pr_auc"]
    )
    print(
        "PRODUCTION_READY:",
        False
    )


if __name__ == "__main__":
    main()