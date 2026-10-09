from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np

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

DATASET = (
    PROJECT_ROOT
    / "data"
    / "email_ai"
    / "normalized"
    / "meajor_phishing_binary.jsonl"
)

MODEL_ROOT = (
    PROJECT_ROOT
    / "models"
    / "email_ai"
)

REPORT_ROOT = (
    PROJECT_ROOT
    / "data"
    / "email_ai"
    / "metadata"
)

SEED = 42


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
    texts: list[str] = []
    labels: list[str] = []

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
            f"Too few usable records: {len(texts)}"
        )

    return texts, labels


def build_pipeline() -> Pipeline:
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
                    max_features=60000,
                    dtype=np.float32,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1500,
                    class_weight="balanced",
                    random_state=SEED,
                    solver="liblinear",
                ),
            ),
        ]
    )


def binary_scores(
    labels,
    predictions,
    probabilities,
):
    y_binary = [
        1 if value == "PHISHING" else 0
        for value in labels
    ]

    return {
        "accuracy": float(
            accuracy_score(
                labels,
                predictions,
            )
        ),
        "precision": float(
            precision_score(
                labels,
                predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "recall": float(
            recall_score(
                labels,
                predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "f1": float(
            f1_score(
                labels,
                predictions,
                pos_label="PHISHING",
                zero_division=0,
            )
        ),
        "roc_auc": float(
            roc_auc_score(
                y_binary,
                probabilities,
            )
        ),
        "pr_auc": float(
            average_precision_score(
                y_binary,
                probabilities,
            )
        ),
        "confusion_matrix": (
            confusion_matrix(
                labels,
                predictions,
                labels=[
                    "LEGITIMATE",
                    "PHISHING",
                ],
            ).tolist()
        ),
        "classification_report": (
            classification_report(
                labels,
                predictions,
                output_dict=True,
                zero_division=0,
            )
        ),
    }


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

    if not DATASET.exists():
        raise RuntimeError(
            f"Dataset not found: {DATASET}"
        )

    dataset_hash = sha256_file(
        DATASET
    )

    print("LOADING_DATASET")

    texts, labels = load_dataset(
        DATASET
    )

    distribution = Counter(labels)

    print(
        "TOTAL_USABLE_ROWS:",
        len(texts),
    )

    print(
        "CLASS_DISTRIBUTION:",
        dict(distribution),
    )

    if set(distribution.keys()) != {
        "LEGITIMATE",
        "PHISHING",
    }:
        raise RuntimeError(
            "Expected exactly LEGITIMATE and PHISHING classes."
        )

    # --------------------------------------------------------
    # 15% untouched final test
    # Remaining 85% -> 88.235% train / 11.765% validation
    # Final result ~= 70 / 15 / 15
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
        random_state=SEED,
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
        random_state=SEED,
        stratify=train_val_labels,
    )

    print(
        "TRAIN_ROWS:",
        len(train_texts),
    )

    print(
        "VALIDATION_ROWS:",
        len(validation_texts),
    )

    print(
        "TEST_ROWS:",
        len(test_texts),
    )

    # --------------------------------------------------------
    # Train exactly ONE base model
    # --------------------------------------------------------

    print("")
    print("TRAINING_BASE_MODEL")

    model = build_pipeline()

    training_started = time.time()

    model.fit(
        train_texts,
        train_labels,
    )

    training_seconds = round(
        time.time() - training_started,
        2,
    )

    print(
        "BASE_MODEL_TRAINING_SECONDS:",
        training_seconds,
    )

    # --------------------------------------------------------
    # Feature-space information
    # --------------------------------------------------------

    vectorizer = model.named_steps["tfidf"]

    feature_count = len(
        vectorizer.get_feature_names_out()
    )

    print(
        "TFIDF_FEATURE_COUNT:",
        feature_count,
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    print("")
    print("EVALUATING_VALIDATION")

    validation_probabilities = (
        model.predict_proba(
            validation_texts
        )[
            :,
            list(
                model.classes_
            ).index("PHISHING"),
        ]
    )

    validation_predictions = [
        "PHISHING"
        if probability >= 0.5
        else "LEGITIMATE"
        for probability in validation_probabilities
    ]

    validation_metrics = binary_scores(
        validation_labels,
        validation_predictions,
        validation_probabilities,
    )

    print(
        "VALIDATION_METRICS:",
        json.dumps(
            validation_metrics,
            indent=2,
        ),
    )

    # --------------------------------------------------------
    # Final untouched test
    # --------------------------------------------------------

    print("")
    print("EVALUATING_FINAL_HOLDOUT_TEST")

    test_probabilities = (
        model.predict_proba(
            test_texts
        )[
            :,
            list(
                model.classes_
            ).index("PHISHING"),
        ]
    )

    test_predictions = [
        "PHISHING"
        if probability >= 0.5
        else "LEGITIMATE"
        for probability in test_probabilities
    ]

    test_metrics = binary_scores(
        test_labels,
        test_predictions,
        test_probabilities,
    )

    print(
        "FINAL_TEST_METRICS:",
        json.dumps(
            test_metrics,
            indent=2,
        ),
    )

    # --------------------------------------------------------
    # Save artifact
    # --------------------------------------------------------

    print("")
    print("SAVING_BASE_MODEL")

    artifact_path = (
        MODEL_ROOT
        / "email_phishing_l3_base.joblib"
    )

    manifest_path = (
        MODEL_ROOT
        / "email_phishing_l3_base_manifest.json"
    )

    report_path = (
        REPORT_ROOT
        / "email_phishing_l3_base_training_report.json"
    )

    joblib.dump(
        model,
        artifact_path,
        compress=3,
    )

    if not artifact_path.exists():
        raise RuntimeError(
            "Model artifact was not created."
        )

    artifact_size = artifact_path.stat().st_size

    if artifact_size <= 0:
        raise RuntimeError(
            "Model artifact is zero bytes."
        )

    artifact_hash = sha256_file(
        artifact_path
    )

    manifest = {
        "engine": "mailtrace-email-ai",
        "model_name": "email-phishing-l3-base",
        "model_type": "tfidf_logistic_regression",
        "model_version": "1.0.0",
        "task": "binary_email_phishing_detection",
        "classes": [
            "LEGITIMATE",
            "PHISHING",
        ],
        "positive_class": "PHISHING",
        "feature_count": feature_count,
        "vectorizer": {
            "ngram_range": [1, 2],
            "min_df": 2,
            "max_df": 0.995,
            "max_features": 60000,
            "dtype": "float32",
        },
        "classifier": {
            "type": "LogisticRegression",
            "solver": "liblinear",
            "class_weight": "balanced",
            "max_iter": 1500,
        },
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
            "seed": SEED,
        },
        "metrics": {
            "validation": validation_metrics,
            "final_holdout_test": test_metrics,
        },
        "artifact": {
            "path": str(artifact_path),
            "bytes": artifact_size,
            "sha256": artifact_hash,
        },
        "calibration": {
            "status": "NOT_CALIBRATED",
            "next_stage": "HOLDOUT_SIGMOID_CALIBRATION",
        },
        "production_ready": False,
        "production_status": (
            "BASELINE_ONLY_REQUIRES_CALIBRATION_"
            "AND_ORGANIZATION_SPECIFIC_VALIDATION"
        ),
        "training_seconds": training_seconds,
        "generated_at_utc": (
            time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            )
        ),
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    report_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # Load saved artifact and perform inference test
    # --------------------------------------------------------

    print("")
    print("VERIFYING_SAVED_ARTIFACT")

    saved_model = joblib.load(
        artifact_path
    )

    sample_email = (
        "URGENT account verification required. "
        "Your mailbox will be suspended today. "
        "Verify your password immediately using "
        "the provided login link."
    )

    probability_vector = (
        saved_model.predict_proba(
            [sample_email]
        )[0]
    )

    saved_classes = list(
        saved_model.classes_
    )

    phishing_index = (
        saved_classes.index(
            "PHISHING"
        )
    )

    phishing_probability = float(
        probability_vector[
            phishing_index
        ]
    )

    prediction = saved_classes[
        int(
            probability_vector.argmax()
        )
    ]

    print(
        "INFERENCE_TEST: PASS"
    )

    print(
        "CLASSES:",
        saved_classes,
    )

    print(
        "PHISHING_PROBABILITY:",
        phishing_probability,
    )

    print(
        "PREDICTION:",
        prediction,
    )

    if not {
        "LEGITIMATE",
        "PHISHING",
    }.issubset(
        set(saved_classes)
    ):
        raise RuntimeError(
            "Saved model classes are invalid."
        )

    print("")
    print(
        "============================================================"
    )
    print(
        "STABLE BASE ML TRAINING: COMPLETE"
    )
    print(
        "============================================================"
    )

    print("")
    print(
        "MODEL:",
        artifact_path,
    )

    print(
        "MANIFEST:",
        manifest_path,
    )

    print(
        "REPORT:",
        report_path,
    )

    print(
        "MODEL_BYTES:",
        artifact_size,
    )

    print(
        "MODEL_SHA256:",
        artifact_hash,
    )

    print(
        "FINAL_ACCURACY:",
        test_metrics["accuracy"],
    )

    print(
        "FINAL_PRECISION:",
        test_metrics["precision"],
    )

    print(
        "FINAL_RECALL:",
        test_metrics["recall"],
    )

    print(
        "FINAL_F1:",
        test_metrics["f1"],
    )

    print(
        "FINAL_ROC_AUC:",
        test_metrics["roc_auc"],
    )

    print(
        "FINAL_PR_AUC:",
        test_metrics["pr_auc"],
    )

    print(
        "PRODUCTION_READY:",
        False,
    )

    print(
        "NEXT_STAGE:",
        "HOLDOUT_SIGMOID_CALIBRATION",
    )


if __name__ == "__main__":
    main()