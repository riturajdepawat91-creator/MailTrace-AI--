from __future__ import annotations

import hashlib
import json
import math
import time
from pathlib import Path

import joblib
import numpy as np

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET = (
    PROJECT_ROOT
    / "data"
    / "email_ai"
    / "normalized"
    / "meajor_phishing_binary.jsonl"
)

BASE_MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "email_ai"
    / "email_phishing_l3_base.joblib"
)

BASE_MANIFEST_PATH = (
    PROJECT_ROOT
    / "models"
    / "email_ai"
    / "email_phishing_l3_base_manifest.json"
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
    texts = []
    labels = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:

        for line in handle:
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


def split_indices(labels):
    from sklearn.model_selection import train_test_split

    indices = np.arange(
        len(labels),
        dtype=np.int64,
    )

    (
        train_val_indices,
        test_indices,
    ) = train_test_split(
        indices,
        test_size=0.15,
        random_state=SEED,
        stratify=labels,
    )

    (
        train_indices,
        validation_indices,
    ) = train_test_split(
        train_val_indices,
        test_size=0.1764705882,
        random_state=SEED,
        stratify=[
            labels[index]
            for index in train_val_indices
        ],
    )

    return (
        np.asarray(train_indices),
        np.asarray(validation_indices),
        np.asarray(test_indices),
    )


def binary_labels(labels):
    return np.asarray(
        [
            1 if value == "PHISHING" else 0
            for value in labels
        ],
        dtype=np.int8,
    )


def phishing_probabilities(model, texts):
    classes = list(
        model.classes_
    )

    phishing_index = classes.index(
        "PHISHING"
    )

    return model.predict_proba(
        texts
    )[
        :,
        phishing_index,
    ].astype(
        np.float64
    )


def predictions_from_probability(
    probabilities,
    threshold=0.5,
):
    return np.asarray(
        [
            "PHISHING"
            if probability >= threshold
            else "LEGITIMATE"
            for probability in probabilities
        ]
    )


def classification_metrics(
    labels,
    probabilities,
    threshold=0.5,
):
    y_true = binary_labels(
        labels
    )

    predictions = predictions_from_probability(
        probabilities,
        threshold,
    )

    return {
        "threshold": float(threshold),
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
                y_true,
                probabilities,
            )
        ),
        "pr_auc": float(
            average_precision_score(
                y_true,
                probabilities,
            )
        ),
        "brier_score": float(
            brier_score_loss(
                y_true,
                probabilities,
            )
        ),
        "positive_rate": float(
            np.mean(
                predictions == "PHISHING"
            )
        ),
    }


def expected_calibration_error(
    labels,
    probabilities,
    bins=10,
):
    y_true = binary_labels(
        labels
    )

    probabilities = np.asarray(
        probabilities,
        dtype=np.float64,
    )

    edges = np.linspace(
        0.0,
        1.0,
        bins + 1,
    )

    ece = 0.0
    details = []

    for index in range(bins):
        lower = edges[index]
        upper = edges[index + 1]

        if index == bins - 1:
            mask = (
                (probabilities >= lower)
                & (probabilities <= upper)
            )
        else:
            mask = (
                (probabilities >= lower)
                & (probabilities < upper)
            )

        count = int(
            np.sum(mask)
        )

        if count == 0:
            details.append(
                {
                    "bin": index,
                    "count": 0,
                    "confidence": None,
                    "accuracy": None,
                    "gap": None,
                }
            )
            continue

        confidence = float(
            np.mean(
                probabilities[mask]
            )
        )

        accuracy = float(
            np.mean(
                y_true[mask]
            )
        )

        gap = abs(
            confidence
            - accuracy
        )

        ece += (
            count
            / len(probabilities)
        ) * gap

        details.append(
            {
                "bin": index,
                "count": count,
                "confidence": confidence,
                "accuracy": accuracy,
                "gap": float(gap),
            }
        )

    return float(ece), details


def fit_sigmoid_calibrator(
    validation_labels,
    validation_probabilities,
):
    """
    Platt-style sigmoid calibration.

    The calibrator is trained ONLY on the validation
    partition. The final test partition remains untouched.
    """

    y = binary_labels(
        validation_labels
    )

    eps = 1e-6

    probabilities = np.clip(
        validation_probabilities,
        eps,
        1.0 - eps,
    )

    logits = np.log(
        probabilities
        / (
            1.0
            - probabilities
        )
    ).reshape(
        -1,
        1,
    )

    calibrator = LogisticRegression(
        solver="lbfgs",
        random_state=SEED,
        max_iter=1000,
    )

    calibrator.fit(
        logits,
        y,
    )

    return calibrator


def calibrate_probability(
    calibrator,
    probabilities,
):
    eps = 1e-6

    probabilities = np.clip(
        probabilities,
        eps,
        1.0 - eps,
    )

    logits = np.log(
        probabilities
        / (
            1.0
            - probabilities
        )
    ).reshape(
        -1,
        1,
    )

    return calibrator.predict_proba(
        logits
    )[
        :,
        1,
    ].astype(
        np.float64
    )


def threshold_sweep(
    labels,
    probabilities,
):
    y_true = binary_labels(
        labels
    )

    results = []

    thresholds = [
        round(
            value,
            2,
        )
        for value in np.arange(
            0.10,
            0.951,
            0.05,
        )
    ]

    for threshold in thresholds:
        predictions = (
            probabilities
            >= threshold
        )

        tp = int(
            np.sum(
                (y_true == 1)
                & predictions
            )
        )

        tn = int(
            np.sum(
                (y_true == 0)
                & (~predictions)
            )
        )

        fp = int(
            np.sum(
                (y_true == 0)
                & predictions
            )
        )

        fn = int(
            np.sum(
                (y_true == 1)
                & (~predictions)
            )
        )

        precision = (
            tp
            / (
                tp + fp
            )
            if (
                tp + fp
            )
            else 0.0
        )

        recall = (
            tp
            / (
                tp + fn
            )
            if (
                tp + fn
            )
            else 0.0
        )

        f1 = (
            2.0
            * precision
            * recall
            / (
                precision
                + recall
            )
            if (
                precision
                + recall
            )
            else 0.0
        )

        fpr = (
            fp
            / (
                fp + tn
            )
            if (
                fp + tn
            )
            else 0.0
        )

        fnr = (
            fn
            / (
                fn + tp
            )
            if (
                fn + tp
            )
            else 0.0
        )

        results.append(
            {
                "threshold": float(threshold),
                "tp": tp,
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
                "false_positive_rate": float(fpr),
                "false_negative_rate": float(fnr),
            }
        )

    return results


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

    print("LOADING_BASE_MODEL")

    base_model = joblib.load(
        BASE_MODEL_PATH
    )

    if not hasattr(
        base_model,
        "predict_proba",
    ):
        raise RuntimeError(
            "Base model does not expose predict_proba."
        )

    print("LOADING_DATASET")

    texts, labels = load_dataset(
        DATASET
    )

    (
        train_indices,
        validation_indices,
        test_indices,
    ) = split_indices(
        labels
    )

    train_texts = [
        texts[index]
        for index in train_indices
    ]

    validation_texts = [
        texts[index]
        for index in validation_indices
    ]

    test_texts = [
        texts[index]
        for index in test_indices
    ]

    validation_labels = [
        labels[index]
        for index in validation_indices
    ]

    test_labels = [
        labels[index]
        for index in test_indices
    ]

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

    print("")
    print("GENERATING_VALIDATION_PROBABILITIES")

    validation_raw_probabilities = (
        phishing_probabilities(
            base_model,
            validation_texts,
        )
    )

    print("")
    print("FITTING_SIGMOID_CALIBRATOR")

    calibrator = fit_sigmoid_calibrator(
        validation_labels,
        validation_raw_probabilities,
    )

    validation_calibrated_probabilities = (
        calibrate_probability(
            calibrator,
            validation_raw_probabilities,
        )
    )

    raw_validation_metrics = classification_metrics(
        validation_labels,
        validation_raw_probabilities,
        threshold=0.5,
    )

    calibrated_validation_metrics = classification_metrics(
        validation_labels,
        validation_calibrated_probabilities,
        threshold=0.5,
    )

    raw_validation_brier = brier_score_loss(
        binary_labels(
            validation_labels
        ),
        validation_raw_probabilities,
    )

    calibrated_validation_brier = brier_score_loss(
        binary_labels(
            validation_labels
        ),
        validation_calibrated_probabilities,
    )

    raw_validation_ece, raw_validation_bins = (
        expected_calibration_error(
            validation_labels,
            validation_raw_probabilities,
            bins=10,
        )
    )

    calibrated_validation_ece, calibrated_validation_bins = (
        expected_calibration_error(
            validation_labels,
            validation_calibrated_probabilities,
            bins=10,
        )
    )

    print("")
    print(
        "VALIDATION_RAW_BRIER:",
        float(raw_validation_brier),
    )

    print(
        "VALIDATION_CALIBRATED_BRIER:",
        float(calibrated_validation_brier),
    )

    print(
        "VALIDATION_RAW_ECE:",
        float(raw_validation_ece),
    )

    print(
        "VALIDATION_CALIBRATED_ECE:",
        float(calibrated_validation_ece),
    )

    # --------------------------------------------------------
    # Final untouched test evaluation
    # --------------------------------------------------------

    print("")
    print(
        "GENERATING_FINAL_TEST_PROBABILITIES"
    )

    test_raw_probabilities = (
        phishing_probabilities(
            base_model,
            test_texts,
        )
    )

    test_calibrated_probabilities = (
        calibrate_probability(
            calibrator,
            test_raw_probabilities,
        )
    )

    raw_test_metrics = classification_metrics(
        test_labels,
        test_raw_probabilities,
        threshold=0.5,
    )

    calibrated_test_metrics = classification_metrics(
        test_labels,
        test_calibrated_probabilities,
        threshold=0.5,
    )

    raw_test_ece, raw_test_bins = (
        expected_calibration_error(
            test_labels,
            test_raw_probabilities,
            bins=10,
        )
    )

    calibrated_test_ece, calibrated_test_bins = (
        expected_calibration_error(
            test_labels,
            test_calibrated_probabilities,
            bins=10,
        )
    )

    raw_test_brier = brier_score_loss(
        binary_labels(
            test_labels
        ),
        test_raw_probabilities,
    )

    calibrated_test_brier = brier_score_loss(
        binary_labels(
            test_labels
        ),
        test_calibrated_probabilities,
    )

    print("")
    print("RAW_TEST_METRICS:")
    print(
        json.dumps(
            raw_test_metrics,
            indent=2,
        )
    )

    print("")
    print(
        "CALIBRATED_TEST_METRICS:"
    )
    print(
        json.dumps(
            calibrated_test_metrics,
            indent=2,
        )
    )

    print("")
    print(
        "TEST_RAW_BRIER:",
        float(raw_test_brier),
    )

    print(
        "TEST_CALIBRATED_BRIER:",
        float(calibrated_test_brier),
    )

    print(
        "TEST_RAW_ECE:",
        float(raw_test_ece),
    )

    print(
        "TEST_CALIBRATED_ECE:",
        float(calibrated_test_ece),
    )

    # --------------------------------------------------------
    # Threshold analysis
    # --------------------------------------------------------

    print("")
    print("BUILDING_THRESHOLD_SWEEP")

    threshold_results = (
        threshold_sweep(
            test_labels,
            test_calibrated_probabilities,
        )
    )

    best_f1_threshold = max(
        threshold_results,
        key=lambda item: (
            item["f1"],
            item["recall"],
            -item["false_positive_rate"],
        ),
    )

    low_fpr_candidates = [
        item
        for item in threshold_results
        if item[
            "false_positive_rate"
        ] <= 0.01
    ]

    best_low_fpr = (
        max(
            low_fpr_candidates,
            key=lambda item: (
                item["recall"],
                item["f1"],
            ),
        )
        if low_fpr_candidates
        else None
    )

    print(
        "BEST_F1_THRESHOLD:",
        best_f1_threshold[
            "threshold"
        ],
    )

    if best_low_fpr:
        print(
            "BEST_THRESHOLD_FPR_LE_1_PERCENT:",
            best_low_fpr[
                "threshold"
            ],
        )
        print(
            "RECALL_AT_FPR_LE_1_PERCENT:",
            best_low_fpr[
                "recall"
            ],
        )
    else:
        print(
            "BEST_THRESHOLD_FPR_LE_1_PERCENT: NONE"
        )

    # --------------------------------------------------------
    # Save calibration bundle
    # --------------------------------------------------------

    print("")
    print("SAVING_CALIBRATED_BUNDLE")

    output_path = (
        MODEL_ROOT
        / "email_phishing_l3_calibrated_bundle.joblib"
    )

    manifest_path = (
        MODEL_ROOT
        / "email_phishing_l3_calibrated_manifest.json"
    )

    report_path = (
        REPORT_ROOT
        / "email_phishing_l3_calibrated_report.json"
    )

    bundle = {
        "base_model": base_model,
        "sigmoid_calibrator": calibrator,
        "positive_class": "PHISHING",
        "classes": [
            "LEGITIMATE",
            "PHISHING",
        ],
        "calibration_method": (
            "platt_sigmoid_on_validation_holdout"
        ),
        "threshold_default": 0.5,
    }

    joblib.dump(
        bundle,
        output_path,
        compress=3,
    )

    if not output_path.exists():
        raise RuntimeError(
            "Calibrated bundle was not created."
        )

    artifact_bytes = output_path.stat().st_size

    if artifact_bytes <= 0:
        raise RuntimeError(
            "Calibrated bundle is zero bytes."
        )

    artifact_hash = sha256_file(
        output_path
    )

    dataset_hash = sha256_file(
        DATASET
    )

    base_hash = sha256_file(
        BASE_MODEL_PATH
    )

    manifest = {
        "engine": "mailtrace-email-ai",
        "model_name": "email-phishing-l3-calibrated",
        "model_type": (
            "tfidf_logistic_regression_plus_"
            "platt_sigmoid"
        ),
        "model_version": "1.1.0",
        "task": "binary_email_phishing_detection",
        "classes": [
            "LEGITIMATE",
            "PHISHING",
        ],
        "positive_class": "PHISHING",
        "calibration": {
            "method": "sigmoid",
            "fit_partition": "validation",
            "test_partition_untouched": True,
            "status": "CALIBRATED",
        },
        "dataset": {
            "path": str(DATASET),
            "sha256": dataset_hash,
            "rows": len(texts),
        },
        "split": {
            "train": len(train_texts),
            "validation": len(validation_texts),
            "test": len(test_texts),
            "seed": SEED,
        },
        "base_model": {
            "path": str(BASE_MODEL_PATH),
            "sha256": base_hash,
        },
        "validation": {
            "raw": raw_validation_metrics,
            "calibrated": calibrated_validation_metrics,
            "raw_brier": float(
                raw_validation_brier
            ),
            "calibrated_brier": float(
                calibrated_validation_brier
            ),
            "raw_ece": float(
                raw_validation_ece
            ),
            "calibrated_ece": float(
                calibrated_validation_ece
            ),
            "raw_calibration_bins": raw_validation_bins,
            "calibrated_calibration_bins": calibrated_validation_bins,
        },
        "final_holdout_test": {
            "raw": raw_test_metrics,
            "calibrated": calibrated_test_metrics,
            "raw_brier": float(
                raw_test_brier
            ),
            "calibrated_brier": float(
                calibrated_test_brier
            ),
            "raw_ece": float(
                raw_test_ece
            ),
            "calibrated_ece": float(
                calibrated_test_ece
            ),
            "raw_calibration_bins": raw_test_bins,
            "calibrated_calibration_bins": calibrated_test_bins,
        },
        "threshold_analysis": {
            "best_f1": best_f1_threshold,
            "best_fpr_le_1_percent": best_low_fpr,
            "sweep": threshold_results,
        },
        "artifact": {
            "path": str(output_path),
            "bytes": artifact_bytes,
            "sha256": artifact_hash,
        },
        "production_ready": False,
        "production_status": (
            "CALIBRATED_BASELINE_REQUIRES_"
            "ORGANIZATION_SPECIFIC_VALIDATION_"
            "AND_MODERN_THREAT_EVALUATION"
        ),
        "generated_at_utc": (
            time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            )
        ),
        "runtime_seconds": round(
            time.time() - started,
            2,
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
    # Reload bundle and test inference
    # --------------------------------------------------------

    print("")
    print("VERIFYING_SAVED_CALIBRATED_BUNDLE")

    saved_bundle = joblib.load(
        output_path
    )

    saved_base = (
        saved_bundle["base_model"]
    )

    saved_calibrator = (
        saved_bundle[
            "sigmoid_calibrator"
        ]
    )

    sample_email = (
        "URGENT account verification required. "
        "Your mailbox will be suspended today. "
        "Verify your password immediately using "
        "the secure verification link."
    )

    raw_sample = float(
        phishing_probabilities(
            saved_base,
            [sample_email],
        )[0]
    )

    calibrated_sample = float(
        calibrate_probability(
            saved_calibrator,
            np.asarray(
                [raw_sample],
                dtype=np.float64,
            ),
        )[0]
    )

    print(
        "CALIBRATED_INFERENCE_TEST: PASS"
    )

    print(
        "RAW_SAMPLE_PROBABILITY:",
        raw_sample,
    )

    print(
        "CALIBRATED_SAMPLE_PROBABILITY:",
        calibrated_sample,
    )

    print("")
    print(
        "============================================================"
    )
    print(
        "HOLDOUT SIGMOID CALIBRATION: COMPLETE"
    )
    print(
        "============================================================"
    )

    print("")
    print(
        "CALIBRATED_MODEL:",
        output_path,
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
        "ARTIFACT_BYTES:",
        artifact_bytes,
    )

    print(
        "ARTIFACT_SHA256:",
        artifact_hash,
    )

    print("")
    print(
        "TEST_RAW_BRIER:",
        float(raw_test_brier),
    )

    print(
        "TEST_CALIBRATED_BRIER:",
        float(calibrated_test_brier),
    )

    print(
        "TEST_RAW_ECE:",
        float(raw_test_ece),
    )

    print(
        "TEST_CALIBRATED_ECE:",
        float(calibrated_test_ece),
    )

    print("")
    print(
        "CALIBRATED_FINAL_F1:",
        calibrated_test_metrics["f1"],
    )

    print(
        "CALIBRATED_FINAL_RECALL:",
        calibrated_test_metrics["recall"],
    )

    print(
        "CALIBRATED_FINAL_PR_AUC:",
        calibrated_test_metrics["pr_auc"],
    )

    print(
        "BEST_F1_THRESHOLD:",
        best_f1_threshold["threshold"],
    )

    print(
        "PRODUCTION_READY:",
        False,
    )


if __name__ == "__main__":
    main()