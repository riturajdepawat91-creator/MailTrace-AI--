from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


MODEL_TYPE = "tfidf_logistic_regression"
MODEL_VERSION = "1.0.0"
RANDOM_STATE = 42


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    min_df=1,
                    max_df=0.995,
                    sublinear_tf=True,
                    max_features=60000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=3000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                    solver="lbfgs",
                ),
            ),
        ]
    )


def dataset_sha256(
    rows: list[dict[str, Any]]
) -> str:

    canonical = json.dumps(
        rows,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(
        canonical
    ).hexdigest()


def train_model(
    rows: list[dict[str, Any]],
    output_dir: str | Path,
    dataset_path: str,
) -> Dict[str, Any]:

    texts = [
        row["text"]
        for row in rows
    ]

    labels = [
        row["label"].upper()
        for row in rows
    ]

    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    pipeline = build_pipeline()
    pipeline.fit(
        x_train,
        y_train
    )

    predictions = pipeline.predict(
        x_test
    )

    accuracy = float(
        accuracy_score(
            y_test,
            predictions
        )
    )

    macro_f1 = float(
        f1_score(
            y_test,
            predictions,
            average="macro",
            zero_division=0,
        )
    )

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    output = Path(output_dir)
    output.mkdir(
        parents=True,
        exist_ok=True
    )

    model_path = (
        output
        / "email_classifier.joblib"
    )

    manifest_path = (
        output
        / "manifest.json"
    )

    joblib.dump(
        pipeline,
        model_path
    )

    manifest = {
        "engine": "mailtrace-email-ai",
        "engine_version": "1.0.0",
        "model_type": MODEL_TYPE,
        "model_version": MODEL_VERSION,
        "artifact": model_path.name,
        "dataset_path": str(dataset_path),
        "dataset_sha256": dataset_sha256(rows),
        "training_samples": len(rows),
        "train_samples": len(x_train),
        "test_samples": len(x_test),
        "classes": sorted(set(labels)),
        "metrics": {
            "accuracy": accuracy,
            "macro_f1": macro_f1,
            "classification_report": report,
        },
        "random_state": RANDOM_STATE,
        "calibration_status": "UNCALIBRATED",
        "confidence_type": (
            "uncalibrated_model_probability"
        ),
        "production_ready": False,
        "production_readiness_reason": (
            "Representative reviewed dataset, "
            "calibration and independent validation "
            "are still required."
        ),
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    return {
        "model_path": str(model_path),
        "manifest_path": str(manifest_path),
        "manifest": manifest,
    }