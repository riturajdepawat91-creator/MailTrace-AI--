from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import joblib

from .contracts import empty_ai_result
from .explainability import explain_prediction
from .features import (
    build_email_text,
    build_feature_evidence,
)


DEFAULT_MODEL_DIR = Path("models/email_ai")

# New calibrated artifact.
CALIBRATED_ARTIFACT_NAME = "email_phishing_l3_calibrated_bundle.joblib"
CALIBRATED_MANIFEST_NAME = "email_phishing_l3_calibrated_manifest.json"

# Backward-compatible legacy artifact names.
LEGACY_ARTIFACT_NAME = "email_classifier.joblib"
LEGACY_MANIFEST_NAME = "manifest.json"


def _load_manifest(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8-sig",
            )
        )
    except Exception:
        return {}


def _is_calibrated_bundle(model: Any) -> bool:
    return (
        isinstance(model, dict)
        and "base_model" in model
        and "sigmoid_calibrator" in model
    )


def _resolve_model_artifact(model_dir: Path) -> Tuple[Path, Path, str]:
    """
    Resolve the preferred calibrated artifact first while preserving
    compatibility with the previous legacy model artifact.
    """

    calibrated_artifact = model_dir / CALIBRATED_ARTIFACT_NAME
    calibrated_manifest = model_dir / CALIBRATED_MANIFEST_NAME

    if calibrated_artifact.exists():
        return (
            calibrated_artifact,
            calibrated_manifest,
            "CALIBRATED_BUNDLE",
        )

    legacy_artifact = model_dir / LEGACY_ARTIFACT_NAME
    legacy_manifest = model_dir / LEGACY_MANIFEST_NAME

    if legacy_artifact.exists():
        return (
            legacy_artifact,
            legacy_manifest,
            "LEGACY_PIPELINE",
        )

    raise FileNotFoundError(
        "No supported email AI model artifact found."
    )


def load_model(
    model_dir: str | Path = DEFAULT_MODEL_DIR,
) -> Tuple[Optional[Any], Dict[str, Any]]:
    model_dir_path = Path(model_dir)

    try:
        artifact_path, manifest_path, artifact_kind = (
            _resolve_model_artifact(model_dir_path)
        )
    except FileNotFoundError:
        return (
            None,
            empty_ai_result("MODEL_ARTIFACT_MISSING"),
        )

    try:
        model = joblib.load(
            artifact_path,
        )
    except Exception as exc:
        return (
            None,
            empty_ai_result(
                f"MODEL_LOAD_FAILED:{type(exc).__name__}"
            ),
        )

    manifest = _load_manifest(
        manifest_path,
    )

    # Runtime metadata is kept alongside the manifest contract.
    manifest = dict(manifest)
    manifest["_artifact_path"] = str(
        artifact_path
    )
    manifest["_manifest_path"] = str(
        manifest_path
    )
    manifest["_artifact_kind"] = artifact_kind

    # Helpful fallback metadata if the artifact itself contains the
    # authoritative bundle contract.
    if _is_calibrated_bundle(model):
        manifest.setdefault(
            "model_type",
            "tfidf_logistic_regression_plus_platt_sigmoid",
        )
        manifest.setdefault(
            "model_version",
            "1.1.0",
        )
        manifest.setdefault(
            "positive_class",
            model.get(
                "positive_class",
                "PHISHING",
            ),
        )
        manifest.setdefault(
            "calibration_status",
            "CALIBRATED",
        )
        manifest.setdefault(
            "calibration_method",
            model.get(
                "calibration_method",
                "sigmoid",
            ),
        )
    else:
        manifest.setdefault(
            "calibration_status",
            "NOT_CALIBRATED",
        )

    return (
        model,
        manifest,
    )


def _class_probability(
    model: Any,
    text: str,
    positive_class: str = "PHISHING",
) -> Tuple[str, float, Dict[str, float]]:
    """
    Return predicted label, positive-class probability and the full
    probability mapping.

    Supports both:
      1. calibrated bundle
      2. legacy sklearn Pipeline
    """

    # --------------------------------------------------------
    # Calibrated bundle
    # --------------------------------------------------------

    if _is_calibrated_bundle(model):
        base_model = model["base_model"]
        calibrator = model["sigmoid_calibrator"]

        base_probabilities = base_model.predict_proba(
            [text]
        )[0]

        base_classes = list(
            getattr(
                base_model,
                "classes_",
                model.get(
                    "classes",
                    ["LEGITIMATE", "PHISHING"],
                ),
            )
        )

        base_mapping: Dict[str, float] = {}

        for index, label in enumerate(base_classes):
            base_mapping[
                str(label)
            ] = float(
                base_probabilities[index]
            )

        positive_class = str(
            model.get(
                "positive_class",
                positive_class,
            )
        )

        raw_positive_probability = float(
            base_mapping.get(
                positive_class,
                0.0,
            )
        )

        # The calibration trainer stores a sigmoid LogisticRegression
        # that receives the base model's positive-class probability as
        # its single input feature.
        calibrated_probability = float(
            calibrator.predict_proba(
                [[raw_positive_probability]]
            )[0][1]
        )

        calibrated_probability = max(
            0.0,
            min(
                1.0,
                calibrated_probability,
            ),
        )

        threshold = float(
            model.get(
                "threshold_default",
                0.5,
            )
        )

        predicted_label = (
            positive_class
            if calibrated_probability >= threshold
            else next(
                (
                    label
                    for label in base_classes
                    if str(label) != positive_class
                ),
                "LEGITIMATE",
            )
        )

        probability_mapping = dict(
            base_mapping
        )

        probability_mapping[
            f"{positive_class}_CALIBRATED"
        ] = calibrated_probability

        probability_mapping[
            f"{positive_class}_RAW"
        ] = raw_positive_probability

        return (
            str(predicted_label),
            calibrated_probability,
            probability_mapping,
        )

    # --------------------------------------------------------
    # Legacy Pipeline
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        [text]
    )[0]

    classes = list(
        getattr(
            model,
            "classes_",
            [],
        )
    )

    if not classes:
        raise RuntimeError(
            "MODEL_CLASSES_UNAVAILABLE"
        )

    probability_mapping = {}

    for index, label in enumerate(classes):
        probability_mapping[
            str(label)
        ] = float(
            probabilities[index]
        )

    predicted_index = int(
        model.predict(
            [text]
        )[0] in classes
    )

    # Prefer the highest probability rather than relying on fragile
    # class ordering assumptions.
    highest_index = max(
        range(
            len(probabilities)
        ),
        key=lambda index: probabilities[index],
    )

    predicted_label = str(
        classes[highest_index]
    )

    positive_probability = float(
        probability_mapping.get(
            positive_class,
            probabilities[highest_index],
        )
    )

    return (
        predicted_label,
        positive_probability,
        probability_mapping,
    )


def predict_email(
    email: Dict[str, Any],
    model_dir: str | Path = DEFAULT_MODEL_DIR,
) -> Dict[str, Any]:
    """
    Run email classification using the preferred calibrated model.

    Public contract intentionally remains compatible with the previous
    inference engine.
    """

    model, manifest = load_model(
        model_dir
    )

    if model is None:
        return dict(
            manifest
        )

    try:
        text = build_email_text(
            email
        )

        predicted_label, calibrated_probability, probability_mapping = (
            _class_probability(
                model,
                text,
                str(
                    manifest.get(
                        "positive_class",
                        "PHISHING",
                    )
                ),
            )
        )

        feature_evidence = build_feature_evidence(
            email
        )

        artifact_kind = str(
            manifest.get(
                "_artifact_kind",
                "UNKNOWN",
            )
        )

        is_calibrated = (
            _is_calibrated_bundle(model)
        )

        # Preserve the existing semantic contract while exposing
        # the additional calibrated probability metadata explicitly.
        result: Dict[str, Any] = {
            "status": "MODEL_READY",
            "model_ready": True,
            "model_type": manifest.get(
                "model_type",
                "unknown",
            ),
            "model_version": manifest.get(
                "model_version",
                "unknown",
            ),
            "classification": predicted_label,
            "model_probability": float(
                calibrated_probability
            ),
            "confidence_kind": (
                "calibrated_model_probability"
                if is_calibrated
                else manifest.get(
                    "confidence_kind",
                    "uncalibrated_model_probability",
                )
            ),
            "calibration_status": (
                "CALIBRATED"
                if is_calibrated
                else manifest.get(
                    "calibration_status",
                    "NOT_CALIBRATED",
                )
            ),
            "calibrated_probability": (
                float(calibrated_probability)
                if is_calibrated
                else None
            ),
            "probabilities": probability_mapping,
            "positive_class": manifest.get(
                "positive_class",
                "PHISHING",
            ),
            "threshold": (
                float(
                    model.get(
                        "threshold_default",
                        0.5,
                    )
                )
                if is_calibrated
                else None
            ),
            "artifact_kind": artifact_kind,
            "artifact_path": manifest.get(
                "_artifact_path",
            ),
            "feature_evidence": feature_evidence,
            "input_text_length": len(
                text
            ),
        }

        # Explainability is intentionally run against the actual
        # sklearn Pipeline inside the calibrated bundle.
        explanation_model = (
            model["base_model"]
            if is_calibrated
            else model
        )

        try:
            result["explanation"] = explain_prediction(
                explanation_model,
                text,
                predicted_label,
            )
        except Exception as exc:
            result["explanation"] = []
            result["explanation_status"] = (
                f"UNAVAILABLE:{type(exc).__name__}"
            )
        else:
            result["explanation_status"] = "AVAILABLE"

        # Additional calibrated-model diagnostics.
        if is_calibrated:
            result["calibration"] = {
                "enabled": True,
                "method": str(
                    manifest.get(
                        "calibration_method",
                        model.get(
                            "calibration_method",
                            "sigmoid",
                        ),
                    )
                ),
                "threshold_default": float(
                    model.get(
                        "threshold_default",
                        0.5,
                    )
                ),
                "raw_positive_probability": float(
                    probability_mapping.get(
                        f"{manifest.get('positive_class', 'PHISHING')}_RAW",
                        0.0,
                    )
                ),
            }
        else:
            result["calibration"] = {
                "enabled": False,
                "method": None,
                "threshold_default": None,
                "raw_positive_probability": None,
            }

        return result

    except Exception as exc:
        failed = empty_ai_result(
            f"INFERENCE_FAILED:{type(exc).__name__}"
        )
        failed["model_ready"] = False
        failed["error_type"] = type(
            exc
        ).__name__
        return failed