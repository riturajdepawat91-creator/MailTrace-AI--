from __future__ import annotations

from typing import Any, Dict


AI_ENGINE_NAME = "mailtrace-email-ai"
AI_ENGINE_VERSION = "1.0.0"


def empty_ai_result(reason: str = "MODEL_NOT_READY") -> Dict[str, Any]:
    return {
        "engine": AI_ENGINE_NAME,
        "version": AI_ENGINE_VERSION,
        "status": "MODEL_NOT_READY",
        "model_ready": False,
        "model_type": None,
        "model_version": None,
        "classification": None,
        "probabilities": {},
        "model_probability": 0.0,
        "confidence": 0.0,
        "confidence_kind": "UNAVAILABLE",
        "confidence_status": "NOT_AVAILABLE",
        "calibration_status": "NOT_CALIBRATED",
        "evidence": [],
        "explanation": [],
        "fallback_allowed": True,
        "fallback_used": False,
        "reason": reason,
        "capabilities": {
            "ml_inference": False,
            "training": True,
            "explainability": False,
            "calibrated_confidence": False,
            "persistence": False,
            "execution_side_effect": False,
        },
    }