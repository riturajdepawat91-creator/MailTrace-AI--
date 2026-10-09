from __future__ import annotations

from typing import Any, Dict, Optional

from .contracts import (
    AI_ENGINE_NAME,
    AI_ENGINE_VERSION,
)
from .inference import predict_email


def analyze_email_ai(
    email: Dict[str, Any],
    model_dir: str = "models/email_ai",
    fallback_result: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:

    result = predict_email(
        email=email,
        model_dir=model_dir,
    )

    if (
        result.get("status")
        == "MODEL_NOT_READY"
    ):
        result["fallback_allowed"] = (
            fallback_result is not None
        )

        if fallback_result is not None:
            result["fallback_used"] = True
            result["fallback"] = (
                fallback_result
            )
            result["reason"] = (
                "ML_MODEL_NOT_READY_FALLBACK_AVAILABLE"
            )

    result["orchestration"] = {
        "engine": AI_ENGINE_NAME,
        "version": AI_ENGINE_VERSION,
        "read_only": True,
        "persistence": False,
        "execution_side_effect": False,
    }

    return result