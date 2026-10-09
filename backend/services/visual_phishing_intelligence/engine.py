from __future__ import annotations

import io
from typing import Any

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError

from services.advanced_url_intelligence import analyze_url_deception

from .models import (
    QRPayloadEvidence,
    VisualAnalysisResult,
    VisualFeatureProfile,
)
from .rules import (
    ACTION_CORRELATION_FAILURE,
    ACTION_LIMITED,
    ACTION_REVIEW_QR_PAYLOAD,
    ACTION_REVIEW_URL,
    ACTION_REVIEW_VISUAL,
    ACTION_REVIEW_VISUAL_SIGNALS,
    ANALYSIS_VERSION,
    MAX_COMPONENTS,
    MAX_CONTOURS,
    MAX_EVIDENCE,
    MAX_HEIGHT,
    MAX_INPUT_BYTES,
    MAX_PAYLOAD_CHARS,
    MAX_PIXELS,
    MAX_QR_RESULTS,
    MAX_URL_ANALYSES,
    MAX_URL_EVIDENCE_CHARS,
    MAX_URL_FINDINGS,
    MAX_VISUAL_SIGNAL_SCORE,
    SEVERITY_RANK,
    VERDICT_ANALYSIS_LIMITED,
    VERDICT_CLEAN,
    VERDICT_COMBINED_VISUAL_RISK,
    VERDICT_ERROR,
    VERDICT_HIGH_RISK_QR,
    VERDICT_QR_PRESENT,
    VERDICT_URL_CORRELATED,
    VERDICT_VISUAL_SUSPICION,
)

MODULE_NAME = "visual_phishing_intelligence"
STATIC_ONLY = True
MAX_WIDTH = 8000


def _clamp_text(
    value: str,
    limit: int = MAX_PAYLOAD_CHARS,
) -> tuple[str, bool]:
    value = str(value or "")

    if len(value) <= limit:
        return value, False

    return value[:limit], True


def _classify_payload(payload: str) -> str:
    value = payload.strip().lower()

    if value.startswith(("http://", "https://")):
        return "URL"
    if value.startswith("mailto:"):
        return "EMAIL"
    if value.startswith(("tel:", "sms:")):
        return "TELEPHONY"
    if value.startswith("wifi:"):
        return "WIFI"
    if value.startswith(("bitcoin:", "ethereum:")):
        return "CRYPTO"

    return "TEXT"


def _normalize_payload(payload: str) -> tuple[str, bool]:
    value = str(payload or "").strip()

    if not value:
        return "", False

    return _clamp_text(value)


def _points_to_list(points: Any) -> list[list[float]]:
    if points is None:
        return []

    try:
        array = np.asarray(points, dtype=np.float32).reshape(-1, 2)

        return [
            [round(float(x), 2), round(float(y), 2)]
            for x, y in array
        ]
    except Exception:
        return []


def _base_result(
    filename: str | None,
) -> VisualAnalysisResult:
    return VisualAnalysisResult(
        module_name=MODULE_NAME,
        analysis_version=ANALYSIS_VERSION,
        static_only=STATIC_ONLY,
        success=False,
        filename=filename,
        image_format=None,
        width=None,
        height=None,
        channels=None,
        pixel_count=0,
        qr_detected=False,
        qr_count=0,
        qr_payloads=[],
        visual_features=None,
        evidence=[],
        recommended_actions=[],
        risk_score=0.0,
        confidence=0.0,
        verdict=VERDICT_ERROR,
    )


def _add_evidence(
    result: VisualAnalysisResult,
    rule_id: str,
    title: str,
    description: str,
    severity: str = "INFO",
    score: float = 0.0,
    extra: dict[str, Any] | None = None,
) -> None:
    if len(result.evidence) >= MAX_EVIDENCE:
        return

    item: dict[str, Any] = {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "score": float(score),
    }

    if extra:
        item["evidence"] = extra

    result.evidence.append(item)


def _extract_visual_features(
    image: np.ndarray,
) -> VisualFeatureProfile:
    height, width = image.shape[:2]

    gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)

    mean = float(np.mean(gray))
    std = float(np.std(gray))

    dark_ratio = float(np.mean(gray < 60))
    bright_ratio = float(np.mean(gray > 210))

    edges = cv2.Canny(gray, 80, 160)

    edge_density = float(
        np.count_nonzero(edges) / max(1, edges.size)
    )

    threshold = cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        11,
    )

    num_labels, _, stats, _ = cv2.connectedComponentsWithStats(
        threshold,
        connectivity=8,
    )

    component_count = min(
        max(0, num_labels - 1),
        MAX_COMPONENTS,
    )

    text_like = 0
    button_like = 0
    card_like = 0

    image_area = float(width * height)

    contours, _ = cv2.findContours(
        cv2.bitwise_not(threshold),
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE,
    )

    for contour in contours[:MAX_CONTOURS]:
        x, y, w, h = cv2.boundingRect(contour)

        area = float(w * h)
        if area <= 0:
            continue

        ratio = float(w / max(1, h))
        relative_area = area / max(1.0, image_area)

        if (
            8 <= w <= max(12, width // 2)
            and 5 <= h <= max(12, height // 4)
            and 0.2 <= ratio <= 12.0
            and relative_area <= 0.20
        ):
            text_like += 1

        if (
            w >= max(40, width // 8)
            and h >= max(18, height // 80)
            and ratio >= 2.0
            and relative_area <= 0.25
        ):
            button_like += 1

        if (
            w >= max(100, width // 5)
            and h >= max(60, height // 10)
            and 0.5 <= ratio <= 4.0
            and relative_area <= 0.70
        ):
            card_like += 1

    # Screenshot-like images often have substantial structured content
    # and a moderate aspect ratio rather than an icon/banner geometry.
    aspect = float(width / max(1, height))

    screenshot_like = (
        0.45 <= aspect <= 2.40
        and edge_density >= 0.025
        and component_count >= 12
    )

    dense_layout = (
        edge_density >= 0.08
        or component_count >= 250
        or text_like >= 30
    )

    return VisualFeatureProfile(
        aspect_ratio=round(aspect, 4),
        grayscale_mean=round(mean, 3),
        grayscale_std=round(std, 3),
        edge_density=round(edge_density, 6),
        dark_pixel_ratio=round(dark_ratio, 6),
        bright_pixel_ratio=round(bright_ratio, 6),
        connected_components=component_count,
        text_like_components=min(text_like, MAX_COMPONENTS),
        button_like_regions=min(button_like, MAX_CONTOURS),
        card_like_regions=min(card_like, MAX_CONTOURS),
        screenshot_like=screenshot_like,
        dense_layout=dense_layout,
    )


def _score_visual_features(
    result: VisualAnalysisResult,
) -> None:
    features = result.visual_features

    if features is None:
        return

    score = 0.0
    signals = 0

    if features.screenshot_like:
        score += 5.0
        signals += 1

        _add_evidence(
            result,
            "VISUAL_SCREENSHOT_LIKE_STRUCTURE",
            "Screenshot-like visual structure",
            "The image exhibits structural characteristics commonly associated with rendered web/app screenshots.",
            severity="LOW",
            score=5.0,
            extra={
                "aspect_ratio": features.aspect_ratio,
                "edge_density": features.edge_density,
                "connected_components": features.connected_components,
            },
        )

    if features.text_like_components >= 30:
        score += 7.0
        signals += 1

        _add_evidence(
            result,
            "VISUAL_TEXT_DENSE_LAYOUT",
            "Dense text-like visual regions",
            "The image contains many small connected regions consistent with a text-dense interface or rendered message.",
            severity="LOW",
            score=7.0,
            extra={
                "text_like_components": features.text_like_components,
            },
        )

    if features.button_like_regions >= 3:
        score += 6.0
        signals += 1

        _add_evidence(
            result,
            "VISUAL_MULTIPLE_CTA_REGIONS",
            "Multiple CTA-like regions",
            "Multiple rectangular regions resemble buttons or action controls.",
            severity="MEDIUM",
            score=6.0,
            extra={
                "button_like_regions": features.button_like_regions,
            },
        )

    if features.card_like_regions >= 2:
        score += 4.0
        signals += 1

        _add_evidence(
            result,
            "VISUAL_CARD_LAYOUT",
            "Structured card-like layout",
            "The image contains multiple large structured regions consistent with a rendered notification or web-style interface.",
            severity="LOW",
            score=4.0,
            extra={
                "card_like_regions": features.card_like_regions,
            },
        )

    if features.dense_layout:
        score += 4.0
        signals += 1

        _add_evidence(
            result,
            "VISUAL_DENSE_LAYOUT",
            "Dense visual layout",
            "The image contains substantial edge/component density requiring analyst review when combined with phishing indicators.",
            severity="LOW",
            score=4.0,
            extra={
                "edge_density": features.edge_density,
                "connected_components": features.connected_components,
            },
        )

    # Very high structure alone must never produce a high-confidence
    # phishing verdict. It only contributes bounded supporting evidence.
    result.visual_signal_score = min(
        MAX_VISUAL_SIGNAL_SCORE,
        score,
    )
    result.visual_signal_count = signals


def _decode_qr(
    image: np.ndarray,
) -> tuple[list[QRPayloadEvidence], bool]:
    detector = cv2.QRCodeDetector()
    payloads: list[QRPayloadEvidence] = []

    try:
        ok, decoded_info, points, _ = detector.detectAndDecodeMulti(
            image
        )

        if ok and decoded_info:
            for index, payload in enumerate(
                decoded_info[:MAX_QR_RESULTS]
            ):
                normalized, truncated = _normalize_payload(payload)

                if not normalized:
                    continue

                point_list = []

                if points is not None and index < len(points):
                    point_list = _points_to_list(points[index])

                payloads.append(
                    QRPayloadEvidence(
                        index=index,
                        payload=normalized,
                        payload_type=_classify_payload(normalized),
                        confidence=1.0,
                        points=point_list,
                        payload_truncated=truncated,
                    )
                )
    except Exception:
        pass

    if payloads:
        return payloads[:MAX_QR_RESULTS], True

    try:
        value, points, _ = detector.detectAndDecode(image)

        normalized, truncated = _normalize_payload(value)

        if normalized:
            return (
                [
                    QRPayloadEvidence(
                        index=0,
                        payload=normalized,
                        payload_type=_classify_payload(normalized),
                        confidence=1.0,
                        points=_points_to_list(points),
                        payload_truncated=truncated,
                    )
                ],
                True,
            )
    except Exception:
        pass

    return [], False


def _serialize_url_result(
    url_result: Any,
) -> dict[str, Any]:
    findings = []

    for finding in list(
        getattr(url_result, "findings", []) or []
    )[:MAX_URL_FINDINGS]:
        finding_dict = {
            "rule_id": str(getattr(finding, "rule_id", "")),
            "title": str(getattr(finding, "title", "")),
            "severity": str(getattr(finding, "severity", "")),
            "score": float(getattr(finding, "score", 0.0)),
            "confidence": float(getattr(finding, "confidence", 0.0)),
        }

        evidence = getattr(finding, "evidence", {}) or {}

        if isinstance(evidence, dict):
            safe_evidence = {}

            for key, value in list(
                evidence.items()
            )[:MAX_URL_FINDINGS]:
                text = str(value)

                if len(text) > MAX_URL_EVIDENCE_CHARS:
                    text = (
                        text[:MAX_URL_EVIDENCE_CHARS]
                        + "[TRUNCATED]"
                    )

                safe_evidence[str(key)] = text

            finding_dict["evidence"] = safe_evidence

        findings.append(finding_dict)

    return {
        "risk_score": float(
            getattr(url_result, "risk_score", 0.0)
        ),
        "severity": str(
            getattr(url_result, "severity", "NONE")
        ),
        "verdict": str(
            getattr(url_result, "verdict", "")
        ),
        "confidence": float(
            getattr(url_result, "confidence", 0.0)
        ),
        "hostname": getattr(
            url_result,
            "hostname",
            None,
        ),
        "registrable_domain": getattr(
            url_result,
            "registrable_domain",
            None,
        ),
        "brand_domain_mismatch": bool(
            getattr(
                url_result,
                "brand_domain_mismatch",
                False,
            )
        ),
        "parser_confusion": bool(
            getattr(
                url_result,
                "parser_confusion",
                False,
            )
        ),
        "lure_tokens": list(
            getattr(url_result, "lure_tokens", []) or []
        )[:20],
        "brand_candidates": list(
            getattr(url_result, "brand_candidates", []) or []
        )[:20],
        "findings": findings,
        "analysis_version": str(
            getattr(url_result, "analysis_version", "")
        ),
        "static_only": bool(
            getattr(url_result, "static_only", True)
        ),
    }


def _correlate_url_payload(
    payload: QRPayloadEvidence,
) -> tuple[
    dict[str, Any] | None,
    list[dict[str, Any]],
    float,
]:
    if payload.payload_type != "URL":
        return None, [], 0.0

    try:
        url_result = analyze_url_deception(payload.payload)
    except Exception as exc:
        payload.correlation_error = type(exc).__name__
        return None, [], 0.0

    serialized = _serialize_url_result(url_result)
    findings = serialized.get("findings", [])
    risk = float(serialized.get("risk_score", 0.0))

    return serialized, findings, risk


def _apply_url_correlations(
    result: VisualAnalysisResult,
) -> None:
    url_payloads = [
        item
        for item in result.qr_payloads
        if item.payload_type == "URL"
    ]

    if not url_payloads:
        return

    bounded_payloads = url_payloads[:MAX_URL_ANALYSES]

    if len(url_payloads) > MAX_URL_ANALYSES:
        result.limits_applied.append(
            "MAX_URL_ANALYSES"
        )

        _add_evidence(
            result,
            "VISUAL_URL_ANALYSIS_LIMIT",
            "QR URL analysis limit reached",
            "Only the configured maximum number of QR URL payloads were correlated.",
            severity="MEDIUM",
            extra={
                "detected_url_payloads": len(url_payloads),
                "analyzed_url_payloads": len(bounded_payloads),
                "maximum": MAX_URL_ANALYSES,
            },
        )

    result.url_correlations = len(bounded_payloads)

    for payload in bounded_payloads:
        serialized, findings, risk = _correlate_url_payload(
            payload
        )

        if serialized is None:
            result.correlation_failures += 1

            _add_evidence(
                result,
                "VISUAL_QR_URL_CORRELATION_FAILURE",
                "QR URL correlation failed safely",
                "The QR payload could not be analyzed by URL intelligence; the visual analyzer continued without crashing.",
                severity="MEDIUM",
                extra={
                    "payload_type": payload.payload_type,
                    "correlation_error": payload.correlation_error,
                },
            )

            if ACTION_CORRELATION_FAILURE not in result.recommended_actions:
                result.recommended_actions.append(
                    ACTION_CORRELATION_FAILURE
                )

            continue

        payload.url_analysis = serialized
        payload.url_risk_score = risk
        payload.url_severity = serialized.get(
            "severity"
        )
        payload.url_verdict = serialized.get(
            "verdict"
        )
        payload.url_confidence = float(
            serialized.get("confidence", 0.0)
        )
        payload.url_finding_ids = [
            str(item.get("rule_id", ""))
            for item in findings
            if item.get("rule_id")
        ]
        payload.url_correlated = bool(findings)

        result.correlated_url_count += 1

        result.max_url_risk_score = max(
            result.max_url_risk_score,
            payload.url_risk_score,
        )

        current_severity = str(
            payload.url_severity or "NONE"
        )
        existing_severity = (
            result.highest_url_severity or "NONE"
        )

        if SEVERITY_RANK.get(
            current_severity,
            0,
        ) > SEVERITY_RANK.get(
            existing_severity,
            0,
        ):
            result.highest_url_severity = (
                current_severity
            )

        if findings:
            _add_evidence(
                result,
                "VISUAL_QR_URL_CORRELATION",
                "QR payload correlated with URL intelligence",
                "A URL decoded from a QR code produced findings in Advanced URL Intelligence.",
                severity=current_severity,
                score=min(
                    45.0,
                    max(5.0, risk * 0.45),
                ),
                extra={
                    "url": payload.payload,
                    "url_risk_score": risk,
                    "url_severity": payload.url_severity,
                    "url_verdict": payload.url_verdict,
                    "finding_ids": payload.url_finding_ids[
                        :MAX_URL_FINDINGS
                    ],
                },
            )

    if result.correlated_url_count:
        result.visual_url_correlation_score = min(
            45.0,
            result.max_url_risk_score * 0.45,
        )

        _add_evidence(
            result,
            "VISUAL_QR_URL_ANALYSIS_PRESENT",
            "Decoded QR URL underwent static URL analysis",
            "The QR payload was analyzed locally by existing URL-deception intelligence without network access.",
            severity=result.highest_url_severity or "INFO",
            score=result.visual_url_correlation_score,
            extra={
                "analyzed_urls": result.correlated_url_count,
                "max_url_risk_score": result.max_url_risk_score,
            },
        )

        if ACTION_REVIEW_URL not in result.recommended_actions:
            result.recommended_actions.append(
                ACTION_REVIEW_URL
            )


def _finalize_risk(
    result: VisualAnalysisResult,
) -> None:
    qr_base = 0.0

    if result.qr_detected:
        qr_base = min(
            20.0,
            10.0 + sum(
                10.0
                if item.payload_type == "URL"
                else 2.0
                for item in result.qr_payloads
            ),
        )

    visual_support = min(
        MAX_VISUAL_SIGNAL_SCORE,
        result.visual_signal_score,
    )

    correlation = result.visual_url_correlation_score

    result.risk_score = min(
        100.0,
        qr_base + visual_support + correlation,
    )

    high_url = (
        result.correlated_url_count
        and (
            result.max_url_risk_score >= 75.0
            or result.highest_url_severity == "CRITICAL"
        )
    )

    if high_url:
        result.risk_score = max(
            result.risk_score,
            min(
                100.0,
                result.max_url_risk_score,
            ),
        )

        if result.visual_signal_count >= 2:
            result.verdict = (
                VERDICT_COMBINED_VISUAL_RISK
            )
        else:
            result.verdict = VERDICT_HIGH_RISK_QR

    elif result.visual_signal_count >= 2:
        result.verdict = VERDICT_VISUAL_SUSPICION

    elif result.correlated_url_count:
        result.verdict = VERDICT_URL_CORRELATED

    elif result.qr_detected:
        result.verdict = VERDICT_QR_PRESENT

    else:
        result.verdict = VERDICT_CLEAN


def analyze_image(
    image_bytes: bytes,
    filename: str | None = None,
) -> VisualAnalysisResult:
    result = _base_result(filename)

    if not isinstance(
        image_bytes,
        (bytes, bytearray, memoryview),
    ):
        result.errors.append(
            "image_bytes must be bytes-like data."
        )
        return result

    raw = bytes(image_bytes)

    if not raw:
        result.errors.append(
            "Image input is empty."
        )
        return result

    if len(raw) > MAX_INPUT_BYTES:
        result.limits_applied.append(
            "MAX_INPUT_BYTES"
        )
        result.recommended_actions.append(
            ACTION_LIMITED
        )
        result.verdict = VERDICT_ANALYSIS_LIMITED
        result.errors.append(
            "Image exceeds maximum input size."
        )
        return result

    try:
        with Image.open(io.BytesIO(raw)) as pil_image:
            pil_image.verify()

        with Image.open(io.BytesIO(raw)) as pil_image:
            image_format = (
                pil_image.format or ""
            ).upper() or None

            width, height = pil_image.size
            mode = pil_image.mode
            pixel_count = width * height

            result.image_format = image_format
            result.width = width
            result.height = height
            result.pixel_count = pixel_count

            if width > MAX_WIDTH:
                result.limits_applied.append(
                    "MAX_WIDTH"
                )

            if height > MAX_HEIGHT:
                result.limits_applied.append(
                    "MAX_HEIGHT"
                )

            if pixel_count > MAX_PIXELS:
                result.limits_applied.append(
                    "MAX_PIXELS"
                )

            if result.limits_applied:
                result.recommended_actions.append(
                    ACTION_LIMITED
                )
                result.verdict = (
                    VERDICT_ANALYSIS_LIMITED
                )
                result.errors.append(
                    "Image exceeds configured processing bounds."
                )
                return result

            rgb = pil_image.convert("RGB")
            image = np.asarray(rgb)

            result.channels = (
                int(image.shape[2])
                if image.ndim == 3
                else 1
            )

            if mode != "RGB":
                _add_evidence(
                    result,
                    "VISUAL_IMAGE_NORMALIZED",
                    "Image normalized for analysis",
                    f"Input image mode '{mode}' was normalized to RGB for static analysis.",
                )

    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
    ) as exc:
        result.errors.append(
            f"Invalid or unreadable image: {type(exc).__name__}."
        )
        return result

    except Exception as exc:
        result.errors.append(
            f"Image parsing failed: {type(exc).__name__}."
        )
        return result

    # Visual structural analysis.
    try:
        result.visual_features = (
            _extract_visual_features(image)
        )
        _score_visual_features(result)
    except Exception as exc:
        result.errors.append(
            f"Visual feature analysis failed: {type(exc).__name__}."
        )

    # QR analysis.
    try:
        qr_payloads, qr_detected = _decode_qr(image)
    except Exception as exc:
        qr_payloads = []
        qr_detected = False
        result.errors.append(
            f"QR analysis failed: {type(exc).__name__}."
        )

    result.qr_payloads = qr_payloads[:MAX_QR_RESULTS]
    result.qr_count = len(result.qr_payloads)
    result.qr_detected = qr_detected

    if qr_detected:
        _add_evidence(
            result,
            "VISUAL_QR_DETECTED",
            "QR code detected",
            f"Detected {result.qr_count} decodable QR payload(s) in the image.",
            severity="MEDIUM",
            score=min(
                20.0,
                5.0 * result.qr_count,
            ),
        )

        for item in result.qr_payloads:
            if item.payload_truncated:
                _add_evidence(
                    result,
                    "VISUAL_QR_PAYLOAD_TRUNCATED",
                    "QR payload truncated to configured safety bound",
                    "The decoded QR payload exceeded the configured character limit and was safely truncated before downstream analysis.",
                    severity="MEDIUM",
                    extra={
                        "index": item.index,
                        "maximum_characters": MAX_PAYLOAD_CHARS,
                    },
                )

            severity = (
                "MEDIUM"
                if item.payload_type == "URL"
                else "INFO"
            )

            score = (
                10.0
                if item.payload_type == "URL"
                else 2.0
            )

            _add_evidence(
                result,
                "VISUAL_QR_PAYLOAD",
                f"QR payload {item.index + 1}",
                f"Decoded QR payload classified as {item.payload_type}.",
                severity=severity,
                score=score,
            )

        result.recommended_actions.append(
            ACTION_REVIEW_QR_PAYLOAD
        )
        result.recommended_actions.append(
            ACTION_REVIEW_VISUAL
        )

    _apply_url_correlations(result)

    if result.visual_signal_count >= 2:
        if ACTION_REVIEW_VISUAL_SIGNALS not in result.recommended_actions:
            result.recommended_actions.append(
                ACTION_REVIEW_VISUAL_SIGNALS
            )

    _finalize_risk(result)

    if result.risk_score >= 75.0:
        result.confidence = 0.97
    elif result.risk_score >= 40.0:
        result.confidence = 0.92
    elif result.visual_signal_count >= 2:
        result.confidence = 0.84
    elif result.qr_detected:
        result.confidence = 0.95
    else:
        result.confidence = 0.80

    result.success = True
    return result


def analyze_image_file(
    path: str,
    filename: str | None = None,
) -> VisualAnalysisResult:
    effective_filename = filename or path

    try:
        with open(path, "rb") as handle:
            data = handle.read(
                MAX_INPUT_BYTES + 1
            )
    except OSError as exc:
        result = _base_result(
            effective_filename
        )
        result.errors.append(
            f"Unable to read image file: {type(exc).__name__}."
        )
        return result

    return analyze_image(
        data,
        filename=effective_filename,
    )


__all__ = [
    "ANALYSIS_VERSION",
    "MODULE_NAME",
    "STATIC_ONLY",
    "analyze_image",
    "analyze_image_file",
]
