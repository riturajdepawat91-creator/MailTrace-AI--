from __future__ import annotations

from typing import Any, Dict, List


def explain_prediction(
    pipeline: Any,
    text: str,
    predicted_label: str,
    limit: int = 12,
) -> List[Dict[str, Any]]:

    try:
        vectorizer = pipeline.named_steps[
            "tfidf"
        ]

        classifier = pipeline.named_steps[
            "classifier"
        ]

        matrix = vectorizer.transform(
            [text]
        )

        feature_names = (
            vectorizer
            .get_feature_names_out()
        )

        classes = list(
            classifier.classes_
        )

        class_index = classes.index(
            predicted_label
        )

        coefficients = classifier.coef_

        if (
            coefficients.shape[0] == 1
            and len(classes) == 2
        ):
            row = coefficients[0]

            if class_index == 0:
                row = -row
        else:
            row = coefficients[
                class_index
            ]

        contributions = []

        for feature_index in matrix.nonzero()[1]:
            value = float(
                matrix[
                    0,
                    feature_index
                ]
            )

            coefficient = float(
                row[feature_index]
            )

            contribution = (
                value * coefficient
            )

            if contribution == 0.0:
                continue

            contributions.append(
                {
                    "feature": feature_names[
                        feature_index
                    ],
                    "contribution": contribution,
                    "direction": (
                        "supports_prediction"
                        if contribution > 0
                        else "contradicts_prediction"
                    ),
                }
            )

        contributions.sort(
            key=lambda item: abs(
                item["contribution"]
            ),
            reverse=True,
        )

        return contributions[:limit]

    except Exception as exc:
        return [
            {
                "feature": (
                    "explainability_error"
                ),
                "contribution": 0.0,
                "direction": "unavailable",
                "error": str(exc),
            }
        ]