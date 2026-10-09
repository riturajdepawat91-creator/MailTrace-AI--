from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def load_rows(path: str | Path) -> List[Dict[str, Any]]:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {file_path}"
        )

    suffix = file_path.suffix.lower()

    if suffix == ".jsonl":
        rows = []

        with file_path.open(
            "r",
            encoding="utf-8"
        ) as handle:

            for line_no, line in enumerate(
                handle,
                start=1
            ):
                line = line.strip()

                if not line:
                    continue

                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSONL at line {line_no}: {exc}"
                    ) from exc

                if not isinstance(row, dict):
                    raise ValueError(
                        f"JSONL line {line_no} must be an object."
                    )

                rows.append(row)

        return rows

    if suffix == ".csv":
        with file_path.open(
            "r",
            encoding="utf-8-sig",
            newline=""
        ) as handle:
            return list(csv.DictReader(handle))

    raise ValueError(
        "Unsupported dataset format. Use CSV or JSONL."
    )


def validate_rows(
    rows: Iterable[Dict[str, Any]],
    min_samples_per_class: int = 4,
) -> Dict[str, Any]:

    rows = list(rows)

    if not rows:
        raise ValueError(
            "Training dataset is empty."
        )

    valid = []
    class_counts: Dict[str, int] = {}

    for index, row in enumerate(
        rows,
        start=1
    ):
        text = str(
            row.get("text", "")
        ).strip()

        label = str(
            row.get("label", "")
        ).strip().upper()

        if not text:
            raise ValueError(
                f"Row {index} has empty text."
            )

        if not label:
            raise ValueError(
                f"Row {index} has empty label."
            )

        valid.append(
            {
                "text": text,
                "label": label,
            }
        )

        class_counts[label] = (
            class_counts.get(label, 0) + 1
        )

    if len(class_counts) < 2:
        raise ValueError(
            "At least two classes are required."
        )

    insufficient = {
        label: count
        for label, count in class_counts.items()
        if count < min_samples_per_class
    }

    if insufficient:
        raise ValueError(
            "Insufficient class samples: "
            + json.dumps(
                insufficient,
                sort_keys=True
            )
        )

    return {
        "rows": valid,
        "sample_count": len(valid),
        "class_count": len(class_counts),
        "class_counts": dict(
            sorted(class_counts.items())
        ),
    }