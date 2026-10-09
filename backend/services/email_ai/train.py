from __future__ import annotations

import argparse
import json

from .dataset import load_rows, validate_rows
from .model import train_model


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Train MailTrace-AI email threat ML model."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to CSV or JSONL training dataset.",
    )

    parser.add_argument(
        "--output",
        default="models/email_ai",
        help="Output model directory.",
    )

    args = parser.parse_args()

    rows = load_rows(
        args.input
    )

    validation = validate_rows(
        rows
    )

    result = train_model(
        rows=validation["rows"],
        output_dir=args.output,
        dataset_path=args.input,
    )

    print(
        json.dumps(
            {
                "status": "TRAINING_COMPLETE",
                "dataset": validation,
                "model": result,
            },
            indent=2,
            ensure_ascii=False,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )