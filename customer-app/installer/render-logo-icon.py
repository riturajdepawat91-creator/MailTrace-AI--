"""Render the bundled MailTrace SVG mark as a Windows ICO for installer shortcuts.

Requires Pillow only when regenerating the ICO after the source SVG changes.
The parser intentionally supports the M/L/H/V/C/Z commands used by the bundled
mark so the rendered icon follows the source vector paths without redrawing them.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "mailtrace-mark.svg"
OUTPUT = ROOT / "assets" / "mailtrace-ai.ico"
PREVIEW = ROOT / "assets" / ".mailtrace-ai-icon-preview.png"
SIZE = 1024
SCALE = SIZE / 48


def parse_path(data: str) -> list[tuple[list[tuple[float, float]], bool]]:
    tokens = re.findall(r"[MLHVCZ]|-?\d+(?:\.\d+)?", data)
    i = 0
    command = ""
    current = (0.0, 0.0)
    start = current
    points: list[tuple[float, float]] = []
    closed = False
    paths = []

    def number() -> float:
        nonlocal i
        value = float(tokens[i])
        i += 1
        return value

    def finish() -> None:
        nonlocal points, closed
        if points:
            paths.append((points, closed))
        points = []
        closed = False

    while i < len(tokens):
        if tokens[i].isalpha():
            command = tokens[i]
            i += 1
        if command == "M":
            finish()
            current = (number(), number())
            start = current
            points = [current]
            command = "L"
        elif command == "L":
            current = (number(), number())
            points.append(current)
        elif command == "H":
            current = (number(), current[1])
            points.append(current)
        elif command == "V":
            current = (current[0], number())
            points.append(current)
        elif command == "C":
            p0 = current
            p1 = (number(), number())
            p2 = (number(), number())
            p3 = (number(), number())
            for step in range(1, 33):
                t = step / 32
                mt = 1 - t
                x = mt**3*p0[0] + 3*mt**2*t*p1[0] + 3*mt*t**2*p2[0] + t**3*p3[0]
                y = mt**3*p0[1] + 3*mt**2*t*p1[1] + 3*mt*t**2*p2[1] + t**3*p3[1]
                points.append((x, y))
            current = p3
        elif command == "Z":
            if current != start:
                points.append(start)
            current = start
            closed = True
            finish()
            command = ""
        else:
            raise ValueError(f"Unsupported SVG path command: {command}")

    finish()
    return paths


def main() -> None:
    tree = ET.parse(SOURCE)
    styles = {}
    for selector, body in re.findall(r"\.([\w-]+)\s*\{([^}]+)\}", tree.getroot().find("{http://www.w3.org/2000/svg}style").text):
        styles[selector] = dict(re.findall(r"([\w-]+)\s*:\s*([^;]+)", body))

    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    for path in tree.getroot().findall("{http://www.w3.org/2000/svg}path"):
        classes = path.attrib.get("class", "").split()
        style = {}
        for name in classes:
            style.update(styles.get(name, {}))
        color = style.get("stroke", "#00c8ff")
        width = max(1, round(float(style.get("stroke-width", "1")) * SCALE))
        round_caps = style.get("stroke-linecap") == "round"
        for coords, _closed in parse_path(path.attrib["d"]):
            scaled = [(round(x*SCALE), round(y*SCALE)) for x, y in coords]
            draw.line(scaled, fill=color, width=width, joint="curve")
            if round_caps and len(scaled) > 1:
                radius = width // 2
                for x, y in (scaled[0], scaled[-1]):
                    draw.ellipse((x-radius, y-radius, x+radius, y+radius), fill=color)

    # Keep a visual proof next to the generated icon for inspection.
    image.resize((256, 256), Image.Resampling.LANCZOS).save(PREVIEW)
    image.save(OUTPUT, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
    print(f"Created {OUTPUT}")


if __name__ == "__main__":
    main()
