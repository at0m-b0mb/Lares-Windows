#!/usr/bin/env python3
"""Draw the repository banner and the application icon.

The motif is the product's own signature element rather than a generic shield:
The Watch, the row of columns showing a machine's backlog of findings coming
down cycle after cycle. It is the one picture that says what Lares does.

Colours are read from the same theme module the desktop application uses, so the
banner cannot drift away from the product it is advertising.

    python tools/make_banner.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image, ImageDraw, ImageFont  # noqa: E402

from lares.version import NAME, TAGLINE  # noqa: E402

OUT = ROOT / "assets"

# Taken from lares/gui/theme.py. Kept as literals here so the banner can be
# drawn without starting Qt; the test suite asserts they still match.
PAPER = "#F3F1EC"
CARD = "#FFFFFF"
INK = "#1A1916"
MUTED = "#6B6558"
RULE = "#DDD8CD"
BRASS = "#7C5F10"
SHINE = "#A0811F"

#: A machine being looked after: the open count falling, then flattening at the
#: handful of findings that need a person. Pairs are (open, fixed).
STORY = [
    (28, 8), (20, 8), (12, 3), (9, 2), (7, 1), (6, 1),
    (5, 0), (5, 0), (5, 0), (5, 0), (5, 0), (5, 0),
]

FONT_DIRS = [
    "/System/Library/Fonts/Supplemental",
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/truetype/liberation",
    "C:/Windows/Fonts",
]

SERIF_FILES = ["Georgia.ttf", "georgia.ttf", "Times New Roman.ttf",
               "LiberationSerif-Regular.ttf", "DejaVuSerif.ttf"]
SANS_FILES = ["Arial.ttf", "arial.ttf", "Helvetica.ttc",
              "LiberationSans-Regular.ttf", "DejaVuSans.ttf"]


def font(files: list[str], size: int) -> ImageFont.FreeTypeFont:
    for directory in FONT_DIRS:
        for name in files:
            path = Path(directory) / name
            if path.exists():
                try:
                    return ImageFont.truetype(str(path), size)
                except OSError:
                    continue
    return ImageFont.load_default(size)


def draw_watch(draw: ImageDraw.ImageDraw, x: int, y: int, width: int, height: int,
               gap: int = 7) -> None:
    """The Watch motif: open findings as column height, fixed as gold at the base."""
    n = len(STORY)
    bar = (width - gap * (n - 1)) / n
    peak = max(o for o, _ in STORY)

    draw.line([(x, y + height), (x + width, y + height)], fill=RULE, width=1)

    for index, (open_count, fixed) in enumerate(STORY):
        left = x + index * (bar + gap)
        column = height * (open_count / peak)
        top = y + height - column
        draw.rectangle([left, top, left + bar, y + height], fill=RULE)
        if fixed:
            closed = column * min(1.0, fixed / open_count)
            draw.rectangle([left, y + height - closed, left + bar, y + height],
                           fill=SHINE)


def banner() -> Path:
    W, H = 1280, 400
    image = Image.new("RGB", (W, H), PAPER)
    draw = ImageDraw.Draw(image)

    # A white card inset on the paper, the same relationship the interface uses.
    margin = 36
    draw.rectangle([margin, margin, W - margin, H - margin], fill=CARD, outline=RULE)
    # The brass rule down the left edge, as on an accented card.
    draw.rectangle([margin, margin, margin + 3, H - margin], fill=BRASS)

    serif = font(SERIF_FILES, 92)
    sans = font(SANS_FILES, 23)
    small = font(SANS_FILES, 17)

    left = margin + 54
    draw.text((left, 104), NAME, font=serif, fill=INK)
    draw.text((left + 4, 214), TAGLINE, font=sans, fill=MUTED)
    draw.text((left + 4, 252),
              "It decides with a local model, fixes what it can undo, "
              "and puts back anything that made the machine worse.",
              font=small, fill=MUTED)

    draw_watch(draw, W - margin - 330, 116, 268, 118)
    draw.text((W - margin - 330, 246), "THE WATCH", font=small, fill=BRASS)
    draw.text((W - margin - 330, 270), "one column per cycle", font=small, fill=MUTED)

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "banner.png"
    image.save(path)
    return path


def icon() -> Path:
    """A square mark: the Watch reduced to five columns."""
    S = 512
    image = Image.new("RGB", (S, S), PAPER)
    draw = ImageDraw.Draw(image)

    inset = 44
    draw.rectangle([inset, inset, S - inset, S - inset], fill=CARD, outline=RULE, width=3)

    bars = [(1.0, 0.28), (0.74, 0.34), (0.5, 0.4), (0.34, 0.22), (0.28, 0.0)]
    width, gap = 46, 22
    total = len(bars) * width + (len(bars) - 1) * gap
    x = (S - total) / 2
    base = S - inset - 64
    tallest = S - 2 * inset - 150

    for fraction, fixed in bars:
        column = tallest * fraction
        draw.rectangle([x, base - column, x + width, base], fill=RULE)
        if fixed:
            draw.rectangle([x, base - column * fixed, x + width, base], fill=SHINE)
        x += width + gap

    draw.rectangle([inset, base + 18, S - inset, base + 24], fill=BRASS)

    path = OUT / "icon.png"
    image.save(path)
    for size in (256, 128, 64, 32):
        image.resize((size, size), Image.LANCZOS).save(OUT / f"icon-{size}.png")
    image.resize((256, 256), Image.LANCZOS).save(
        OUT / "lares.ico", format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    return path


if __name__ == "__main__":
    print(f"  {banner().relative_to(ROOT)}")
    print(f"  {icon().relative_to(ROOT)}")
    print("  assets/icon-{256,128,64,32}.png, assets/lares.ico")
