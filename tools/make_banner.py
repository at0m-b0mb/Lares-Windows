#!/usr/bin/env python3
"""Draw the repository banner and the application icon.

The motif is the product's own signature element rather than a generic shield
or padlock: The Watch, the row of columns showing a machine's backlog of
findings coming down cycle after cycle - and then flattening, not at zero, but
at the handful of things that need a person. That floor is the honest part of
the picture and the reason this motif is worth drawing at all. It is the one
image only this program could produce, because it is made of what the program
produces.

Two banners come out, light and true-black, because GitHub renders the README
in the reader's own colour scheme and a light-only banner is a white slab to
half the people who open the page.

Colours mirror lares/gui/theme.py so the banner cannot advertise a product it
no longer looks like; tests/test_theme.py asserts they still match.

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


class Palette:
    """One theme's colours, named as lares/gui/theme.py names them.

    Held as literals rather than imported so the banner can be drawn without
    starting Qt, which theme.py needs only to resolve a font family. The drift
    that invites is caught by a test rather than shipped.
    """

    def __init__(self, paper: str, card: str, ink: str, ink_soft: str,
                 muted: str, rule: str, brass: str, shine: str) -> None:
        self.paper, self.card = paper, card
        self.ink, self.ink_soft, self.muted = ink, ink_soft, muted
        self.rule, self.brass, self.shine = rule, brass, shine


LIGHT = Palette(paper="#F3F1EC", card="#FFFFFF", ink="#1A1916",
                ink_soft="#4A463D", muted="#6B6558", rule="#DDD8CD",
                brass="#7C5F10", shine="#A0811F")

#: True black. Nothing in the dark theme may read as navy.
DARK = Palette(paper="#000000", card="#121212", ink="#ECEAE4",
               ink_soft="#B8B3A9", muted="#8A857B", rule="#2A2A2A",
               brass="#D4A73A", shine="#E8C468")

#: A machine being looked after, cycle by cycle. Pairs are (open, closed).
STORY = [
    (28, 8), (20, 8), (12, 3), (9, 2), (7, 1), (6, 1),
    (5, 0), (5, 0), (5, 0), (5, 0), (5, 0), (5, 0),
]

#: Where the story stops falling. Drawn, so the flat tail reads as a deliberate
#: floor rather than as the agent having given up.
FLOOR = 5

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


def draw_watch(draw: ImageDraw.ImageDraw, pal: Palette, x: int, y: int,
               width: int, height: int, gap: int = 7) -> None:
    """Open findings as column height, closed as brass at the base."""
    count = len(STORY)
    bar = (width - gap * (count - 1)) / count
    peak = max(open_count for open_count, _ in STORY)

    # Drawn in muted rather than rule. At rule weight the dashes vanish into
    # the card in both themes, which left the caption underneath pointing at
    # a line nobody could see.
    floor_y = y + height - height * (FLOOR / peak)
    for dash in range(0, int(width), 8):
        draw.line([(x + dash, floor_y), (x + min(dash + 3, width), floor_y)],
                  fill=pal.muted, width=1)

    draw.line([(x, y + height), (x + width, y + height)], fill=pal.rule, width=1)

    for index, (open_count, closed) in enumerate(STORY):
        left = x + index * (bar + gap)
        column = height * (open_count / peak)
        draw.rectangle([left, y + height - column, left + bar, y + height],
                       fill=pal.rule)
        if closed:
            filled = column * min(1.0, closed / open_count)
            draw.rectangle([left, y + height - filled, left + bar, y + height],
                           fill=pal.shine)


def banner(pal: Palette, filename: str) -> Path:
    width, height = 1280, 400
    image = Image.new("RGB", (width, height), pal.paper)
    draw = ImageDraw.Draw(image)

    margin = 36
    draw.rectangle([margin, margin, width - margin, height - margin],
                   fill=pal.card, outline=pal.rule)
    draw.rectangle([margin, margin, margin + 3, height - margin], fill=pal.brass)

    serif = font(SERIF_FILES, 92)
    sans = font(SANS_FILES, 23)
    small = font(SANS_FILES, 17)
    tiny = font(SANS_FILES, 15)

    left = margin + 54
    draw.text((left, 92), NAME, font=serif, fill=pal.ink)
    draw.text((left + 4, 202), TAGLINE, font=sans, fill=pal.ink_soft)
    draw.text((left + 4, 240),
              "It decides with a local model, fixes what it can undo, "
              "and puts back anything that made the machine worse.",
              font=small, fill=pal.muted)

    # The three programs as a line of type rather than three boxes. What
    # separates them is a sentence, so it is set as one.
    rule_y = 294
    draw.line([(left + 4, rule_y), (left + 640, rule_y)], fill=pal.rule, width=1)
    draw.text((left + 4, rule_y + 15),
              "TERMINAL    DESKTOP    FREEHAND", font=tiny, fill=pal.brass)
    draw.text((left + 4, rule_y + 37),
              "the third has no catalogue - the model writes every fix itself",
              font=tiny, fill=pal.muted)

    watch_x, watch_w = width - margin - 330, 268
    draw_watch(draw, pal, watch_x, 108, watch_w, 116)
    draw.text((watch_x, 238), "THE WATCH", font=small, fill=pal.brass)
    draw.text((watch_x, 262), "one column per cycle, brass is what it closed",
              font=tiny, fill=pal.muted)
    draw.text((watch_x, 283), "the floor is what needs a person",
              font=tiny, fill=pal.muted)

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / filename
    image.save(path)
    return path


def icon(pal: Palette = LIGHT) -> Path:
    """A square mark: the Watch reduced to five columns.

    Always light. This becomes lares.ico, and a Windows taskbar icon has no
    way to follow the reader's colour scheme.
    """
    size = 512
    image = Image.new("RGB", (size, size), pal.paper)
    draw = ImageDraw.Draw(image)

    inset = 44
    draw.rectangle([inset, inset, size - inset, size - inset],
                   fill=pal.card, outline=pal.rule, width=3)

    bars = [(1.0, 0.28), (0.74, 0.34), (0.5, 0.4), (0.34, 0.22), (0.28, 0.0)]
    bar_width, gap = 46, 22
    total = len(bars) * bar_width + (len(bars) - 1) * gap
    x = (size - total) / 2
    base = size - inset - 64
    tallest = size - 2 * inset - 150

    for fraction, closed in bars:
        column = tallest * fraction
        draw.rectangle([x, base - column, x + bar_width, base], fill=pal.rule)
        if closed:
            draw.rectangle([x, base - column * closed, x + bar_width, base],
                           fill=pal.shine)
        x += bar_width + gap

    draw.rectangle([inset, base + 18, size - inset, base + 24], fill=pal.brass)

    path = OUT / "icon.png"
    image.save(path)
    for edge in (256, 128, 64, 32):
        image.resize((edge, edge), Image.LANCZOS).save(OUT / f"icon-{edge}.png")
    image.resize((256, 256), Image.LANCZOS).save(
        OUT / "lares.ico", format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    return path


if __name__ == "__main__":
    for palette, name in ((LIGHT, "banner.png"), (DARK, "banner-dark.png")):
        print(f"  {banner(palette, name).relative_to(ROOT)}")
    print(f"  {icon().relative_to(ROOT)}")
    print("  assets/icon-{256,128,64,32}.png, assets/lares.ico")
