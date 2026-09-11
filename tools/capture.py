#!/usr/bin/env python3
"""Render every page of the desktop application, in both themes, to PNG.

Runs offscreen, so it works in CI and over SSH with no display attached. Uses
demo data, so the screenshots are reproducible and contain nobody's real machine.

    python tools/capture.py
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("LARES_DEMO", "1")
# Keep the capture away from a real journal or settings file.
os.environ.setdefault("XDG_DATA_HOME", str(ROOT / "build" / "capture-state"))
os.environ.setdefault("LOCALAPPDATA", str(ROOT / "build" / "capture-state"))

from PyQt6.QtWidgets import QApplication  # noqa: E402

from lares.config import Settings  # noqa: E402
from lares.gui.main_window import PAGES, Window  # noqa: E402
from lares.gui.theme import Mode  # noqa: E402

OUT = ROOT / "assets" / "screenshots"
STATE = ROOT / "build" / "capture-state"


def capture() -> list[Path]:
    # Start from nothing, or every run appends more cycles to the Watch and the
    # screenshots stop being reproducible.
    shutil.rmtree(STATE, ignore_errors=True)

    app = QApplication(sys.argv)
    OUT.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    window = Window(Settings(theme="light"), autostart=False)
    window.resize(1180, 800)
    window.show()

    # Three cycles, so the Watch has a real shape to draw rather than one bar -
    # the backlog coming down is the whole point of that element.
    for _ in range(3):
        cycle = window.agent.run_cycle()
        window.on_cycle(cycle)
    window.page_catalogue.show_detail()
    app.processEvents()

    for choice, mode in (("light", Mode.LIGHT), ("dark", Mode.DARK)):
        window.mode = mode
        window.apply_theme()
        window.page_catalogue.fill()
        window.page_catalogue.show_detail()
        app.processEvents()

        for index, name in enumerate(PAGES):
            window._show_page(index)
            app.processEvents()
            path = OUT / f"{index + 1:02d}-{name.lower()}-{choice}.png"
            window.grab().save(str(path))
            written.append(path)
            print(f"  {path.relative_to(ROOT)}")

    return written


if __name__ == "__main__":
    print("Capturing the desktop application:")
    files = capture()
    print(f"\n{len(files)} screenshots written to {OUT.relative_to(ROOT)}")
