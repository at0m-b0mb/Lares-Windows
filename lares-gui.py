#!/usr/bin/env python3
"""Lares - desktop application entry point.

Starts the agent and opens a window onto it. The agent runs whether the window
is looked at or not; closing the window stops this instance.
"""

import sys


def main() -> int:
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("The desktop application needs PyQt6:\n\n    pip install PyQt6\n")
        print("The terminal application needs nothing extra:\n\n    python lares.py run\n")
        return 1

    from lares import config
    from lares.gui.main_window import Window
    from lares.version import NAME
    from lares.winsys import set_demo

    if "--demo" in sys.argv:
        set_demo(True)

    app = QApplication(sys.argv)
    app.setApplicationName(NAME)
    app.setApplicationDisplayName(NAME)

    window = Window(config.load(), autostart="--no-start" not in sys.argv)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
