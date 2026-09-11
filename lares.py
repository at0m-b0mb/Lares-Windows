#!/usr/bin/env python3
"""Lares - terminal application entry point.

    python lares.py run        one cycle: scan, decide, fix, verify
    python lares.py watch      run on a schedule until stopped
    python lares.py scan       look and report, change nothing
"""

import sys

from lares.cli.app import main

if __name__ == "__main__":
    sys.exit(main())
