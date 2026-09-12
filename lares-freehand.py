#!/usr/bin/env python3
"""Entry point for the Freehand executable.

Kept as a separate script, and a separate binary, because the difference
between it and lares.exe is not a setting. In lares.exe the model chooses from
remediations a person wrote; here it writes them. Someone should have to pick
up a different program to get that, rather than discover it behind a flag.
"""

from lares.cli.freehand import main

if __name__ == "__main__":
    raise SystemExit(main())
