"""The menu you get when you double-click lares.exe.

A console application launched from Explorer has a problem that the same
application run from a prompt does not: there is nobody there who typed a
command, and when it exits the window disappears before anything can be read.
The default behaviour of an argument parser in that situation - print a usage
block to stderr and exit 2 - is the worst possible outcome, because the window
closes too fast to see even that.

So when Lares is started with no arguments *and* it owns its console alone, it
shows this instead: a short account of the machine and a numbered list of the
things a person actually wants to do. Run it from a shell with arguments and
none of this happens; the ordinary command-line behaviour is untouched.

Detecting the difference is the one Windows-specific trick here.
``GetConsoleProcessList`` reports how many processes are attached to the
console. Launched from ``cmd`` or PowerShell the answer is two or more - the
shell and us. Launched by double-click, Windows makes a console just for this
process and the answer is one.
"""

from __future__ import annotations

import ctypes
import sys

from .. import logs
from ..catalog import loader
from ..version import NAME, TAGLINE, VERSION
from ..winsys import current_user, is_demo, is_elevated
from .render import Console


def owns_console_alone() -> bool:
    """True when this process was started by double-click rather than a shell.

    Returns False anywhere that cannot be determined, because the cost of being
    wrong in that direction is merely showing a usage block, whereas guessing
    "double-click" inside a script would hang a pipeline on a menu prompt.
    """
    if not sys.platform.startswith("win"):
        return False
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        buffer = (ctypes.c_uint32 * 8)()
        count = kernel32.GetConsoleProcessList(buffer, 8)
        return count == 1
    except (AttributeError, OSError):
        return False


def should_offer_menu(argv: list[str]) -> bool:
    """Whether to show the menu rather than parse arguments.

    The test used to require owning the console alone, on the theory that this
    distinguishes a double-click from a shell. It does not, on Windows 11:
    when Windows Terminal is the default console host it hosts the process
    through ConPTY and is itself attached, so the count is two and a
    double-clicked executable fell through to an argparse usage block - the
    exact outcome the menu exists to replace.

    So the test is now simply: no command was given, and there is a person
    there to read the answer. Someone who types `lares` with nothing after it
    wants to know what it can do, and a numbered list answers that better than
    a usage line does. Anything non-interactive - a pipe, a redirect, a
    scheduled task, CI - still gets the ordinary argument parsing, because a
    menu prompt would hang there forever.
    """
    if argv:
        return False
    # A closed or detached stdin raises rather than answering, and in a frozen
    # build that is not rare, so it counts as "nobody is there".
    try:
        if sys.stdin is None or not sys.stdin.isatty():
            return False
    except (ValueError, OSError, AttributeError):
        return False
    try:
        return sys.stdout is not None and sys.stdout.isatty()
    except (ValueError, OSError, AttributeError):
        return False


# --------------------------------------------------------------------------
# The menu
# --------------------------------------------------------------------------

ITEMS: list[tuple[str, str, list[str]]] = [
    ("Check this machine",
     "Look at everything and report, changing nothing.",
     ["scan"]),
    ("Show what it would do",
     "The plan for this machine, and the reasoning behind each step.",
     ["plan"]),
    ("Fix what it can, now",
     "One full cycle: check, decide, apply, verify, record.",
     ["run"]),
    ("Keep working in the background",
     "Run cycles on a schedule until you stop it.",
     ["watch"]),
    ("What has it changed?",
     "Every change made to this machine, and how to put one back.",
     ["journal"]),
    ("Recent activity",
     "The running account of what Lares has been doing.",
     ["logs"]),
    ("Anything failed?",
     "Failures, each with a full report you can quote.",
     ["errors"]),
    ("What did the model say?",
     "Every exchange, and which of its choices were accepted.",
     ["transcript"]),
    ("Browse the controls",
     "The thirty checks, including the ones it will not touch.",
     ["controls"]),
    ("Can this machine run it?",
     "What is present, what is missing, and what to do about it.",
     ["doctor"]),
    ("Settings",
     "How much it is allowed to do, and how often.",
     ["config"]),
]


def _header(console: Console) -> None:
    console.rule(f"{NAME} {VERSION}")
    console.paragraph(TAGLINE)
    console.blank()

    try:
        catalog = loader.load()
        controls = f"{len(catalog)} controls"
    except loader.CatalogError as exc:
        controls = f"catalogue unreadable ({exc})"

    console.field("Account", current_user())
    console.field("Rights", "administrator" if is_elevated() else "standard user")
    console.field("Checks", controls)
    if is_demo():
        console.blank()
        console.warn("Demo mode: the data is synthetic and nothing will be changed.")
    elif not is_elevated():
        console.blank()
        console.warn("Not running as administrator, so nothing can be fixed yet.")
        console.advice(
            "Close this, right-click lares.exe and choose 'Run as administrator' "
            "to let it apply fixes. Checking and reporting work either way.",
            indent=2)


def _menu(console: Console) -> None:
    console.blank()
    console.section("What would you like to do?")
    for index, (title, blurb, _) in enumerate(ITEMS, start=1):
        console.field(f"  {index}", title)
        console.detail(blurb)
    console.blank()
    console.field("  q", "Quit")
    console.blank()


def run(console: Console, dispatch) -> int:
    """Show the menu until the user leaves.

    *dispatch* takes a list of command-line arguments and runs them, which is
    how every menu entry is served: the menu is a front end onto the same
    commands, not a second implementation of them.
    """
    log = logs.get()
    log.info("cli", "Started from Explorer; showing the menu")

    _header(console)

    while True:
        _menu(console)
        try:
            choice = input("  Choose a number, or q to quit: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.blank()
            return 0

        if choice in ("q", "quit", "exit", ""):
            console.blank()
            console.dim("Closing.")
            return 0

        if not choice.isdigit() or not 1 <= int(choice) <= len(ITEMS):
            console.blank()
            console.warn(f"'{choice}' is not one of the numbers above.")
            continue

        title, _, argv = ITEMS[int(choice) - 1]
        console.blank()
        console.rule(title)
        try:
            dispatch(argv)
        except KeyboardInterrupt:
            console.blank()
            console.dim("Stopped.")
        except Exception as exc:  # noqa: BLE001 - the menu must survive anything
            report = log.error("cli", f"{title} failed from the menu", exc=exc,
                               argv=" ".join(argv))
            console.error(f"That did not work: {exc}")
            console.detail(f"Saved as {report.error_id}; see it under 'Anything failed?'")

        console.blank()
        try:
            input("  Press Enter to go back to the menu: ")
        except (EOFError, KeyboardInterrupt):
            return 0


def pause_before_closing(console: Console) -> None:
    """Hold the window open so a double-clicked run can be read.

    Only called when the console belongs to us alone; from a shell there is
    nothing to hold open and prompting would be an irritation.
    """
    if not owns_console_alone():
        return
    try:
        console.blank()
        input("  Press Enter to close: ")
    except (EOFError, KeyboardInterrupt):
        pass
