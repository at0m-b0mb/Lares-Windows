"""The window must not vanish.

Someone who double-clicks lares.exe has no shell to print into and no scrollback
to read afterwards. If anything goes wrong before the first prompt appears, the
console closes faster than a person can see why - which is the exact failure the
menu was built to prevent, and which the menu itself suffered from because the
guard was inside it rather than around it.

So: nothing reaches the top of main() uncaught, and when this process owns its
console the exit is always held open.
"""

from __future__ import annotations

import pytest

from lares.cli import app, interactive


@pytest.fixture(autouse=True)
def _own_the_console(monkeypatch, tmp_path):
    """Pretend to have been double-clicked, and count the holds."""
    from lares import logs
    logs.configure(directory=tmp_path / "logs")

    held: list[int] = []
    monkeypatch.setattr(interactive, "owns_console_alone", lambda: True)
    monkeypatch.setattr(interactive, "pause_before_closing",
                        lambda *a, **k: held.append(1))
    return held


# --------------------------------------------------------------------------
# Nothing escapes
# --------------------------------------------------------------------------

def test_a_crash_on_the_menu_path_does_not_escape(monkeypatch, _own_the_console):
    """This is the bug: interactive.run() was called outside every handler.

    Called as the real entry point does - main() with no argument - because
    that is what marks a top-level invocation and therefore what holds the
    window open afterwards.
    """
    monkeypatch.setattr("sys.argv", ["lares"])
    monkeypatch.setattr(interactive, "should_offer_menu", lambda argv: True)
    monkeypatch.setattr(interactive, "run",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    assert app.main() == 1
    assert _own_the_console, "the window must be held open after a crash"


def test_a_crash_is_written_to_the_log_with_an_id(monkeypatch, capsys, _own_the_console):
    from lares import logs
    monkeypatch.setattr("sys.argv", ["lares"])
    monkeypatch.setattr(interactive, "should_offer_menu", lambda argv: True)
    monkeypatch.setattr(interactive, "run",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    app.main()

    reports = logs.get().errors()
    assert reports, "a crash must leave a report behind"
    assert reports[0].error_id in capsys.readouterr().out


def test_an_unknown_command_still_holds_the_window(monkeypatch, _own_the_console):
    """argparse raises SystemExit after printing usage; that must not slip past
    the hold, or the usage message is invisible to whoever needs it."""
    monkeypatch.setattr("sys.argv", ["lares", "definitely-not-a-command"])
    with pytest.raises(SystemExit):
        app.main()

    assert _own_the_console


def test_no_command_at_all_holds_the_window(monkeypatch, _own_the_console):
    monkeypatch.setattr("sys.argv", ["lares"])
    monkeypatch.setattr(interactive, "should_offer_menu", lambda argv: False)

    with pytest.raises(SystemExit):
        app.main()

    assert _own_the_console


def test_an_interrupt_is_not_a_crash(monkeypatch, _own_the_console):
    monkeypatch.setattr("sys.argv", ["lares"])
    monkeypatch.setattr(interactive, "should_offer_menu", lambda argv: True)
    monkeypatch.setattr(interactive, "run",
                        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))

    assert app.main() == 130


# --------------------------------------------------------------------------
# The menu re-enters main; those calls must not each stop for a keypress
# --------------------------------------------------------------------------

def test_a_nested_call_from_the_menu_does_not_pause(monkeypatch, _own_the_console):
    """The menu already asks "press Enter to go back". A second hold per item
    would make every menu action need two keypresses."""
    monkeypatch.setattr(interactive, "should_offer_menu", lambda argv: False)

    app.main(["--demo", "--plain", "doctor"])

    assert not _own_the_console, "a nested call must not hold the window"


def test_the_real_entry_point_does_pause(monkeypatch, _own_the_console):
    monkeypatch.setattr(interactive, "should_offer_menu", lambda argv: False)
    monkeypatch.setattr("sys.argv", ["lares", "--demo", "--plain", "doctor"])

    app.main()          # argv=None marks the real entry point

    assert _own_the_console


# --------------------------------------------------------------------------
# When to offer the menu at all
# --------------------------------------------------------------------------

def test_arguments_mean_no_menu(monkeypatch):
    monkeypatch.setattr(interactive, "owns_console_alone", lambda: True)
    assert interactive.should_offer_menu(["scan"]) is False


def test_a_shell_launch_means_no_menu(monkeypatch):
    monkeypatch.setattr(interactive, "owns_console_alone", lambda: False)
    assert interactive.should_offer_menu([]) is False


def test_an_unusable_stdin_means_no_menu(monkeypatch):
    """A frozen build can have a stdin that raises rather than answering.
    Blocking on input() there would hang with nothing on screen."""
    class Hostile:
        def isatty(self):
            raise ValueError("I/O operation on closed file")

    monkeypatch.setattr(interactive, "owns_console_alone", lambda: True)
    monkeypatch.setattr("sys.stdin", Hostile())
    assert interactive.should_offer_menu([]) is False


def test_a_missing_stdin_means_no_menu(monkeypatch):
    monkeypatch.setattr(interactive, "owns_console_alone", lambda: True)
    monkeypatch.setattr("sys.stdin", None)
    assert interactive.should_offer_menu([]) is False
