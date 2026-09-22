"""State files that survive being interrupted.

Every loader in Lares treats an unparseable state file as "use the defaults",
which is the right call for a tool that must keep running. It also means a
half-written file is not an error - it is a silent reset. For the circuit
breaker that is the dangerous case: the default for `tripped` is False, so a
torn breaker.json re-arms autonomy on the machine that had just halted itself.
"""

from __future__ import annotations

import json

import pytest

from lares import config as config_mod
from lares.autonomy import breaker as breaker_mod
from lares.autonomy.breaker import Breaker, State
from lares.winsys import read_json, write_json_atomic


# --------------------------------------------------------------------------
# The writer
# --------------------------------------------------------------------------

def test_a_written_file_reads_back(tmp_path):
    path = tmp_path / "state.json"
    assert write_json_atomic(path, {"tripped": True, "count": 3})
    assert read_json(path) == {"tripped": True, "count": 3}


def test_no_temporary_file_is_left_behind(tmp_path):
    path = tmp_path / "state.json"
    write_json_atomic(path, {"a": 1})
    assert list(tmp_path.iterdir()) == [path]


def test_an_unwritable_location_reports_failure_rather_than_raising(tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")
    assert write_json_atomic(blocker / "state.json", {"a": 1}) is False


def test_unserialisable_content_fails_without_destroying_the_old_file(tmp_path):
    path = tmp_path / "state.json"
    write_json_atomic(path, {"good": True})
    assert write_json_atomic(path, {"bad": object()}) is False
    # The point of writing to a sibling first: the previous state is intact.
    assert read_json(path) == {"good": True}


def test_read_json_returns_the_default_for_a_torn_file(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"tripped": tr', encoding="utf-8")
    assert read_json(path, default={"fallback": True}) == {"fallback": True}


# --------------------------------------------------------------------------
# The breaker on top of it
# --------------------------------------------------------------------------

def test_a_tripped_breaker_survives_a_reload(tmp_path, monkeypatch):
    monkeypatch.setattr(breaker_mod, "_path", lambda: tmp_path / "breaker.json")

    first = Breaker(threshold=2)
    first.trip("a change could not be undone")
    assert first.open

    assert Breaker(threshold=2).open, "the halt must outlive the process"


def test_a_breaker_file_of_the_wrong_shape_does_not_crash(tmp_path, monkeypatch):
    path = tmp_path / "breaker.json"
    monkeypatch.setattr(breaker_mod, "_path", lambda: path)
    path.write_text('["not", "a", "mapping"]', encoding="utf-8")

    assert Breaker(threshold=2).open is False


def test_a_breaker_file_with_unknown_keys_keeps_the_ones_it_knows(tmp_path, monkeypatch):
    path = tmp_path / "breaker.json"
    monkeypatch.setattr(breaker_mod, "_path", lambda: path)
    path.write_text(json.dumps({"tripped": True, "reason": "x", "from_the_future": 1}),
                    encoding="utf-8")

    assert Breaker(threshold=2).open is True


def test_the_written_breaker_file_is_complete_json(tmp_path, monkeypatch):
    """The property the atomic write buys: never a fragment on disk."""
    path = tmp_path / "breaker.json"
    monkeypatch.setattr(breaker_mod, "_path", lambda: path)

    breaker = Breaker(threshold=2)
    breaker.trip("halted")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["tripped"] is True
    assert set(State().__dataclass_fields__) <= set(payload)


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

def test_settings_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "path", lambda: tmp_path / "settings.json")

    settings = config_mod.Settings(ceiling="safe", budget=3, excluded=["NET-003"])
    assert config_mod.save(settings)

    back = config_mod.load()
    assert back.ceiling == "safe"
    assert back.budget == 3
    assert back.excluded == ["NET-003"]


def test_a_torn_settings_file_falls_back_to_defaults_without_raising(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    monkeypatch.setattr(config_mod, "path", lambda: path)
    path.write_text('{"ceiling": "saf', encoding="utf-8")

    assert config_mod.load().ceiling == "caution"


def test_saving_clamps_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "path", lambda: tmp_path / "settings.json")
    config_mod.save(config_mod.Settings(budget=9999))
    assert config_mod.load().budget == 8


# --------------------------------------------------------------------------
# A settings file somebody edited by hand
# --------------------------------------------------------------------------

BADLY_TYPED = [
    ({"budget": None}, "budget", 8),
    ({"budget": "eight"}, "budget", 8),
    ({"budget": True}, "budget", 8),
    ({"ceiling": 3}, "ceiling", "caution"),
    ({"theme": None}, "theme", "auto"),
    ({"excluded": "NET-003"}, "excluded", []),
    ({"domains": None}, "domains", []),
    ({"dry_run": "yes"}, "dry_run", False),
    ({"interval_minutes": []}, "interval_minutes", 240),
    ({"breaker_threshold": "two"}, "breaker_threshold", 2),
]


@pytest.mark.parametrize("payload,field,expected", BADLY_TYPED)
def test_a_hand_edited_settings_file_does_not_crash_the_application(
        payload, field, expected, tmp_path, monkeypatch):
    """The defence against a bad settings file used to crash on one.

    validate() clamped values that were out of range and assumed every value
    had the right type, so `{"budget": null}` - a far likelier edit than
    `{"budget": 9999}` - raised TypeError comparing None to an int. In the
    CLI and in the desktop application, at startup, with a traceback instead
    of the fallback this promises.
    """
    path = tmp_path / "settings.json"
    monkeypatch.setattr(config_mod, "path", lambda: path)
    path.write_text(json.dumps(payload), encoding="utf-8")

    settings = config_mod.load()
    assert getattr(settings, field) == expected


@pytest.mark.parametrize("payload,field,expected", BADLY_TYPED)
def test_every_correction_is_reported_rather_than_made_silently(
        payload, field, expected):
    """Someone who typed it should be told it did not take."""
    settings = config_mod.Settings(**payload)
    corrections = settings.validate()
    assert any(field in c for c in corrections), corrections


def test_a_true_is_not_accepted_as_a_number():
    """bool subclasses int, so a naive isinstance check passes and True
    silently becomes a budget of 1."""
    settings = config_mod.Settings(budget=True)
    settings.validate()
    assert settings.budget == 8


def test_a_good_settings_file_is_left_entirely_alone():
    settings = config_mod.Settings(ceiling="safe", budget=3, theme="dark",
                                   excluded=["NET-003"], dry_run=True)
    assert settings.validate() == []
    assert (settings.ceiling, settings.budget, settings.theme) == ("safe", 3, "dark")


def test_the_desktop_application_starts_on_a_hand_edited_file(tmp_path, monkeypatch, qt_app):
    """Both front doors read this file at startup, so both must survive it."""
    pytest.importorskip("PyQt6.QtWidgets")
    from lares.gui.main_window import Window

    path = tmp_path / "settings.json"
    monkeypatch.setattr(config_mod, "path", lambda: path)
    path.write_text('{"budget": null, "theme": 7}', encoding="utf-8")

    window = Window(config_mod.load(), autostart=False)
    assert window.settings.budget == 8
