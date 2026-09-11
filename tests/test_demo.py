"""The narrated walkthrough.

Its whole value is that the artefacts are real - the prompt shown is the
prompt sent, the script shown is the script that would run. So the tests check
that it stays honest, and that its recorded model reply is genuinely usable
input rather than something hand-waved.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from lares.brain.engine import extract_json
from lares.catalog import loader
from lares.cli import demo as demo_mod
from lares.cli.render import Console

CATALOG = loader.load()


@pytest.fixture
def console():
    return Console(plain=True)


# --------------------------------------------------------------------------
# The recorded reply
# --------------------------------------------------------------------------

def test_the_recorded_reply_is_valid_json():
    """It is fed through the real parser, so it has to survive it. An earlier
    draft had literal newlines inside JSON strings and the demo failed at its
    own stage four."""
    assert json.loads(demo_mod.RECORDED_REPLY)


def test_the_recorded_reply_survives_the_real_parser():
    parsed = extract_json(demo_mod.RECORDED_REPLY)
    assert parsed is not None
    assert parsed["actions"]


def test_the_recorded_reply_names_controls_that_exist():
    parsed = json.loads(demo_mod.RECORDED_REPLY)
    for action in parsed["actions"]:
        assert action["control_id"] in CATALOG, (
            "an action in the recorded reply must be applicable, or stage five "
            "has nothing real to show")


def test_the_recorded_reply_keeps_one_genuine_mistake():
    """A demonstration where the model never errs teaches the wrong lesson
    about what the guard is for."""
    parsed = json.loads(demo_mod.RECORDED_REPLY)
    invented = [cid for cid in parsed.get("deferred", {}) if cid not in CATALOG]
    assert invented, "the recorded reply should still contain an invented id"


def test_the_recorded_actions_are_actually_applicable():
    """Stage five renders real PowerShell from the first accepted action, so
    that action must be one the guard will clear."""
    from lares.act.guard import Context, clear_to_run
    from lares.core import RiskTier

    parsed = json.loads(demo_mod.RECORDED_REPLY)
    ctx = Context(elevated=True, ceiling=RiskTier.CAUTION, autonomous=True)
    first = CATALOG.require(parsed["actions"][0]["control_id"])

    assert first.has_remediation
    assert clear_to_run(first, {}, ctx) == {}


# --------------------------------------------------------------------------
# The walkthrough itself
# --------------------------------------------------------------------------

def test_it_runs_end_to_end_without_a_model(console, capsys):
    code = demo_mod.run(Namespace(recorded=True), console, CATALOG)
    out = capsys.readouterr().out

    assert code == 0
    for stage in ("What it reads off the machine",
                  "What it asks the model",
                  "What the model answers",
                  "What the guard makes of it",
                  "The exact PowerShell that would run",
                  "Applying it",
                  "What gets written down"):
        assert stage in out, f"stage missing: {stage}"


def test_it_shows_the_real_script_not_a_paraphrase(console, capsys):
    demo_mod.run(Namespace(recorded=True), console, CATALOG)
    out = capsys.readouterr().out

    # The exact text of the control's own remediation must appear.
    assert "EnableMulticast" in out
    assert "Remove-ItemProperty" in out, "the undo should be shown beside it"


def test_it_shows_the_guard_refusing_the_invented_control(console, capsys):
    demo_mod.run(Namespace(recorded=True), console, CATALOG)
    out = capsys.readouterr().out

    assert "SYS-006" in out
    assert "not in the catalogue" in out


def test_it_changes_nothing(console, capsys):
    """Stage six is a dry run. A walkthrough that edits the machine would be a
    poor thing to hand somebody who is still deciding whether to trust it."""
    demo_mod.run(Namespace(recorded=True), console, CATALOG)
    out = capsys.readouterr().out

    assert "simulated" in out
    assert "changed nothing" in out


def test_it_reports_whether_the_prompt_fits(console, capsys):
    demo_mod.run(Namespace(recorded=True), console, CATALOG)
    out = capsys.readouterr().out

    assert "Context window" in out
    assert "fits" in out or "OVERFLOWS" in out
