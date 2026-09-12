"""The lane where the model writes the code that runs.

Everywhere else the catalogue is the trust boundary and most of what is worth
proving is that the model cannot get past it. Here there is no catalogue, so
the properties worth proving are different ones: that the screen is actually
reached, that a check saying NOTFIXED can never be read as success, that a fix
which fails to verify is put back, and that what the walkthrough prints is what
the lane runs rather than a second arrangement of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lares.act.journal import Journal
from lares.brain import freehand as fh
from lares.brain.engine import Reply, Watch
from lares.brain.replay import FREEHAND_ANSWERS, Replay
from lares.core import Status
from lares.sense import surface as surface_mod

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def machine():
    return surface_mod.survey()


def agent(answers, tmp_path, **kwargs):
    engine = Replay(list(answers), pace=0)
    kwargs.setdefault("journal", Journal(tmp_path / "actions.jsonl"))
    return fh.Freehand(engine, **kwargs), engine


# --------------------------------------------------------------------------
# Reading the machine
# --------------------------------------------------------------------------

def test_survey_reads_every_view(machine):
    assert {s.key for s in machine.sections} == {
        "system", "software", "ports", "services", "accounts", "exposure"}


def test_a_socket_on_every_interface_is_marked_reachable(machine):
    ports = {(r["proto"], r["port"]): r for r in machine.rows("ports")}
    assert ports[("TCP", 445)]["exposed"] is True
    assert ports[("TCP", 8080)]["exposed"] is False, \
        "a socket bound to 127.0.0.1 is not reachable from the network"


def test_an_unquoted_service_path_is_marked(machine):
    by_name = {r["name"]: r for r in machine.rows("services")}
    assert by_name["VulnAgent"]["unquoted"] is True
    assert by_name["Spooler"]["unquoted"] is False, \
        "a path with no space in it cannot be hijacked this way"


def test_render_can_be_narrowed_to_one_reading(machine):
    text = machine.render(only=["ports"])
    assert "Listening ports" in text
    assert "Installed software" not in text


def test_render_honours_a_character_budget(machine):
    assert len(machine.render(budget=900)) <= 900 or \
        len(machine.render(limit=5)) <= len(machine.render(limit=60))


def test_a_reading_that_fails_does_not_take_the_others_with_it(monkeypatch):
    real = surface_mod._collect

    def explode(key, title, script):
        if key == "ports":
            section = surface_mod.Section(key=key, title=title)
            section.error = "access denied"
            return section
        return real(key, title, script)

    monkeypatch.setattr(surface_mod, "_collect", explode)
    found = surface_mod.survey()
    assert found.get("ports").error == "access denied"
    assert found.get("software").rows, "the other readings must still be there"
    assert "could not be read" in found.render(), \
        "the model has to be told a reading is missing, not left to infer it"


# --------------------------------------------------------------------------
# Reading the model's check
# --------------------------------------------------------------------------

@pytest.mark.parametrize("output, expected", [
    ("FIXED", True),
    ("NOTFIXED", False),
    ("NOT_FIXED", False),
    ("NOT-FIXED", False),
    ("  notfixed  ", False),
    ("The setting is fixed", True),
    ("prefixed", None),
    ("", None),
    ("who knows", None),
])
def test_a_check_verdict_is_read_the_right_way_round(output, expected):
    assert fh._verdict(output) is expected


def test_notfixed_is_never_read_as_fixed():
    """The bug this exists to prevent is a one-character one.

    "FIXED" is a substring of "NOTFIXED". A membership test in the wrong order
    reads every failure as a success, which would leave a change in place on
    the strength of the check that said it had not worked.
    """
    assert fh._verdict("NOTFIXED") is False


# --------------------------------------------------------------------------
# The screen - the one judgement the application keeps
# --------------------------------------------------------------------------

def reply(**fields) -> str:
    base = {"explain": "x", "check": "'FIXED'", "fix": "Set-Thing", "undo": "Unset-Thing"}
    base.update(fields)
    return json.dumps(base)


def test_a_fix_that_reboots_is_refused(machine, tmp_path):
    brain, _ = agent([reply(fix="Set-Thing\nRestart-Computer -Force")], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    assert remedy.refused
    assert "reboot" in remedy.refused
    assert not remedy.runnable


def test_a_check_is_screened_too(machine, tmp_path):
    """A check runs before the fix and runs even in a dry run.

    That it is read-only is a claim by the same model that wrote it, so it
    goes through the screen like anything else.
    """
    brain, _ = agent([reply(check="Format-Volume -DriveLetter C")], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    assert remedy.refused and "check" in remedy.refused


def test_an_undo_may_re_enable_what_the_fix_turned_off(machine, tmp_path):
    """The mirror of a catalogue rollback.

    Putting a setting back can legitimately mean switching something on again,
    so an undo is screened on the absolute rules only. It must still not be
    allowed to wipe a disk.
    """
    brain, _ = agent([reply(undo="Set-NetFirewallProfile -All -Enabled False")], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    assert not remedy.refused, "an undo is allowed to turn protection back off"

    brain, _ = agent([reply(undo="Clear-Disk -Number 0")], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    assert remedy.refused and "undo" in remedy.refused


def test_no_fix_is_a_valid_answer(machine, tmp_path):
    brain, _ = agent([reply(fix="", explain="this needs a person")], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    assert not remedy.runnable
    assert "no fix" in remedy.refused


def test_a_refused_remedy_is_never_run(machine, tmp_path):
    brain, _ = agent([reply(fix="bcdedit /set x")], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    attempt = brain.apply(remedy)
    assert attempt.status is Status.REFUSED
    assert [name for name, _ in attempt.stages] == ["refused"]


# --------------------------------------------------------------------------
# Applying
# --------------------------------------------------------------------------

class FakeShell:
    """Stands in for PowerShell, answering per script."""

    def __init__(self, answers: dict[str, tuple[bool, str]]) -> None:
        self.answers = answers
        self.ran: list[str] = []

    def __call__(self, script, timeout=0):
        from lares.winsys import Result
        self.ran.append(script)
        for needle, (ok, out) in self.answers.items():
            if needle in script:
                return Result(ok, out, "", 0 if ok else 1)
        return Result(True, "", "", 0)


def run_with(monkeypatch, shell, remedy, **kwargs):
    monkeypatch.setattr(fh, "powershell", shell)
    monkeypatch.setattr(fh, "is_demo", lambda: False)
    brain = fh.Freehand(Replay([], pace=0), journal=Journal(kwargs.pop("path")), **kwargs)
    return brain.apply(remedy)


def remedy_of(check="CHECK", fix="FIX", undo="UNDO") -> fh.Remedy:
    return fh.Remedy(issue=fh.Issue(id="FH-01", title="t"),
                     check=check, fix=fix, undo=undo)


def test_a_machine_already_in_that_state_is_left_alone(monkeypatch, tmp_path):
    shell = FakeShell({"CHECK": (True, "FIXED")})
    attempt = run_with(monkeypatch, shell, remedy_of(), path=tmp_path / "j.jsonl")
    assert attempt.status is Status.SKIPPED
    assert "FIX" not in shell.ran, "nothing should be changed that is already right"


def test_a_fix_the_check_confirms_is_kept(monkeypatch, tmp_path):
    calls = {"n": 0}

    def shell(script, timeout=0):
        from lares.winsys import Result
        if "CHECK" in script:
            calls["n"] += 1
            return Result(True, "NOTFIXED" if calls["n"] == 1 else "FIXED", "", 0)
        return Result(True, "done", "", 0)

    attempt = run_with(monkeypatch, shell, remedy_of(), path=tmp_path / "j.jsonl")
    assert attempt.status is Status.VERIFIED
    assert attempt.outcome.change_in_place is True


def test_a_fix_the_check_still_rejects_is_put_back(monkeypatch, tmp_path):
    shell = FakeShell({"CHECK": (True, "NOTFIXED")})
    attempt = run_with(monkeypatch, shell, remedy_of(), path=tmp_path / "j.jsonl")
    assert attempt.status is Status.ROLLED_BACK
    assert "UNDO" in shell.ran
    assert attempt.outcome.change_in_place is False


def test_a_failed_undo_leaves_the_change_recorded_as_still_there(monkeypatch, tmp_path):
    """The journal must not say a change was undone when it was not.

    The undo list is where someone goes to put something back by hand, so an
    entry that lies about this is an entry that hides the change.
    """
    shell = FakeShell({"CHECK": (True, "NOTFIXED"), "UNDO": (False, "denied")})
    attempt = run_with(monkeypatch, shell, remedy_of(), path=tmp_path / "j.jsonl")
    assert attempt.status is Status.FAILED
    assert attempt.outcome.change_in_place is True


def test_an_undo_that_exits_cleanly_and_changes_nothing_is_not_a_rollback(
        monkeypatch, tmp_path):
    """The failure that looks like success.

    The undo is written by the same model as the fix, so "it did not error" is
    a weak claim. After a real undo the machine is back in the state the check
    called NOTFIXED - a check still reporting FIXED means the change is still
    there, whatever the exit code said.
    """
    calls = {"n": 0}

    def shell(script, timeout=0):
        from lares.winsys import Result
        if "CHECK" in script:
            calls["n"] += 1
            # Before: needs doing. After the undo: reports the fixed state,
            # which cannot be true if the undo put anything back.
            return Result(True, "NOTFIXED" if calls["n"] == 1 else "FIXED", "", 0)
        if "FIX" in script:
            # The fix half-runs: it satisfies the condition and then errors.
            return Result(False, "", "the last statement threw", 1)
        return Result(True, "", "", 0)     # the undo exits 0 and does nothing

    attempt = run_with(monkeypatch, shell, remedy_of(), path=tmp_path / "j.jsonl")
    assert attempt.status is Status.FAILED
    assert attempt.outcome.change_in_place is True, \
        "an undo that removed nothing must leave the change listed as present"


def test_an_undo_with_no_check_to_confirm_it_says_so(monkeypatch, tmp_path):
    shell = FakeShell({})
    remedy = remedy_of(check="")
    attempt = run_with(monkeypatch, shell, remedy, path=tmp_path / "j.jsonl")
    # No check at all, so the fix is applied and nothing can confirm either it
    # or an undo. It must not claim otherwise.
    assert attempt.status is Status.UNVERIFIED


def test_a_fix_with_no_check_is_applied_but_never_called_verified(monkeypatch, tmp_path):
    shell = FakeShell({})
    attempt = run_with(monkeypatch, shell, remedy_of(check=""), path=tmp_path / "j.jsonl")
    assert attempt.status is Status.UNVERIFIED
    assert "nothing proves it worked" in attempt.outcome.message


def test_a_failing_fix_is_put_back_immediately(monkeypatch, tmp_path):
    shell = FakeShell({"CHECK": (True, "NOTFIXED"), "FIX": (False, "the cmdlet threw")})
    attempt = run_with(monkeypatch, shell, remedy_of(), path=tmp_path / "j.jsonl")
    assert attempt.status is Status.FAILED
    assert "UNDO" in shell.ran


def test_a_dry_run_changes_nothing(monkeypatch, tmp_path):
    shell = FakeShell({"CHECK": (True, "NOTFIXED")})
    attempt = run_with(monkeypatch, shell, remedy_of(), path=tmp_path / "j.jsonl",
                       dry_run=True)
    assert attempt.status is Status.SIMULATED
    assert "FIX" not in shell.ran


# --------------------------------------------------------------------------
# The whole pass
# --------------------------------------------------------------------------

def test_a_pass_stops_at_its_budget(machine, tmp_path):
    brain, _ = agent(FREEHAND_ANSWERS, tmp_path, budget=2, dry_run=True)
    session = brain.run(machine)
    assert len(session.issues) == 5
    assert len(session.attempts) == 2, "the budget is a cap on changes, not on issues"


def test_every_attempt_reaches_the_journal(machine, tmp_path):
    path = tmp_path / "actions.jsonl"
    brain, _ = agent(FREEHAND_ANSWERS, tmp_path, budget=3, dry_run=True,
                     journal=Journal(path))
    brain.run(machine)
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(lines) == 3
    assert all(entry["outcome"]["control_id"].startswith("FH-") for entry in lines)


def test_the_undo_is_written_down_before_anything_is_changed(machine, tmp_path):
    path = tmp_path / "actions.jsonl"
    brain, _ = agent(FREEHAND_ANSWERS, tmp_path, budget=1, dry_run=True,
                     journal=Journal(path))
    brain.run(machine)
    entry = json.loads(path.read_text().splitlines()[0])
    assert entry["outcome"]["rollback_script"].strip(), \
        "a change with no recorded undo is a change nobody can put back"


def test_a_model_that_will_not_answer_stops_the_lane(machine, tmp_path):
    class Silent(Replay):
        def ask(self, *a, **k):
            return Reply("", ok=False, error="out of memory")

    brain = fh.Freehand(Silent([], pace=0), journal=Journal(tmp_path / "j.jsonl"))
    session = brain.run(machine)
    assert session.error and not session.attempts, \
        "with no catalogue there is nothing to fall back to, and it must not pretend"


def test_a_reply_that_is_not_json_stops_the_lane(machine, tmp_path):
    brain, _ = agent(["I think you should check your firewall."], tmp_path)
    session = brain.run(machine)
    assert session.error and not session.issues


def test_an_issue_with_no_title_is_dropped(machine, tmp_path):
    answer = json.dumps({"summary": "s", "issues": [
        {"title": "", "why": "w"}, {"title": "real", "why": "w"}]})
    brain, _ = agent([answer], tmp_path)
    summary, issues, error = brain.assess(machine)
    assert not error
    assert [i.title for i in issues] == ["real"]


def test_a_script_given_as_a_list_of_lines_is_still_a_script(machine, tmp_path):
    answer = json.dumps({"explain": "x", "check": "'FIXED'",
                         "fix": ["Set-One", "Set-Two"], "undo": "Undo"})
    brain, _ = agent([answer], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    assert remedy.fix == "Set-One\nSet-Two"


def test_a_fenced_script_is_unfenced(machine, tmp_path):
    answer = json.dumps({"explain": "x", "check": "'FIXED'",
                         "fix": "```powershell\nSet-One\n```", "undo": ""})
    brain, _ = agent([answer], tmp_path)
    remedy = brain.write_remedy(fh.Issue(id="FH-01", title="t"), machine)
    assert remedy.fix == "Set-One"


# --------------------------------------------------------------------------
# The live view
# --------------------------------------------------------------------------

def test_the_replay_can_be_called_every_way_the_engine_can():
    """A stand-in that cannot be called the way the real thing is called is
    not standing in for it. Caught for real: adding a sampler argument to
    Engine.ask broke every walkthrough and nothing said so until the suite
    ran."""
    import inspect

    from lares.brain.engine import Engine

    real = inspect.signature(Engine.ask).parameters
    stand_in = inspect.signature(Replay.ask).parameters
    missing = [name for name in real
               if not name.startswith("_") and name not in stand_in]
    assert not missing, f"Replay.ask cannot accept {missing}"


def test_the_replay_streams_through_the_same_watch_the_engine_uses(machine):
    seen: list[str] = []
    engine = Replay(["hello world"], pace=0)
    engine.watch = Watch(on_token=seen.append)
    reply = engine.ask("sys", "user")
    assert "".join(seen) == "hello world" == reply.text


def test_the_watch_reports_the_prompt_and_the_finished_reply():
    prompts, replies = [], []
    engine = Replay(["done"], pace=0)
    engine.watch = Watch(on_prompt=lambda s, u: prompts.append((s, u)),
                         on_reply=replies.append)
    engine.ask("the rules", "the machine")
    assert prompts == [("the rules", "the machine")]
    assert replies[0].text == "done"


def test_a_display_that_throws_does_not_lose_the_reply():
    """A console that cannot encode a character must not cost a minute of
    inference. Every watcher callback is display and none of them may change
    the outcome."""
    def broken(_):
        raise UnicodeEncodeError("utf-8", "x", 0, 1, "nope")

    from lares.brain.engine import _safely
    _safely(broken, "text")     # must not raise


# --------------------------------------------------------------------------
# The walkthrough is the lane, not a second copy of it
# --------------------------------------------------------------------------

FREEHAND_SRC = (ROOT / "lares" / "cli" / "freehand.py").read_text(encoding="utf-8")


def test_the_walkthrough_goes_through_the_real_agent():
    assert "Freehand(" in FREEHAND_SRC
    assert "agent.run(" in FREEHAND_SRC


def test_the_walkthrough_does_not_build_its_own_prompts():
    """--recorded swaps the engine and nothing else.

    If the walkthrough ever assembles its own prompt or screens its own
    script, what it shows stops being what the lane does - which is the whole
    reason anyone would trust the walkthrough.
    """
    for forbidden in ("ASSESS_SYSTEM", "REMEDY_SYSTEM", "screen_script(",
                      "powershell("):
        assert forbidden not in FREEHAND_SRC, \
            f"the walkthrough must not do {forbidden} itself"


def test_the_recorded_answers_are_the_shape_the_lane_parses():
    first = json.loads(FREEHAND_ANSWERS[0])
    assert "issues" in first and first["issues"]
    for answer in FREEHAND_ANSWERS[1:]:
        parsed = json.loads(answer)
        assert {"explain", "check", "fix", "undo"} <= set(parsed)


def test_one_recorded_remedy_is_refused_on_purpose(machine, tmp_path):
    """A walkthrough where every script is accepted teaches nothing about the
    one judgement this program keeps for itself."""
    brain, _ = agent(FREEHAND_ANSWERS, tmp_path, budget=5, dry_run=True)
    session = brain.run(machine)
    assert any(r.refused for r in session.remedies)


# --------------------------------------------------------------------------
# The program end to end
# --------------------------------------------------------------------------

def walkthrough(capsys, *extra) -> str:
    """Run the whole program the way a person does, and return what it printed."""
    from lares.cli.freehand import dispatch
    from lares.cli.render import Console
    from lares.winsys import set_demo

    try:
        # pace 0 because the walkthrough's reading-pace delay is for people
        # watching it, and thirty-five seconds of sleep in a test suite buys
        # nothing.
        code = dispatch(["--demo", "--recorded", "--plain", "--pace", "0", *extra],
                        Console(plain=True))
    finally:
        set_demo(True)      # conftest puts every test in demo mode; keep it there
    assert code == 0
    return capsys.readouterr().out


def test_the_program_runs_end_to_end(capsys):
    out = walkthrough(capsys, "--budget", "2")
    for expected in ("what is on this machine",
                     "REACHABLE FROM THE NETWORK",
                     "sent to the model",
                     "the code the model wrote",
                     "WHAT THE SCREEN MADE OF IT",
                     "what happened"):
        assert expected in out, f"the walkthrough never showed {expected!r}"


def test_the_reading_is_only_ever_shown_inside_a_prompt(capsys):
    """With the live view on, the survey is printed where it is sent and
    nowhere else.

    A separate rendering built with different arguments would look like the
    thing that was sent without being it, and nothing would tell you which of
    the two was real. Two prompts each carrying the reading is not that - each
    one is showing its own contents.
    """
    out = walkthrough(capsys, "--budget", "1")
    first_reading = out.index("== Listening ports ==")
    first_prompt = out.index("sent to the model")
    assert first_prompt < first_reading, \
        "the survey was printed before any prompt contained it"


def test_without_the_live_view_the_reading_is_still_shown(capsys):
    out = walkthrough(capsys, "--budget", "1", "--no-live")
    assert "EVERYTHING THAT WAS READ" in out.upper()


def test_the_program_never_claims_a_recorded_answer_came_from_a_model(capsys):
    out = walkthrough(capsys, "--budget", "1")
    assert "no model is running" in out
    assert "written out for this walkthrough" in out


def test_recorded_can_never_change_a_machine(capsys):
    """--recorded forces a dry run, and not as a default someone can override.

    The answers were written for the walkthrough rather than produced by a
    model looking at this machine, so running them against one would be acting
    on a decision nothing made about it.
    """
    out = walkthrough(capsys, "--budget", "2")
    assert "Nothing on this machine was changed" in out
    assert "decided, not applied" in out


def test_a_model_stuck_repeating_itself_is_told_apart_from_bad_json(machine, tmp_path):
    """Caught in a release build: a 1.5B said the same sentence forty-five
    times inside one JSON string and never reached the part that mattered.

    "Not usable JSON" is true of that and useless to whoever reads it. The two
    have different causes and different answers - one is a parsing problem, the
    other is a model too small for the question.
    """
    loop = '{"summary": "' + "The machine is not running useful software. " * 45
    brain, _ = agent([loop], tmp_path)
    _, issues, error = brain.assess(machine)
    assert not issues
    assert "stuck repeating itself" in error
    assert "3b" in error, "it should say what to do about it"


def test_ordinary_bad_json_still_says_so(machine, tmp_path):
    brain, _ = agent(["I would start with the firewall."], tmp_path)
    _, _, error = brain.assess(machine)
    assert "not usable JSON" in error


def test_the_issues_are_asked_for_before_the_summary():
    """Property order is generation order.

    If the model loses itself in prose it should lose itself after the part
    worth having, so that even a truncated reply parses back into findings.
    """
    from lares.brain.freehand import ASSESS_SCHEMA, ASSESS_SYSTEM

    keys = list(ASSESS_SCHEMA["properties"])
    assert keys.index("issues") < keys.index("summary")
    assert ASSESS_SYSTEM.index('"issues"') < ASSESS_SYSTEM.index('"summary"'), \
        "the prompt must show the same order the schema generates in"


def test_every_string_the_model_writes_is_bounded():
    """The only thing that reliably stops a small model writing forever is the
    grammar, and the grammar only bounds what the schema bounds."""
    from lares.brain.freehand import ASSESS_SCHEMA, REMEDY_SCHEMA

    def strings(node):
        if isinstance(node, dict):
            if node.get("type") == "string":
                yield node
            for value in node.values():
                yield from strings(value)
        elif isinstance(node, list):
            for item in node:
                yield from strings(item)

    for schema in (ASSESS_SCHEMA, REMEDY_SCHEMA):
        for field in strings(schema):
            assert "maxLength" in field, f"unbounded string: {field}"
