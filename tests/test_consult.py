"""The model-led investigation.

Here the model chooses what to look at, not just what to fix. That inverts who
is driving, so the properties worth proving are about what it can and cannot
reach: it directs the investigation, and it still cannot invent either a check
or a remediation.
"""

from __future__ import annotations

import json


from lares.brain.consult import Consultant
from lares.brain.engine import Reply
from lares.catalog import loader
from lares.core import RiskTier

CATALOG = loader.load()


class ScriptedEngine:
    """A model whose answers are decided in advance."""

    name = "scripted"
    available = True
    status = "ready"
    spec = None          # a real Engine carries one; None means "assume 4096"

    def __init__(self, *answers) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def ask(self, system, user, **kwargs) -> Reply:
        self.prompts.append(user)
        if not self.answers:
            return Reply("", ok=False, error="ran out of scripted answers")
        answer = self.answers.pop(0)
        if isinstance(answer, Reply):
            return answer
        return Reply(json.dumps(answer), ok=True, tokens=50, seconds=1.0)


def consult(*answers, rounds=3, **kwargs):
    engine = ScriptedEngine(*answers)
    consultant = Consultant(CATALOG, engine, max_rounds=rounds)
    return consultant, consultant.run(ceiling=RiskTier.CAUTION, elevated=True,
                                      budget=8, **kwargs)


# --------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------

def test_it_runs_only_the_checks_the_model_asked_for():
    _, result = consult(
        {"ask": {"controls": ["NET-005", "IDN-005"]}, "why": "credential paths"},
        {"assessment": "two credential problems", "actions": []},
    )

    assert result.probes_run == 2
    assert set(result.rounds[0].probed) == {"NET-005", "IDN-005"}


def test_a_domain_request_runs_that_domain():
    _, result = consult(
        {"ask": {"domains": ["network"]}},
        {"assessment": "the network is exposed", "actions": []},
    )

    probed = set(result.rounds[0].probed)
    assert probed == {c.id for c in CATALOG.in_domain("network")}


def test_it_keeps_asking_until_it_concludes():
    _, result = consult(
        {"ask": {"facts": True}},
        {"ask": {"controls": ["NET-005"]}},
        {"assessment": "done looking", "actions": []},
    )

    assert len(result.rounds) == 3
    assert result.concluded


def test_the_same_check_is_not_run_twice():
    _, result = consult(
        {"ask": {"controls": ["NET-005"]}},
        {"ask": {"controls": ["NET-005", "IDN-005"]}},
        {"assessment": "done", "actions": []},
    )

    assert result.rounds[1].probed == ["IDN-005"]


def test_running_out_of_rounds_forces_a_verdict():
    consultant, result = consult(
        {"ask": {"controls": ["NET-005"]}},
        {"assessment": "I had to stop", "actions": []},
        rounds=2,
    )

    assert "last round" in consultant.engine.prompts[-1]


def test_a_model_that_never_concludes_changes_nothing():
    _, result = consult(
        {"ask": {"controls": ["NET-005"]}},
        {"ask": {"controls": ["IDN-005"]}},
        {"ask": {"controls": ["SYS-001"]}},
        rounds=3,
    )

    assert result.concluded is False
    assert result.plan.actions == []
    assert "did not reach a verdict" in result.plan.summary.lower()


# --------------------------------------------------------------------------
# What it cannot reach
# --------------------------------------------------------------------------

def test_it_cannot_ask_for_a_check_that_does_not_exist():
    _, result = consult(
        {"ask": {"controls": ["SYS-006", "SYS-007", "NET-005"]}},
        {"assessment": "done", "actions": []},
    )

    assert result.rounds[0].probed == ["NET-005"]


def test_it_cannot_ask_for_a_domain_that_does_not_exist():
    _, result = consult(
        {"ask": {"domains": ["quantum"]}},
        {"assessment": "done", "actions": []},
    )

    assert result.rounds[0].probed == []


def test_its_verdict_goes_through_the_ordinary_guard():
    """A model-led route must not be a looser path into the executor."""
    _, result = consult(
        {"ask": {"controls": ["NET-005"]}},
        {"assessment": "fix it",
         "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1},
                     {"control_id": "XXX-999", "rationale": "r", "order": 2}]},
    )

    assert [a.control_id for a in result.plan.actions] == ["NET-005"]


def test_it_cannot_act_on_something_it_never_looked_at():
    """Only findings from checks it requested are in the scan, so a control it
    never probed has nothing to act on."""
    _, result = consult(
        {"ask": {"controls": ["NET-005"]}},
        {"assessment": "fix everything",
         "actions": [{"control_id": "SYS-001", "rationale": "r", "order": 1}]},
    )

    assert all(a.control_id != "SYS-001" or a.params == {}
               for a in result.plan.actions)


def test_an_invented_deferral_is_not_displayed():
    _, result = consult(
        {"ask": {"controls": ["NET-005"]}},
        {"assessment": "done", "actions": [],
         "deferred": {"SYS-006": "the drive is not encrypted"}},
    )

    assert "SYS-006" not in result.plan.deferred


# --------------------------------------------------------------------------
# Failure
# --------------------------------------------------------------------------

def test_a_model_that_will_not_answer_stops_cleanly():
    _, result = consult(Reply("", ok=False, error="out of memory"))

    assert result.plan.actions == []
    assert "out of memory" in result.rounds[0].error


def test_unusable_json_stops_cleanly():
    _, result = consult(Reply("I think you should check the firewall", ok=True))

    assert result.plan.actions == []
    assert "not usable JSON" in result.rounds[0].error


def test_every_round_is_described_for_the_operator():
    _, result = consult(
        {"ask": {"controls": ["NET-005"]}, "why": "checking name resolution"},
        {"assessment": "done", "actions": []},
    )

    assert "NET-005" in result.rounds[0].describe()
    assert "verdict" in result.rounds[1].describe()


# --------------------------------------------------------------------------
# The transcript must not outgrow the window
#
# The consultation accumulates readings every round, so it is the shape most
# likely to overflow - and it overflows exactly when a verdict is demanded,
# which is the worst possible moment to lose the rules.
# --------------------------------------------------------------------------

def test_the_opening_is_never_dropped():
    """It carries the rules and the list of ids that actually exist."""
    from lares.brain.consult import _fit

    opening = "RULES: do not invent ids. Controls: NET-001 NET-002"
    readings = ["reading " + "x" * 500 for _ in range(20)]

    fitted = _fit([opening, *readings], 900)

    assert fitted.startswith(opening)
    assert "omitted to fit the context window" in fitted


def test_the_newest_readings_are_the_ones_kept():
    from lares.brain.consult import _fit

    parts = ["OPENING", "oldest " + "x" * 200, "middle " + "x" * 200,
             "newest " + "x" * 200]
    fitted = _fit(parts, len("OPENING") + 260)

    assert "newest" in fitted
    assert "oldest" not in fitted


def test_a_transcript_that_fits_is_left_alone():
    from lares.brain.consult import _fit

    parts = ["OPENING", "a reading", "another reading"]
    assert _fit(parts, 10_000) == "\n\n".join(parts)


def test_a_long_consultation_stays_inside_the_window():
    """Three rounds of a whole domain each, on the smallest window."""
    from lares.brain import prompt as prompt_mod
    from lares.brain.consult import ROUND_TOKENS, SYSTEM, _fit

    window = 2048
    budget = prompt_mod.budget_for(window, ROUND_TOKENS, SYSTEM)
    reply = prompt_mod.answer_room(window, ROUND_TOKENS)

    parts = ["OPENING " + "x" * 2000] + ["READING " + "y" * 3000 for _ in range(6)]
    body = _fit(parts, budget)

    needed = (prompt_mod.estimate_tokens(SYSTEM)
              + prompt_mod.estimate_tokens(body) + reply)
    assert needed <= window, f"overflows by {needed - window} tokens"
