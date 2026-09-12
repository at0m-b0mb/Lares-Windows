"""What the planner does with what the model says.

The model is a 1.5B-to-7B quantised local model. It will sometimes name a
control that does not exist, add a key nobody asked for, forget an item from a
list of twelve, or return prose where JSON was demanded. None of that may
result in a wrong change or a lost fix, so each of those shapes is exercised
here against a real catalogue.
"""

from __future__ import annotations

from lares.brain.engine import extract_json
from lares.brain.plan import Planner, builtin_plan
from lares.catalog import loader
from lares.core import Finding, RiskTier, Scan


CATALOG = loader.load()


def scan_with(*findings: Finding) -> Scan:
    scan = Scan()
    scan.findings = list(findings)
    return scan


def finding(control_id: str, **params) -> Finding:
    control = CATALOG.require(control_id)
    return Finding(control_id=control_id, title=control.title,
                   severity=control.severity, observed="something is wrong",
                   params=params)


def plan_from(raw: dict, scan: Scan, budget: int = 8):
    """Run the model-output validator without needing a model."""
    planner = Planner(CATALOG, engine=None)
    return planner, planner._validate(raw, scan, RiskTier.CAUTION, True, budget)


# --------------------------------------------------------------------------
# Hostile and sloppy model output
# --------------------------------------------------------------------------

def test_a_hallucinated_control_is_dropped():
    scan = scan_with(finding("NET-005"))
    planner, plan = plan_from(
        {"summary": "s", "actions": [{"control_id": "XXX-999", "rationale": "r", "order": 1}]},
        scan)

    assert "XXX-999" not in [a.control_id for a in plan.actions]
    assert any("not in the catalogue" in n.text for n in planner.notes)


def test_a_junk_parameter_does_not_block_a_fix_the_scan_already_solved():
    """The guard refuses undeclared parameters, and should. The planner must
    not hand it noise when the probe already supplied every real value."""
    scan = scan_with(finding("NET-003", port=3389, profile="Public"))
    planner, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-003", "rationale": "rdp is exposed",
                     "order": 1,
                     "params": {"port": 3389, "profile": "Public",
                                "reason": "hallucinated key"}}],
    }, scan)

    assert [a.control_id for a in plan.actions] == ["NET-003"]
    action = plan.actions[0]
    assert set(action.params) == {"port", "profile"}
    assert "reason" not in action.params
    assert any("does not take" in n.text for n in planner.notes)

    # And the surviving parameters really do pass the guard.
    from lares.act.guard import validate_params
    assert validate_params(CATALOG.require("NET-003"), action.params)


def test_the_scan_beats_the_model_on_discovered_values():
    """A measurement is a fact; the model's recollection of it is not."""
    scan = scan_with(finding("NET-003", port=3389, profile="Public"))
    _, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-003", "rationale": "r", "order": 1,
                     "params": {"port": 22, "profile": "Domain"}}],
    }, scan)

    assert plan.actions[0].params["port"] == 3389


def test_a_finding_the_model_forgot_is_added_anyway():
    """A generation artefact must not silently leave a critical fix unapplied."""
    scan = scan_with(finding("NET-005"), finding("IDN-005"))
    _, plan = plan_from(
        {"summary": "s", "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1}]},
        scan)

    assert {"NET-005", "IDN-005"} <= {a.control_id for a in plan.actions}


def test_a_finding_the_model_explicitly_deferred_is_respected():
    """Silence is a generation artefact; an explicit reason is a decision."""
    scan = scan_with(finding("NET-005"), finding("IDN-005"))
    _, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1}],
        "deferred": {"IDN-005": "this machine still needs WDigest for an old app"},
    }, scan)

    assert "IDN-005" not in {a.control_id for a in plan.actions}
    assert "IDN-005" in plan.deferred


def test_actions_beyond_the_budget_are_trimmed():
    findings = [finding(c.id) for c in CATALOG if c.autonomy_eligible][:10]
    scan = scan_with(*findings)
    _, plan = plan_from(
        {"summary": "s",
         "actions": [{"control_id": f.control_id, "rationale": "r", "order": i}
                     for i, f in enumerate(findings, 1)]},
        scan, budget=3)

    assert len(plan.actions) == 3


def test_dependencies_are_ordered_regardless_of_what_the_model_said():
    scan = scan_with(finding("NET-002", profile="Public"),
                     finding("NET-001", profile="Public"))
    _, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-002", "rationale": "r", "order": 1},
                    {"control_id": "NET-001", "rationale": "r", "order": 2}],
    }, scan)

    ordered = [a.control_id for a in plan.ordered()]
    assert ordered.index("NET-001") < ordered.index("NET-002"), (
        "NET-002 depends on NET-001; the catalogue decides order, not the model")


def test_garbage_shapes_do_not_raise():
    scan = scan_with(finding("NET-005"))
    for actions in (None, "not a list", 42, [None], ["string"], [[]], [{"no_id": 1}]):
        _, plan = plan_from({"summary": "s", "actions": actions}, scan)
        # Whatever came in, what comes out is a usable plan.
        assert all(CATALOG.get(a.control_id) for a in plan.actions)


def test_a_control_above_the_ceiling_is_refused_even_if_the_model_asks():
    scan = scan_with(finding("IDN-008"))          # intrusive, report-only
    planner = Planner(CATALOG, engine=None)
    plan = planner._validate(
        {"summary": "s",
         "actions": [{"control_id": "IDN-008", "rationale": "r", "order": 1}]},
        scan, RiskTier.CAUTION, True, 8)

    assert "IDN-008" not in {a.control_id for a in plan.actions}
    assert "IDN-008" in plan.deferred


# --------------------------------------------------------------------------
# The planner that needs no model at all
# --------------------------------------------------------------------------

def test_the_builtin_planner_plans_without_a_model():
    findings = [finding(c.id) for c in CATALOG if c.autonomy_eligible][:6]
    plan = builtin_plan(scan_with(*findings), CATALOG, budget=8)

    assert plan.actions
    assert plan.fallback
    assert all(CATALOG.require(a.control_id).autonomy_eligible for a in plan.actions)


def test_the_builtin_planner_never_plans_something_it_may_not_do():
    findings = [finding(c.id) for c in CATALOG if c.has_remediation]
    plan = builtin_plan(scan_with(*findings), CATALOG,
                        ceiling=RiskTier.SAFE, budget=40)

    for action in plan.actions:
        assert CATALOG.require(action.control_id).risk is RiskTier.SAFE


def test_without_elevation_nothing_that_needs_admin_is_planned():
    findings = [finding(c.id) for c in CATALOG if c.autonomy_eligible][:8]
    plan = builtin_plan(scan_with(*findings), CATALOG, elevated=False, budget=40)

    for action in plan.actions:
        assert not CATALOG.require(action.control_id).needs_admin


# --------------------------------------------------------------------------
# Letting the model be the only decision-maker
#
# Off, the built-in planner is a safety net. On, the model's answer is the
# whole plan - and if it cannot answer, nothing is changed rather than
# something else quietly deciding instead.
# --------------------------------------------------------------------------

class _Unavailable:
    """An engine that cannot serve a request."""
    name = "Qwen2.5-Coder 1.5B"
    available = False
    status = "not downloaded yet"


def test_without_a_model_the_builtin_planner_still_acts():
    scan = scan_with(finding("NET-005"))
    planner = Planner(CATALOG, engine=_Unavailable())

    plan = planner.plan(scan, require_model=False)

    assert plan.actions, "the safety net should still harden the machine"
    assert plan.fallback


def test_model_only_changes_nothing_when_the_model_is_unavailable():
    scan = scan_with(finding("NET-005"), finding("IDN-005"))
    planner = Planner(CATALOG, engine=_Unavailable())

    plan = planner.plan(scan, require_model=True)

    assert plan.actions == [], "nothing may be applied by a different decider"
    assert "not downloaded yet" in plan.summary
    assert set(plan.deferred) == {"NET-005", "IDN-005"}
    assert any(n.level == "warn" for n in planner.notes)


def test_model_only_says_why_rather_than_going_quiet():
    planner = Planner(CATALOG, engine=_Unavailable())
    plan = planner.plan(scan_with(finding("NET-005")), require_model=True)

    assert "Nothing was changed" in plan.summary or "none were" in plan.summary
    assert "model" in plan.summary.lower()


def test_model_only_does_not_append_what_the_model_left_out():
    """The whole point: the plan is the model's answer, not a superset of it."""
    scan = scan_with(finding("NET-005"), finding("IDN-005"))
    planner = Planner(CATALOG, engine=None)

    plan = planner._validate(
        {"summary": "s",
         "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1}]},
        scan, RiskTier.CAUTION, True, 8, require_model=True)

    assert [a.control_id for a in plan.actions] == ["NET-005"]
    assert "IDN-005" in plan.deferred
    assert "did not choose" in plan.deferred["IDN-005"]


def test_the_safety_net_does_append_what_the_model_left_out():
    scan = scan_with(finding("NET-005"), finding("IDN-005"))
    planner = Planner(CATALOG, engine=None)

    plan = planner._validate(
        {"summary": "s",
         "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1}]},
        scan, RiskTier.CAUTION, True, 8, require_model=False)

    assert {"NET-005", "IDN-005"} <= {a.control_id for a in plan.actions}


def test_model_only_does_not_weaken_the_guard():
    """Sole decision-maker is not the same as unchecked."""
    scan = scan_with(finding("IDN-008"))          # intrusive, report-only
    planner = Planner(CATALOG, engine=None)

    plan = planner._validate(
        {"summary": "s",
         "actions": [{"control_id": "IDN-008", "rationale": "r", "order": 1},
                     {"control_id": "XXX-999", "rationale": "r", "order": 2}]},
        scan, RiskTier.CAUTION, True, 8, require_model=True)

    assert plan.actions == []
    assert "IDN-008" in plan.deferred


# --------------------------------------------------------------------------
# Invented controls
#
# From a real 1.5B run on live Windows: the model deferred SYS-006 "The system
# drive is not encrypted" and SYS-007 "The firewall is not recording what it
# blocks". Both sound entirely plausible. Neither exists. They could never have
# been executed - the guard checks actions against the catalogue - but they were
# displayed under "Left alone", which claims Lares checked something it did not.
# --------------------------------------------------------------------------

def test_a_deferred_control_that_does_not_exist_is_not_shown():
    scan = scan_with(finding("NET-005"))
    planner, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1}],
        "deferred": {
            "SYS-006": "The system drive is not encrypted",
            "SYS-007": "The firewall is not recording what it blocks",
        },
    }, scan)

    assert "SYS-006" not in plan.deferred
    assert "SYS-007" not in plan.deferred
    assert any("not in the catalogue" in n.text for n in planner.notes)


def test_a_real_deferred_control_is_kept():
    scan = scan_with(finding("NET-005"), finding("IDN-005"))
    _, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1}],
        "deferred": {"IDN-005": "an old application still needs WDigest"},
    }, scan)

    assert plan.deferred["IDN-005"] == "an old application still needs WDigest"


def test_a_lowercase_deferred_id_still_matches():
    scan = scan_with(finding("NET-005"), finding("IDN-005"))
    _, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-005", "rationale": "r", "order": 1}],
        "deferred": {"idn-005": "still needed here"},
    }, scan)

    assert "IDN-005" in plan.deferred


def test_a_long_rationale_does_not_end_mid_word():
    """A real plan ended on '...which is reading the mem', which reads like the
    program broke rather than like a sentence was too long."""
    scan = scan_with(finding("NET-005"))
    _, plan = plan_from({
        "summary": "s",
        "actions": [{"control_id": "NET-005", "order": 1,
                     "rationale": "word " * 300}],
    }, scan)

    rationale = plan.actions[0].rationale
    assert len(rationale) <= 404
    assert rationale.endswith("...")
    assert not rationale.rstrip(".").endswith("wor")


# --------------------------------------------------------------------------
# Replies that ran out of room
# --------------------------------------------------------------------------

class TestTruncatedReplies:
    """A small model asked for several hundred tokens of JSON reaches the cap
    mid-sentence, and the document is then correct up to the cut and
    unparseable because of it. Refusing the whole reply loses everything the
    model had actually finished saying."""

    def test_a_reply_cut_off_inside_a_string_keeps_what_was_finished(self):
        raw = ('{"summary": "ok", "actions": [{"control_id": "NET-005"}, '
               '{"control_id": "SVC-003", "rationale": "the spooler is')
        got = extract_json(raw)
        assert got is not None
        assert [a["control_id"] for a in got["actions"]] == ["NET-005", "SVC-003"]

    def test_a_reply_cut_off_after_a_comma_keeps_the_complete_items(self):
        raw = '{"summary": "ok", "actions": [{"control_id": "NET-005"},'
        got = extract_json(raw)
        assert got["actions"] == [{"control_id": "NET-005"}]

    def test_a_reply_cut_off_before_anything_completed_is_refused(self):
        """The dangerous repair, and the reason the empty case is special.

        "{}" parses perfectly and reads downstream as a confident "nothing is
        wrong with this machine". A model that genuinely meant that would have
        produced valid JSON and never reached the repair at all.
        """
        assert extract_json('{"summ') is None
        assert extract_json("{") is None

    def test_an_empty_object_the_model_really_sent_is_still_read(self):
        assert extract_json("{}") == {}

    def test_escapes_inside_a_truncated_string_do_not_confuse_the_scan(self):
        raw = r'{"fix": "Set-Item -Value \"C:\\x\"", "undo": "Undo-'
        got = extract_json(raw)
        assert got == {"fix": 'Set-Item -Value "C:\\x"'}

    def test_a_valid_reply_is_never_touched_by_the_repair(self):
        raw = '{"summary": "fine", "actions": []}'
        assert extract_json(raw) == {"summary": "fine", "actions": []}

    def test_text_with_no_object_at_all_is_still_nothing(self):
        assert extract_json("I would check the firewall first.") is None
        assert extract_json("") is None
