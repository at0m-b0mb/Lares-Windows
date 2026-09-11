"""What the planner does with what the model says.

The model is a 1.5B-to-7B quantised local model. It will sometimes name a
control that does not exist, add a key nobody asked for, forget an item from a
list of twelve, or return prose where JSON was demanded. None of that may
result in a wrong change or a lost fix, so each of those shapes is exercised
here against a real catalogue.
"""

from __future__ import annotations

from lares.brain.plan import Planner, builtin_plan
from lares.catalog import loader
from lares.core import Finding, RiskTier, Scan, Severity


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
