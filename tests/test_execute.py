"""The apply / verify / rollback state machine.

Two properties here were broken in a way tests would not have noticed, and both
are about telling the truth after something went wrong:

* a rollback that *itself* fails leaves the change on the machine, and recording
  that as "rolled back" puts a lie in the journal and hides the change from the
  Ledger, which is the one list someone would use to try the undo again;

* the health baseline is what decides whether a change made the machine worse.
  Holding one baseline for a whole cycle means a regression caused by the first
  action is measured against the third one, so the innocent change is the one
  that gets undone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lares.act import execute as execute_mod
from lares.act import health as health_mod
from lares.act import snapshot as snapshot_mod
from lares.act.execute import Executor, ProbeReading
from lares.act.guard import Context
from lares.catalog.loader import Catalog
from lares.core import Control, ParamSpec, PlannedAction, RiskTier, Severity, Status


# --------------------------------------------------------------------------
# A catalogue of one, and a machine we can script
# --------------------------------------------------------------------------

def make_control(**overrides) -> Control:
    base = dict(
        id="TST-001",
        title="Test control",
        domain="test",
        severity=Severity.HIGH,
        risk=RiskTier.SAFE,
        rationale="A control used only by the tests.",
        detect="probe",
        remediate="Set-Thing -Port {port}",
        rollback="Remove-Thing -Port {port}",
        params=(ParamSpec("port", "int", minimum=1, maximum=65535),),
    )
    base.update(overrides)
    return Control(**base)


@pytest.fixture
def catalog() -> Catalog:
    control = make_control()
    return Catalog({control.id: control}, digest="test")


@pytest.fixture
def machine(monkeypatch):
    """A scriptable stand-in for the Windows side of the executor.

    ``probe`` is a list of readings handed out in order; ``scripts`` records
    what was run and decides whether each call succeeds.
    """

    class Machine:
        def __init__(self) -> None:
            self.readings: list[ProbeReading] = []
            self.ran: list[str] = []
            self.remediate_ok = True
            self.rollback_ok = True
            self.health = [health_mod.Health(values={"dns": True})]

        def next_reading(self, *_args, **_kwargs) -> ProbeReading:
            return self.readings.pop(0) if self.readings else ProbeReading(compliant=True)

        def run(self, script: str, _timeout: int) -> tuple[bool, str]:
            self.ran.append(script)
            if script.startswith("Remove-Thing"):
                return self.rollback_ok, "" if self.rollback_ok else "rollback exploded"
            return self.remediate_ok, "" if self.remediate_ok else "remediation exploded"

        def capture(self) -> health_mod.Health:
            return self.health[-1] if len(self.health) == 1 else self.health.pop(0)

    m = Machine()
    monkeypatch.setattr(execute_mod, "read_probe", m.next_reading)
    monkeypatch.setattr(Executor, "_run", lambda self, s, t: m.run(s, t))
    monkeypatch.setattr(health_mod, "capture", m.capture)
    monkeypatch.setattr(snapshot_mod, "take",
                        lambda script, label="", **kw: snapshot_mod.Snapshot(
                            snapshot_id="snap-test", directory=Path("/tmp"),
                            captured=["registry"]))
    monkeypatch.setattr(execute_mod, "is_demo", lambda: False)
    return m


def executor(catalog: Catalog) -> Executor:
    return Executor(catalog, Context(elevated=True, ceiling=RiskTier.CAUTION,
                                     autonomous=True))


ACTION = PlannedAction(control_id="TST-001", params={"port": 443})


# --------------------------------------------------------------------------
# Honest rollbacks
# --------------------------------------------------------------------------

def test_a_change_that_works_is_kept_and_marked_as_in_place(catalog, machine):
    machine.readings = [ProbeReading(compliant=False, observed="broken"),
                        ProbeReading(compliant=True, observed="fixed")]

    outcome = executor(catalog).apply(ACTION)

    assert outcome.status is Status.VERIFIED
    assert outcome.change_in_place is True


def test_a_failed_verification_rolls_back_and_clears_the_flag(catalog, machine):
    machine.readings = [ProbeReading(compliant=False, observed="broken"),
                        ProbeReading(compliant=False, observed="still broken")]

    outcome = executor(catalog).apply(ACTION)

    assert outcome.status is Status.ROLLED_BACK
    assert outcome.change_in_place is False
    assert any(s.startswith("Remove-Thing") for s in machine.ran)


def test_a_rollback_that_fails_is_not_reported_as_rolled_back(catalog, machine):
    """The bug this exists for: the change is still on the machine."""
    machine.readings = [ProbeReading(compliant=False, observed="broken"),
                        ProbeReading(compliant=False, observed="still broken")]
    machine.rollback_ok = False

    outcome = executor(catalog).apply(ACTION)

    assert outcome.status is Status.FAILED, "claiming rolled_back here would be a lie"
    assert outcome.change_in_place is True
    assert "ROLLBACK ALSO FAILED" in outcome.message
    assert "retried from the Ledger" in outcome.message


def test_a_failed_remediation_still_counts_as_a_change_until_undone(catalog, machine):
    machine.readings = [ProbeReading(compliant=False, observed="broken")]
    machine.remediate_ok = False
    machine.rollback_ok = False

    outcome = executor(catalog).apply(ACTION)

    assert outcome.status is Status.FAILED
    assert outcome.change_in_place is True


def test_an_additive_control_has_nothing_to_undo(catalog, machine):
    control = make_control(rollback="", rollback_policy="additive",
                           rollback_note="only refreshes state")
    cat = Catalog({control.id: control}, digest="t")
    machine.readings = [ProbeReading(compliant=False, observed="stale"),
                        ProbeReading(compliant=False, observed="still stale")]

    outcome = executor(cat).apply(ACTION)

    assert outcome.change_in_place is False
    assert "nothing to undo" in outcome.message


# --------------------------------------------------------------------------
# Health attribution
# --------------------------------------------------------------------------

def test_a_regression_rolls_the_change_back(catalog, machine):
    machine.readings = [ProbeReading(compliant=False, observed="broken"),
                        ProbeReading(compliant=True, observed="fixed")]
    machine.health = [health_mod.Health(values={"dns": True}),
                      health_mod.Health(values={"dns": False})]

    outcome = executor(catalog).apply(ACTION)

    assert outcome.status is Status.ROLLED_BACK
    assert "got worse" in outcome.message


def test_the_baseline_advances_after_a_change_is_kept(catalog, machine):
    """Otherwise a later action is blamed for an earlier action's damage."""
    machine.readings = [ProbeReading(compliant=False, observed="broken"),
                        ProbeReading(compliant=True, observed="fixed")]
    good = health_mod.Health(values={"dns": True})
    machine.health = [good, good]

    ex = executor(catalog)
    ex.apply(ACTION)

    assert ex.baseline is not None
    assert ex.baseline.values == {"dns": True}


# --------------------------------------------------------------------------
# Refusals before anything runs
# --------------------------------------------------------------------------

def test_an_unknown_control_is_refused(catalog, machine):
    outcome = executor(catalog).apply(PlannedAction(control_id="NOPE-001"))
    assert outcome.status is Status.REFUSED
    assert not machine.ran


def test_an_unreadable_probe_stops_the_action(catalog, machine):
    machine.readings = [ProbeReading(compliant=False, error="access denied")]

    outcome = executor(catalog).apply(ACTION)

    assert outcome.status is Status.REFUSED
    assert "cannot be measured" in outcome.message
    assert not machine.ran, "nothing should run when the state cannot be read"


def test_an_already_compliant_control_is_left_alone(catalog, machine):
    machine.readings = [ProbeReading(compliant=True, observed="already fine")]

    outcome = executor(catalog).apply(ACTION)

    assert outcome.status is Status.SKIPPED
    assert not machine.ran


def test_a_dry_run_changes_nothing(catalog, machine):
    machine.readings = [ProbeReading(compliant=False, observed="broken")]
    ex = Executor(catalog, Context(elevated=True, ceiling=RiskTier.CAUTION,
                                   autonomous=True), dry_run=True)

    outcome = ex.apply(ACTION)

    assert outcome.status is Status.SIMULATED
    assert outcome.change_in_place is False
    assert not machine.ran
