"""Applying one action, safely, with nobody watching.

The sequence below is the whole safety argument of this application. There is no
confirmation dialog anywhere in it, by design - the operator asked for a tool
that runs unattended. What replaces the dialog is that every step is checked and
every change is provably undoable:

    validate  -> the model's parameters must fit the control's declared shapes
    screen    -> the rendered script must contain no forbidden operation
    probe     -> re-run detection; if it is already fixed, do nothing
    baseline  -> read the health signals while the machine is still known good
    snapshot  -> export the state the script is about to touch
    apply     -> run the remediation
    verify    -> re-run detection; did it actually work?
    health    -> re-read the signals; did anything that worked stop working?
    decide    -> keep it, or put it back, right now

A change is kept only when the problem is gone and nothing regressed. Anything
else is rolled back on the spot. Controls that cannot take effect until a restart
are the one exception, and they say so in the catalogue rather than being guessed
at here.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from ..catalog.loader import Catalog, render
from ..core import Control, Outcome, PlannedAction, Status
from ..winsys import powershell, is_demo
from . import health as health_mod
from . import snapshot as snapshot_mod
from .guard import Context, Refused, clear_to_run, screen_script

#: Remediation scripts get longer than probes, especially DISM ones.
REMEDIATE_TIMEOUT = 300
PROBE_TIMEOUT = 60
ROLLBACK_TIMEOUT = 180


@dataclass
class ProbeReading:
    """What a detection probe said about one control at one moment."""

    compliant: bool
    observed: str = ""
    evidence: str = ""
    params: dict[str, Any] | None = None
    instances: list[dict[str, Any]] | None = None
    error: str = ""

    @property
    def usable(self) -> bool:
        return not self.error


def read_probe(control: Control, params: dict[str, Any] | None = None) -> ProbeReading:
    """Run a control's detection probe and parse its JSON answer.

    A probe that cannot run, or that answers with something other than the
    documented object, is reported as unusable rather than being guessed at.
    The executor treats an unusable probe as "do not touch this", because a
    change whose effect cannot be measured cannot be verified either.
    """
    script = control.detect
    if params:
        try:
            script = render(script, params)
        except Exception as exc:  # noqa: BLE001 - surfaced as an unusable probe
            return ProbeReading(False, error=f"could not render probe: {exc}")

    result = powershell(script, timeout=PROBE_TIMEOUT)
    if not result.ok and not result.stdout.strip():
        detail = result.error or result.stderr.strip() or f"exit {result.code}"
        return ProbeReading(False, error=detail[:400])

    data = result.json(default=None)
    if not isinstance(data, dict):
        return ProbeReading(False, error=f"probe did not return a JSON object: {result.stdout[:200]}")

    instances = data.get("instances")
    if isinstance(instances, dict):
        # PowerShell serialises a one-element array as a bare object.
        instances = [instances]
    elif not isinstance(instances, list):
        instances = None

    return ProbeReading(
        compliant=bool(data.get("compliant", False)),
        observed=str(data.get("observed", "") or ""),
        evidence=str(data.get("evidence", "") or ""),
        params=data.get("params") if isinstance(data.get("params"), dict) else None,
        instances=instances,
    )


@dataclass
class Report:
    """Progress callback payload, so a UI can follow a long cycle."""

    control_id: str
    stage: str
    message: str = ""


Listener = Callable[[Report], None]


class Executor:
    """Applies planned actions against the live machine."""

    def __init__(
        self,
        catalog: Catalog,
        ctx: Context,
        *,
        dry_run: bool = False,
        listener: Listener | None = None,
    ) -> None:
        self.catalog = catalog
        self.ctx = ctx
        self.dry_run = dry_run
        self._listener = listener
        #: Health reading from before the first change of this cycle.
        self.baseline: health_mod.Health | None = None

    # -- plumbing -------------------------------------------------------

    def _say(self, control_id: str, stage: str, message: str = "") -> None:
        if self._listener:
            self._listener(Report(control_id, stage, message))

    def _run(self, script: str, timeout: int) -> tuple[bool, str]:
        if is_demo():
            return True, "demo mode: not executed"
        result = powershell(script, timeout=timeout)
        output = (result.stdout + ("\n" + result.stderr if result.stderr else "")).strip()
        if not result.ok:
            return False, (result.error or output or f"exit {result.code}")[:2000]
        return True, output[:2000]

    # -- the sequence ---------------------------------------------------

    def apply(self, action: PlannedAction) -> Outcome:
        """Run one planned action through the full safety sequence."""
        started = time.monotonic()
        control = self.catalog.get(action.control_id)

        if control is None:
            return Outcome(
                control_id=action.control_id,
                status=Status.REFUSED,
                refusal_reason=(
                    f"{action.control_id} is not in the catalogue. The model may only "
                    "select controls that exist."
                ),
                message="unknown control",
            )

        rendered = ""
        rollback_script = ""
        try:
            clean = clear_to_run(control, action.params, self.ctx)
            rendered = render(control.remediate, clean)
            screened = screen_script(rendered)
            if not screened.ok:
                raise Refused(
                    f"{control.id} remediation contains a forbidden operation",
                    detail=screened.summary,
                )
            if control.rollback:
                rollback_script = render(control.rollback, clean)
                back = screen_script(rollback_script, absolute_only=True)
                if not back.ok:
                    raise Refused(
                        f"{control.id} rollback contains a forbidden operation",
                        detail=back.summary,
                    )
        except Refused as refusal:
            return Outcome(
                control_id=control.id,
                status=Status.REFUSED,
                params=dict(action.params or {}),
                refusal_reason=refusal.reason,
                message=refusal.detail or refusal.reason,
                duration_ms=_ms(started),
            )

        outcome = Outcome(
            control_id=control.id,
            status=Status.SKIPPED,
            params=clean,
            rollback_script=rollback_script,
        )

        # -- probe before -------------------------------------------------
        self._say(control.id, "probe", "checking current state")
        before = read_probe(control, clean)
        outcome.before = before.observed or before.error

        if not before.usable:
            outcome.status = Status.REFUSED
            outcome.refusal_reason = "the detection probe could not be read"
            outcome.message = (
                f"{control.id} was left alone: {before.error}. A change that cannot "
                "be measured cannot be verified, so it is not attempted."
            )
            outcome.duration_ms = _ms(started)
            return outcome

        if before.compliant:
            outcome.status = Status.SKIPPED
            outcome.message = f"already in the desired state: {before.observed}"
            outcome.duration_ms = _ms(started)
            return outcome

        if self.dry_run:
            outcome.status = Status.SIMULATED
            outcome.message = f"would apply {control.id}: {control.title}"
            outcome.output = rendered
            outcome.duration_ms = _ms(started)
            return outcome

        # -- health baseline ----------------------------------------------
        if self.baseline is None:
            self._say(control.id, "baseline", "reading health signals")
            self.baseline = health_mod.capture()
        if self.baseline.unavailable:
            outcome.status = Status.REFUSED
            outcome.refusal_reason = "health signals could not be read"
            outcome.message = (
                "No baseline could be taken, so a regression caused by a change "
                "would be undetectable. Nothing was changed."
            )
            outcome.duration_ms = _ms(started)
            return outcome

        # -- snapshot ------------------------------------------------------
        self._say(control.id, "snapshot", "capturing state before the change")
        snap = snapshot_mod.take(rendered, label=control.id)
        outcome.snapshot_id = snap.snapshot_id
        if not snap.ok and control.rollback_policy != "additive":
            outcome.status = Status.REFUSED
            outcome.refusal_reason = "state could not be captured before changing it"
            outcome.message = snap.summary()
            outcome.duration_ms = _ms(started)
            return outcome

        # -- apply ---------------------------------------------------------
        self._say(control.id, "apply", control.title)
        ok, output = self._run(rendered, REMEDIATE_TIMEOUT)
        outcome.output = output

        if not ok:
            outcome.status = Status.FAILED
            outcome.message = f"the remediation failed: {output[:300]}"
            self._undo(outcome, control, "the remediation failed part way through")
            outcome.duration_ms = _ms(started)
            return outcome

        # -- verify --------------------------------------------------------
        self._say(control.id, "verify", "checking the change took effect")
        after = read_probe(control, clean)
        outcome.after = after.observed or after.error

        regressions = health_mod.compare(self.baseline, health_mod.capture())
        if regressions:
            outcome.message = (
                "undone because the machine got worse: "
                + health_mod.describe(regressions)
            )
            self._undo(outcome, control, outcome.message)
            outcome.status = Status.ROLLED_BACK
            outcome.duration_ms = _ms(started)
            return outcome

        if after.usable and after.compliant:
            outcome.status = Status.VERIFIED
            outcome.message = f"fixed: {after.observed or control.title}"
        elif control.deferred_effect:
            # Expected: the value is written but Windows has not read it yet.
            outcome.status = Status.UNVERIFIED
            outcome.message = (
                f"applied; takes effect at next {control.effective}. "
                f"Until then the probe still reports: {after.observed or 'unchanged'}"
            )
        else:
            outcome.message = (
                "undone because it did not take effect: the problem is still "
                f"present after the change ({after.observed or after.error})"
            )
            self._undo(outcome, control, outcome.message)
            outcome.status = Status.ROLLED_BACK

        outcome.duration_ms = _ms(started)
        return outcome

    # -- undo ------------------------------------------------------------

    def _undo(self, outcome: Outcome, control: Control, why: str) -> None:
        """Put the machine back. Records what happened; never raises."""
        if control.rollback_policy == "additive":
            outcome.message += " (nothing to undo; this control only adds state)"
            return
        if not outcome.rollback_script:
            outcome.message += " (no rollback script was available)"
            return

        self._say(control.id, "rollback", why)
        ok, output = self._run(outcome.rollback_script, ROLLBACK_TIMEOUT)
        if ok:
            outcome.message += " - rolled back cleanly"
        else:
            outcome.message += (
                f" - THE ROLLBACK ALSO FAILED ({output[:200]}). State was captured "
                f"before the change in snapshot {outcome.snapshot_id}."
            )

    # -- manual undo of a past change -------------------------------------

    def undo_recorded(self, rollback_script: str, control_id: str = "") -> Outcome:
        """Run a rollback script kept in the journal, for an older change."""
        started = time.monotonic()
        outcome = Outcome(control_id=control_id, status=Status.FAILED,
                          rollback_script=rollback_script)
        screened = screen_script(rollback_script, absolute_only=True)
        if not screened.ok:
            outcome.status = Status.REFUSED
            outcome.refusal_reason = "the stored rollback contains a forbidden operation"
            outcome.message = screened.summary
            return outcome
        ok, output = self._run(rollback_script, ROLLBACK_TIMEOUT)
        outcome.output = output
        outcome.status = Status.VERIFIED if ok else Status.FAILED
        outcome.message = "change undone" if ok else f"undo failed: {output[:300]}"
        outcome.duration_ms = _ms(started)
        return outcome


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
