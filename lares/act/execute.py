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

import time
from dataclasses import dataclass
from typing import Any, Callable

from ..catalog.loader import Catalog, render
from ..core import Control, Outcome, PlannedAction, Status
from .. import demo_data, logs
from ..winsys import powershell, is_demo
from . import health as health_mod
from . import snapshot as snapshot_mod
from .guard import (
    Context,
    Refused,
    clear_to_run,
    screen_script,
    validate_params,
)

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


def demo_reading(control_id: str) -> ProbeReading:
    """The probe answer demo mode supplies, in the same shape as a real one."""
    data = demo_data.probe_for(control_id)
    instances = data.get("instances")
    return ProbeReading(
        compliant=bool(data.get("compliant", False)),
        observed=str(data.get("observed", "")),
        evidence=str(data.get("evidence", "")),
        params=data.get("params") if isinstance(data.get("params"), dict) else None,
        instances=instances if isinstance(instances, list) else None,
    )


def read_probe(control: Control, params: dict[str, Any] | None = None) -> ProbeReading:
    """Run a control's detection probe and parse its JSON answer.

    A probe that cannot run, or that answers with something other than the
    documented object, is reported as unusable rather than being guessed at.
    The executor treats an unusable probe as "do not touch this", because a
    change whose effect cannot be measured cannot be verified either.
    """
    if is_demo():
        return demo_reading(control.id)

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
        return self._run_live(script, timeout)

    def _run_live(self, script: str, timeout: int) -> tuple[bool, str]:
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
        ok, output = self._run(rendered, control.timeout or REMEDIATE_TIMEOUT)
        outcome.output = output
        # Set before checking `ok`: a script that failed part way through has
        # still changed something, and that is exactly when the undo matters.
        outcome.change_in_place = True
        if ok and is_demo():
            demo_data.mark_fixed(control.id)

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

        current_health = health_mod.capture()
        regressions = health_mod.compare(self.baseline, current_health)
        if regressions:
            outcome.message = (
                "undone because the machine got worse: "
                + health_mod.describe(regressions)
            )
            undone = self._undo(outcome, control, outcome.message)
            outcome.status = Status.ROLLED_BACK if undone else Status.FAILED
            outcome.duration_ms = _ms(started)
            return outcome

        if after.usable and after.compliant:
            outcome.status = Status.VERIFIED
            outcome.message = f"fixed: {after.observed or control.title}"
            # This change is staying, and the machine is still healthy with it
            # applied. That is the new known-good state, so the next action in
            # this cycle is compared against it rather than against how the
            # machine looked several changes ago - otherwise a regression caused
            # by an earlier action gets blamed on a later one, and the innocent
            # change is the one that gets rolled back.
            self.baseline = current_health
        elif control.deferred_effect:
            # Expected: the value is written but Windows has not read it yet.
            outcome.status = Status.UNVERIFIED
            outcome.message = (
                f"applied; takes effect at next {control.effective}. "
                f"Until then the probe still reports: {after.observed or 'unchanged'}"
            )
            self.baseline = current_health
        else:
            outcome.message = (
                "undone because it did not take effect: the problem is still "
                f"present after the change ({after.observed or after.error})"
            )
            undone = self._undo(outcome, control, outcome.message)
            outcome.status = Status.ROLLED_BACK if undone else Status.FAILED

        outcome.duration_ms = _ms(started)
        return outcome

    # -- undo ------------------------------------------------------------

    def _undo(self, outcome: Outcome, control: Control, why: str) -> bool:
        """Put the machine back. Returns whether it worked; never raises.

        The return value matters more than it looks. A rollback that fails
        leaves the change on the machine, and the caller has to record that
        honestly instead of claiming the attempt was rolled back - otherwise
        the journal says "undone" about a change that is still in force, and
        the Ledger hides it from the one list someone would use to undo it.
        """
        if control.rollback_policy == "additive":
            outcome.message += " (nothing to undo; this control only adds state)"
            outcome.change_in_place = False
            return True
        if not outcome.rollback_script:
            outcome.message += " (no rollback script was available)"
            return False

        # A rollback gets at least as long as the remediation did. Undoing a
        # DISM feature change costs the same minutes as making it, and cutting
        # the undo short is far worse than cutting the change short.
        self._say(control.id, "rollback", why)
        ok, output = self._run(outcome.rollback_script,
                               max(control.timeout, ROLLBACK_TIMEOUT))
        if ok and is_demo():
            demo_data.mark_unfixed(control.id)
        if ok:
            outcome.message += " - rolled back cleanly"
            outcome.change_in_place = False
        else:
            outcome.message += (
                f" - THE ROLLBACK ALSO FAILED ({output[:200]}). The change is still "
                f"in place. State was captured beforehand in snapshot "
                f"{outcome.snapshot_id}, and the undo can be retried from the Ledger."
            )
        return ok

    # -- manual undo of a past change -------------------------------------

    def undo_recorded(self, rollback_script: str, control_id: str = "",
                      params: dict[str, Any] | None = None) -> Outcome:
        """Run a rollback for an older change.

        The stored script is a record, not an input, wherever it can be
        avoided. The journal lives in the user's own profile, so a process
        running as that user at medium integrity can rewrite it - and the
        person who then runs ``lares undo`` is running as administrator. That
        turns a file anybody could edit into elevated PowerShell, which is the
        only privilege escalation this program could plausibly offer anyone.

        So when the control is still in the catalogue, the rollback is
        re-rendered from the catalogue and the stored parameters, through the
        same validation any other action goes through, and *that* is what runs.
        A difference between what was rendered and what the journal holds is
        reported rather than swallowed: it means the catalogue changed under
        the entry, or somebody edited the file.

        Only when the control has gone from the catalogue is the stored text
        used, and then it is screened in full rather than with the rollback
        exemption. That exemption is earned by provenance - a vetted
        remediation's exact inverse - and a line read back off disk has none.
        """
        started = time.monotonic()
        outcome = Outcome(control_id=control_id, status=Status.FAILED,
                          params=dict(params or {}),
                          rollback_script=rollback_script)

        script, absolute_only = rollback_script, False
        control = self.catalog.get(control_id) if control_id else None
        if control is not None and control.rollback:
            try:
                clean = validate_params(control, params or {})
                script = render(control.rollback, clean)
            except Refused as refusal:
                outcome.status = Status.REFUSED
                outcome.refusal_reason = (
                    f"the stored parameters are not valid for {control_id}: "
                    f"{refusal.reason}")
                outcome.message = outcome.refusal_reason
                return outcome
            # Re-rendered from a reviewed catalogue, so it has the provenance
            # the exemption exists for.
            absolute_only = True
            outcome.rollback_script = script
            if _squash(script) != _squash(rollback_script):
                logs.get().warn(
                    "act", "The stored rollback differs from the catalogue's",
                    control=control_id,
                    detail="re-rendered from the catalogue and running that")
                self._say(control_id, "undo",
                          "the journal's copy differs from the catalogue - "
                          "running the catalogue's")

        screened = screen_script(script, absolute_only=absolute_only)
        if not screened.ok:
            outcome.status = Status.REFUSED
            outcome.refusal_reason = "the stored rollback contains a forbidden operation"
            outcome.message = screened.summary
            return outcome
        ok, output = self._run(script, ROLLBACK_TIMEOUT)
        outcome.output = output
        outcome.status = Status.VERIFIED if ok else Status.FAILED
        # An undo that failed leaves the change exactly where it was, and the
        # undo list is the one place someone would go to try again. Recording
        # it as not-in-place is how a change that is still on the machine
        # disappears from the only view that would let anyone remove it.
        outcome.change_in_place = not ok
        outcome.rollback_script = script if not ok else ""
        outcome.message = "change undone" if ok else f"undo failed: {output[:300]}"
        outcome.duration_ms = _ms(started)
        return outcome


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _squash(script: str) -> str:
    """Whitespace-insensitive form, for comparing two renderings."""
    return " ".join(script.split())
