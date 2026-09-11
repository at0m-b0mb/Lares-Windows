"""The cycle. Sense, think, act, verify, record - then wait and do it again.

This is the piece both applications share. The terminal agent and the desktop
agent differ only in how they show what is happening; the work itself, and every
decision about whether to act, happens here.

One cycle:

    scan     run every control's probe, gather machine context
    plan     ask the model which controls to apply, in what order
    act      for each, through the executor's full safety sequence
    record   journal every outcome, including refusals
    judge    update the circuit breaker

A cycle never raises. On any unexpected error it records what happened, trips the
breaker, and returns - because the alternative is an agent that dies silently at
2am and leaves a machine half-configured with nobody to tell.
"""

from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass
from typing import Callable

from .. import logs
from ..act.execute import Executor, Report
from ..act.guard import Context
from ..act.journal import Journal
from ..brain.engine import Engine
from ..brain.plan import Planner
from ..catalog.loader import Catalog
from ..config import Settings
from ..core import Cycle, Plan, Scan, Status, new_id, utcnow
from ..sense import scanner
from ..winsys import is_demo, is_elevated
from .breaker import Breaker


@dataclass
class Event:
    """Something the user interface may want to show."""

    kind: str        # scan | plan | action | cycle | error | wait
    message: str
    detail: str = ""
    progress: tuple[int, int] | None = None
    #: Set on errors. The id of the report on disk holding the full traceback,
    #: so the interface can show something a person can actually look up.
    error_id: str = ""


Listener = Callable[[Event], None]


class Agent:
    """Runs cycles, on demand or on a schedule."""

    def __init__(
        self,
        catalog: Catalog,
        settings: Settings,
        *,
        engine: Engine | None = None,
        journal: Journal | None = None,
        breaker: Breaker | None = None,
        listener: Listener | None = None,
    ) -> None:
        self.catalog = catalog
        self.settings = settings
        self.engine = engine
        self.journal = journal or Journal()
        self.breaker = breaker or Breaker(settings.breaker_threshold)
        self.planner = Planner(catalog, engine)
        self._listener = listener
        self._stop = threading.Event()
        self.last_cycle: Cycle | None = None

    # -- plumbing -------------------------------------------------------

    def _emit(self, kind: str, message: str, detail: str = "",
              progress: tuple[int, int] | None = None, error_id: str = "") -> None:
        if self._listener:
            try:
                self._listener(Event(kind, message, detail, progress, error_id))
            except Exception:  # noqa: BLE001 - a broken UI must not stop the agent
                pass

    # -- one cycle ------------------------------------------------------

    def run_cycle(self) -> Cycle:
        """Do one full pass. Never raises."""
        cycle_id = new_id("cyc")
        log = logs.get()
        log.info("cycle", "Cycle starting", cycle=cycle_id,
                 ceiling=self.settings.ceiling, budget=self.settings.budget,
                 dry_run=self.settings.dry_run)
        try:
            return self._run_cycle(cycle_id)
        except Exception as exc:  # noqa: BLE001
            # The one place a crash is genuinely expected to be survivable. Write
            # a full report, put its id where the user will see it, trip the
            # breaker, and return an empty cycle rather than dying in a thread.
            report = log.error(
                "cycle", "The cycle stopped unexpectedly", exc=exc,
                cycle=cycle_id, ceiling=self.settings.ceiling,
            )
            detail = traceback.format_exc(limit=6)
            self._emit("error", f"The cycle stopped unexpectedly: {exc}", detail,
                       error_id=report.error_id)
            self.breaker.trip(
                f"a cycle raised {type(exc).__name__}: {exc} ({report.error_id})")
            empty = Cycle(scan=Scan(), plan=Plan(),
                          halted=f"{exc} ({report.error_id})", cycle_id=cycle_id)
            empty.finished_at = utcnow()
            self.last_cycle = empty
            return empty

    def _run_cycle(self, cycle_id: str) -> Cycle:
        log = logs.get()

        # -- sense ------------------------------------------------------
        self._emit("scan", "Checking the machine")
        scan = scanner.scan(
            self.catalog,
            domains=self.settings.domains or None,
            progress=lambda cid, i, n: self._emit(
                "scan", f"Checking {cid}", progress=(i, n)),
        )
        log.info("scan", f"Scan finished: {len(scan.findings)} finding(s)",
                 cycle=cycle_id, worst=scan.worst.value,
                 probes_failed=len(scan.errors), demo=scan.demo,
                 duration_ms=scan.duration_ms)

        if scan.errors:
            self._emit("scan", f"{len(scan.errors)} probe(s) could not be read",
                       "; ".join(f"{k}: {v}" for k, v in list(scan.errors.items())[:4]))
            for control_id, message in scan.errors.items():
                log.warn("scan", f"Probe {control_id} could not be read",
                         cycle=cycle_id, detail=message[:300])

        elevated = is_elevated()
        halted = self.breaker.open

        # -- think ------------------------------------------------------
        self._emit("plan", f"Deciding what to do about {len(scan.findings)} finding(s)")
        plan = self.planner.plan(
            scan,
            ceiling=self.settings.risk_ceiling,
            elevated=elevated,
            budget=self.settings.budget,
            cycle_id=cycle_id,
        )
        for note in self.planner.notes:
            self._emit("plan", note.text, "")
            if note.level == "warn":
                log.warn("plan", note.text, cycle=cycle_id)

        if self.settings.excluded:
            excluded = set(self.settings.excluded)
            kept = [a for a in plan.actions if a.control_id not in excluded]
            for action in plan.actions:
                if action.control_id in excluded:
                    plan.deferred[action.control_id] = "excluded in this machine's settings"
            plan.actions = kept

        cycle = Cycle(scan=scan, plan=plan, cycle_id=cycle_id)

        # -- act --------------------------------------------------------
        if halted:
            cycle.halted = self.breaker.explain()
            self._emit("cycle", "Changes are halted; reporting only", cycle.halted)
            log.warn("cycle", "Autonomy is halted; reporting only",
                     cycle=cycle_id, reason=cycle.halted)
        elif not plan.actions:
            self._emit("cycle", "Nothing to change this cycle")
            log.info("cycle", "Nothing to change this cycle", cycle=cycle_id)
        else:
            self._apply(cycle, elevated)

        cycle.finished_at = utcnow()
        self.last_cycle = cycle

        if not halted:
            self.breaker.record(cycle)

        self._emit("cycle", cycle.summary_line(), self.breaker.explain())
        log.info("cycle", f"Cycle finished: {cycle.summary_line()}",
                 cycle=cycle_id, fixed=len(cycle.fixed),
                 rolled_back=len(cycle.reverted), halted=cycle.halted)
        return cycle

    def _apply(self, cycle: Cycle, elevated: bool) -> None:
        ctx = Context(
            elevated=elevated,
            ceiling=self.settings.risk_ceiling,
            autonomous=True,
            edition=cycle.scan.fact("Operating system"),
            change_budget=self.settings.budget,
            changes_made=0,
        )
        executor = Executor(
            self.catalog, ctx,
            dry_run=self.settings.dry_run,
            listener=lambda r: self._on_stage(r),
        )

        total = len(cycle.plan.actions)
        for index, action in enumerate(cycle.plan.ordered(), start=1):
            if self._stop.is_set():
                cycle.halted = "stopped while the cycle was running"
                break

            control = self.catalog.get(action.control_id)
            title = control.title if control else action.control_id
            self._emit("action", f"{action.control_id}: {title}", action.rationale,
                       progress=(index, total))

            outcome = executor.apply(action)
            cycle.outcomes.append(outcome)

            if outcome.status.is_change:
                ctx = Context(
                    elevated=ctx.elevated, ceiling=ctx.ceiling, autonomous=True,
                    edition=ctx.edition, change_budget=ctx.change_budget,
                    changes_made=ctx.changes_made + 1,
                )
                executor.ctx = ctx

            self.journal.record(
                outcome,
                cycle_id=cycle.cycle_id,
                control_title=title,
                rationale=action.rationale,
                model=cycle.plan.model_name,
                host=cycle.scan.fact("Host name"),
            )
            self._emit("action", f"{action.control_id}: {outcome.status.value}",
                       outcome.message, progress=(index, total))

            level = logs.Level.INFO
            if outcome.status in (Status.ROLLED_BACK, Status.UNVERIFIED):
                level = logs.Level.WARN
            elif outcome.status is Status.FAILED:
                level = logs.Level.ERROR
            logs.get().write(
                level, "act", f"{action.control_id} {outcome.status.value}: {outcome.message}",
                cycle=cycle.cycle_id, control=action.control_id,
                params=outcome.params, duration_ms=outcome.duration_ms,
                snapshot=outcome.snapshot_id, action_id=outcome.action_id,
                refusal=outcome.refusal_reason,
            )

            # Two changes going wrong inside a single cycle is already enough
            # evidence that this machine does not match the catalogue. Stop here
            # rather than working through the remaining eight finding out.
            #
            # A failed remediation counts, and so does a rollback that could not
            # be completed - that one leaves a change in place that nobody asked
            # to keep, which is the strongest possible reason to stop touching
            # this machine.
            gone_wrong = len(cycle.reverted) + sum(
                1 for o in cycle.outcomes if o.status is Status.FAILED)
            if gone_wrong >= 2:
                stuck = [o.control_id for o in cycle.outcomes
                         if o.status is Status.FAILED and o.change_in_place]
                cycle.halted = (
                    f"stopped early: {gone_wrong} changes in this cycle went wrong"
                )
                if stuck:
                    cycle.halted += (
                        f", and {', '.join(stuck)} could not be undone and is still "
                        "in place"
                    )
                self._emit("cycle", cycle.halted)
                logs.get().warn("cycle", cycle.halted, cycle=cycle.cycle_id,
                                stuck=stuck)
                break

    def _on_stage(self, report: Report) -> None:
        self._emit("action", f"{report.control_id}: {report.stage}", report.message)

    # -- scheduling -----------------------------------------------------

    def run_forever(self) -> None:
        """Cycle on the configured interval until :meth:`stop` is called."""
        if self.settings.scan_on_start:
            self.run_cycle()
            self._release_model()

        interval = max(300, self.settings.interval_minutes * 60)
        while not self._stop.is_set():
            self._emit("wait", f"Next check in {self.settings.interval_minutes} minutes")
            # Wait in slices so a stop request is acted on promptly rather than
            # after however many hours remain of the interval.
            waited = 0.0
            while waited < interval and not self._stop.is_set():
                self._stop.wait(min(5.0, interval - waited))
                waited += 5.0
            if self._stop.is_set():
                break
            self.run_cycle()
            self._release_model()

    def _release_model(self) -> None:
        if self.engine is not None and self.settings.unload_between_cycles:
            self.engine.unload()

    def stop(self) -> None:
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()


# --------------------------------------------------------------------------

def build(settings: Settings, catalog: Catalog, *, listener: Listener | None = None,
          with_model: bool = True) -> tuple[Agent, str]:
    """Assemble an agent, returning it and a line about the model in use."""
    engine: Engine | None = None
    note = "built-in planner (no model)"

    if with_model:
        engine, decision = Engine.autoselect(prefer=settings.model_tier)
        if decision.spec is None:
            note = decision.reason
        elif not decision.present:
            note = (
                f"{decision.spec.name} is not downloaded yet "
                f"({decision.spec.size_mb} MB). Using the built-in planner until it is."
            )
        elif not engine.available:
            note = engine.status
        else:
            note = f"{decision.spec.name}, {decision.hardware.threads} threads"

    agent = Agent(catalog, settings, engine=engine, listener=listener)
    if is_demo():
        note += " - demo mode, nothing on this machine will be changed"
    return agent, note
