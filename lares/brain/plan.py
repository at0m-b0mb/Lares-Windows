"""Turning a scan into a plan.

There are two planners here and they are both real.

The **built-in planner** needs no model at all. It sorts by severity, prefers the
cheapest reversible fix, respects dependencies, and stops at the budget. It is
what runs before the model has been downloaded, on a machine too small to load
one, or any time inference fails. It is deliberately not a stub: a Lares install
that never gets a model still hardens the machine correctly, it just cannot
explain itself in the owner's own terms.

The **model planner** adds judgement the sort order cannot express - noticing that
this is a laptop on an untrusted network so the firewall matters more than the
audit policy today, or that fixing the unquoted service path is pointless while
the folder it lives in is world-writable. Its output is then put through the same
validation as everything else.

Whatever the model returns, three things are enforced afterwards:

* every control id must exist in the catalogue, or the action is dropped;
* a finding the model neither planned nor explicitly deferred is appended anyway,
  so a weak model cannot silently lose a critical fix;
* the final order is recomputed from the dependency graph, not trusted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import logs
from ..catalog.loader import Catalog
from ..core import Control, Finding, Plan, PlannedAction, RiskTier, Scan, Severity
from . import prompt as prompt_mod
from .engine import Engine, extract_json
from .retrieve import Index, context_for


@dataclass
class PlanNote:
    """Something worth telling the operator about how the plan was made."""

    level: str  # "info" | "warn"
    text: str


def _eligible(control: Control, ceiling: RiskTier, elevated: bool) -> tuple[bool, str]:
    """Can this control be part of an autonomous plan at all?"""
    if not control.has_remediation:
        return False, "report-only; there is no automatic fix for this"
    if not control.is_reversible:
        return False, (control.rollback_note or "cannot be undone").strip()
    if control.risk.rank > ceiling.rank:
        return False, f"risk '{control.risk.value}' is above the autonomy ceiling"
    if control.needs_admin and not elevated:
        return False, "needs administrator rights and this process is not elevated"
    return True, ""


def _candidates(scan: Scan, catalog: Catalog, ceiling: RiskTier,
                elevated: bool) -> tuple[list[tuple[Finding, Control]], dict[str, str]]:
    """Split findings into what can be acted on and what cannot, with reasons."""
    actionable: list[tuple[Finding, Control]] = []
    blocked: dict[str, str] = {}
    for finding in scan.findings:
        control = catalog.get(finding.control_id)
        if control is None:
            blocked[finding.control_id] = "not in the catalogue"
            continue
        ok, why = _eligible(control, ceiling, elevated)
        if ok:
            actionable.append((finding, control))
        else:
            blocked.setdefault(control.id, why)
    return actionable, blocked


def _sort_key(pair: tuple[Finding, Control]) -> tuple:
    finding, control = pair
    # Severity first because it is the reason to act at all. Then risk ascending,
    # so that when two problems are equally bad the one that is cheaper to undo
    # goes first - if the cycle is interrupted, the machine is left in the more
    # recoverable state.
    return (-finding.severity.rank, control.risk.rank, control.id, str(sorted(finding.params.items())))


# --------------------------------------------------------------------------
# The built-in planner
# --------------------------------------------------------------------------

def builtin_plan(scan: Scan, catalog: Catalog, *, ceiling: RiskTier = RiskTier.CAUTION,
                 elevated: bool = True, budget: int = 8) -> Plan:
    """Plan without a model. Correct, if not articulate."""
    actionable, blocked = _candidates(scan, catalog, ceiling, elevated)
    actionable.sort(key=_sort_key)

    chosen = actionable[:budget]
    ordered_ids = catalog.resolve_order([c.id for _, c in chosen])
    rank = {cid: i for i, cid in enumerate(ordered_ids)}

    actions = [
        PlannedAction(
            control_id=control.id,
            params=dict(finding.params),
            rationale=_builtin_rationale(finding, control),
            confidence=70,
            order=rank.get(control.id, 99) + 1,
        )
        for finding, control in chosen
    ]

    counts = scan.counts()
    summary = (
        f"{len(scan.findings)} finding(s) are open on this machine: "
        f"{counts[Severity.CRITICAL]} critical, {counts[Severity.HIGH]} high, "
        f"{counts[Severity.MEDIUM]} medium. Lares will apply {len(actions)} "
        f"reversible fix(es) this cycle and re-check afterwards. "
        "This reflects the controls Lares checks, not the machine's overall safety."
    )

    deferred = dict(blocked)
    for finding, control in actionable[budget:]:
        deferred.setdefault(control.id, "queued for the next cycle; this cycle's budget is full")

    return Plan(actions=sorted(actions, key=lambda a: a.order), summary=summary,
                deferred=deferred, model_name="built-in planner", fallback=True)


def _builtin_rationale(finding: Finding, control: Control) -> str:
    detail = finding.observed or control.title
    return f"{detail}. Applying {control.id} ({control.risk.value}, reversible)."


# --------------------------------------------------------------------------
# The model planner
# --------------------------------------------------------------------------

class Planner:
    """Builds plans, with the model when it can and without it when it cannot."""

    def __init__(self, catalog: Catalog, engine: Engine | None = None) -> None:
        self.catalog = catalog
        self.engine = engine
        self.index = Index.build(catalog)
        self.notes: list[PlanNote] = []
        #: The exchange in flight, held between asking and validating so that
        #: the transcript entry can carry what the guard did with the answer.
        self._exchange: logs.Exchange | None = None

    def plan(self, scan: Scan, *, ceiling: RiskTier = RiskTier.CAUTION,
             elevated: bool = True, budget: int = 8, cycle_id: str = "",
             require_model: bool = False) -> Plan:
        """Decide what to do about a scan.

        *require_model* makes the model the only decision-maker. Without it the
        built-in planner is a safety net - it runs when the model cannot, and
        it appends fixable findings the model neither chose nor deferred. With
        it, the model's answer is the whole plan, and a model that cannot
        answer means nothing is changed rather than something else quietly
        deciding instead.
        """
        self.notes = []
        self._exchange = None
        log = logs.get()
        fallback = builtin_plan(scan, self.catalog, ceiling=ceiling,
                                elevated=elevated, budget=budget)

        if not scan.findings:
            fallback.summary = (
                "Every control Lares checks is in the desired state. That means "
                "these particular checks passed, not that the machine is secure."
            )
            return fallback

        if self.engine is None or not self.engine.available:
            reason = self.engine.status if self.engine else "no model configured"
            if require_model:
                # Asked for the model to decide, and it cannot. Substituting a
                # different decision-maker without saying so would be the one
                # thing this mode exists to prevent.
                self.notes.append(PlanNote(
                    "warn",
                    f"Nothing was changed: the model is the only permitted "
                    f"decision-maker here and it is unavailable ({reason})."))
                log.warn("plan", "Model required but unavailable; changing nothing",
                         reason=reason, findings=len(scan.findings))
                return Plan(
                    actions=[],
                    summary=(
                        f"{len(scan.findings)} finding(s) are open, and none were "
                        "acted on. This machine is configured so that the model "
                        "decides what to do, and the model could not be reached: "
                        f"{reason}. Nothing was changed."),
                    deferred={f.control_id: "the model was unavailable to decide"
                              for f in scan.findings},
                    model_name="none available",
                )
            self.notes.append(PlanNote("info", f"Planned without the model: {reason}."))
            log.info("plan", "Planned without the model", reason=reason,
                     actions=len(fallback.actions))
            return fallback

        raw = self._ask_model(scan, ceiling, elevated, budget, cycle_id)
        if raw is None:
            if require_model:
                self._commit_exchange(
                    accepted=[], rejected={},
                    note="unusable answer; nothing changed, model required")
                self.notes.append(PlanNote(
                    "warn",
                    "Nothing was changed: the model is the only permitted "
                    "decision-maker here and its answer could not be used."))
                return Plan(
                    actions=[],
                    summary=("The model did not return a usable answer, and this "
                             "machine is configured so that only the model decides. "
                             "Nothing was changed."),
                    model_name=self.engine.name if self.engine else "",
                )
            self._commit_exchange(accepted=[], rejected={},
                                  note="unusable answer; built-in planner used")
            return fallback

        plan = self._validate(raw, scan, ceiling, elevated, budget,
                              require_model=require_model)
        self._commit_exchange(
            accepted=[a.control_id for a in plan.actions],
            rejected={k: v for k, v in plan.deferred.items()},
            parsed={"summary": plan.summary[:400],
                    "proposed": len(_as_list(raw.get("actions")))},
        )

        if not plan.actions and fallback.actions and not require_model:
            self.notes.append(PlanNote(
                "warn",
                "The model returned no usable actions, so the built-in planner was "
                "used instead. Nothing was skipped.",
            ))
            log.warn("plan", "Model produced no usable actions; used built-in planner",
                     fallback_actions=len(fallback.actions))
            fallback.summary = plan.summary or fallback.summary
            return fallback

        log.info("plan", f"Planned {len(plan.actions)} action(s)",
                 model=plan.model_name, deferred=len(plan.deferred))
        return plan

    def _commit_exchange(self, *, accepted: list[str], rejected: dict[str, str],
                         parsed: dict[str, Any] | None = None,
                         note: str = "") -> None:
        """Write the pending exchange to the transcript, with its consequences."""
        exchange = self._exchange
        self._exchange = None
        if exchange is None:
            return
        exchange.accepted = accepted
        exchange.rejected = rejected
        if parsed:
            exchange.parsed = parsed
        if note:
            exchange.parsed = dict(exchange.parsed, note=note)
        try:
            logs.transcript().record(exchange)
        except Exception:  # noqa: BLE001 - never fail a cycle over a log write
            pass

    # -- calling --------------------------------------------------------

    def _ask_model(self, scan: Scan, ceiling: RiskTier, elevated: bool,
                   budget: int, cycle_id: str = "") -> dict[str, Any] | None:
        queries = [f.observed or f.title for f in scan.by_severity()[:prompt_mod.MAX_FINDINGS]]
        must = {f.control_id for f in scan.findings}
        context = context_for(self.index, queries, must, limit=min(12, len(must) + 3))

        user = prompt_mod.build(scan, context, ceiling.value, elevated, budget)
        log = logs.get()
        log.debug("model", "Asking the model to plan",
                  findings=len(scan.findings), context=len(context), budget=budget)

        reply = self.engine.ask(  # type: ignore[union-attr]
            prompt_mod.SYSTEM, user, schema=prompt_mod.PLAN_SCHEMA,
        )

        # Build the transcript entry now, while the prompt and the raw reply are
        # both in hand. It is completed and written after validation, so that the
        # record shows not just what the model said but what was done with it.
        self._exchange = logs.Exchange(
            purpose="plan",
            model=self.engine.name if self.engine else "",
            system=prompt_mod.SYSTEM,
            prompt=user,
            reply=reply.text,
            ok=reply.ok,
            error=reply.error,
            tokens=reply.tokens,
            seconds=reply.seconds,
            cycle_id=cycle_id,
        )

        if not reply.ok:
            self.notes.append(PlanNote("warn", f"The model did not answer: {reply.error}"))
            log.warn("model", "The model did not answer", detail=reply.error)
            return None

        data = extract_json(reply.text)
        if data is None:
            self.notes.append(PlanNote(
                "warn", "The model's answer was not valid JSON; used the built-in planner."))
            log.warn("model", "The model's answer was not valid JSON",
                     reply_chars=len(reply.text), preview=reply.text[:200])
            return None

        self.notes.append(PlanNote(
            "info",
            f"{self.engine.name} planned in {reply.seconds:.1f}s "  # type: ignore[union-attr]
            f"({reply.tps:.1f} tokens/s).",
        ))
        log.info("model", f"{self.engine.name} answered",  # type: ignore[union-attr]
                 seconds=round(reply.seconds, 2), tokens=reply.tokens,
                 tps=round(reply.tps, 1))
        return data

    # -- validating -----------------------------------------------------

    def _validate(self, raw: dict[str, Any], scan: Scan, ceiling: RiskTier,
                  elevated: bool, budget: int, require_model: bool = False) -> Plan:
        """Turn the model's answer into a plan we are willing to execute."""
        actionable, blocked = _candidates(scan, self.catalog, ceiling, elevated)
        by_control: dict[str, list[Finding]] = {}
        for finding, _ in actionable:
            by_control.setdefault(finding.control_id, []).append(finding)

        deferred: dict[str, str] = dict(blocked)
        # Deferred entries go through the same catalogue check as actions.
        # They did not, and a 1.5B model on a real machine duly invented
        # SYS-006 "The system drive is not encrypted" and SYS-007 "The firewall
        # is not recording what it blocks" - plausible-sounding controls that
        # do not exist. They could never have been executed, because the guard
        # stops that, but they were displayed in "Left alone" as though Lares
        # had checked them and chosen not to act. Claiming to have checked
        # something you have not is worse than saying nothing.
        raw_deferred = raw.get("deferred")
        invented: list[str] = []
        if isinstance(raw_deferred, dict):
            for key, value in raw_deferred.items():
                control_id = str(key).strip().upper()
                if control_id not in self.catalog:
                    invented.append(control_id)
                    continue
                deferred.setdefault(control_id, str(value)[:300])

        if invented:
            self.notes.append(PlanNote(
                "warn",
                f"The model referred to {', '.join(sorted(invented))}, which "
                f"{'is' if len(invented) == 1 else 'are'} not in the catalogue. "
                "Not shown, because Lares did not check for them.",
            ))

        actions: list[PlannedAction] = []
        seen: set[str] = set()

        for item in _as_list(raw.get("actions")):
            if not isinstance(item, dict):
                continue
            control_id = str(item.get("control_id", "")).strip().upper()
            control = self.catalog.get(control_id)

            if control is None:
                self.notes.append(PlanNote(
                    "warn",
                    f"The model proposed {control_id or '<blank>'}, which is not in the "
                    "catalogue. Dropped.",
                ))
                continue

            ok, why = _eligible(control, ceiling, elevated)
            if not ok:
                deferred.setdefault(control.id, why)
                self.notes.append(PlanNote(
                    "warn", f"The model proposed {control.id}, which {why}. Dropped."))
                continue

            params = self._resolve_params(item.get("params"), control_id, by_control)
            key = f"{control_id}:{sorted(params.items())}"
            if key in seen:
                continue
            seen.add(key)

            actions.append(PlannedAction(
                control_id=control.id,
                params=params,
                rationale=_trim(str(item.get("rationale", "") or "")),
                confidence=_clamp_int(item.get("confidence"), 50),
                order=_clamp_int(item.get("order"), len(actions) + 1),
            ))

        if not require_model:
            actions = self._append_forgotten(actions, seen, actionable, deferred, budget)
        elif len(actions) < len(actionable):
            # The model's answer is the whole plan here, so anything it left out
            # stays out - but silence is not the same as a decision, and the
            # operator should be able to see what was dropped without one.
            chosen = {a.control_id for a in actions}
            for finding, control in actionable:
                if control.id not in chosen:
                    deferred.setdefault(
                        control.id, "the model did not choose it this cycle")
        actions = actions[:budget]

        ordered_ids = self.catalog.resolve_order([a.control_id for a in actions])
        rank = {cid: i for i, cid in enumerate(ordered_ids)}
        for action in actions:
            action.order = rank.get(action.control_id, 99) + 1
        actions.sort(key=lambda a: (a.order, a.control_id, str(sorted(a.params.items()))))

        summary = str(raw.get("summary", "") or "").strip()[:1200]
        return Plan(
            actions=actions,
            summary=summary or "The model did not summarise this machine.",
            deferred=deferred,
            model_name=self.engine.name if self.engine else "",
        )

    def _resolve_params(self, supplied: Any, control_id: str,
                        by_control: dict[str, list[Finding]]) -> dict[str, Any]:
        """Decide which parameters this action really carries.

        The scan already discovered the correct values - which port, which
        profile, what the registry held before. Those are facts, and preferring
        the model's guess over a measurement would be strange. So a discovered
        value wins, and the model's parameters only fill gaps or pick between
        several findings for the same control.

        Keys the control does not declare are dropped here rather than passed
        on. The guard refuses an action carrying an undeclared parameter, and
        it is right to - but a small model that helpfully adds
        ``"reason": "rdp exposed"`` beside two perfectly good discovered values
        would otherwise block a fix the scan had already worked out in full.
        Dropping noise the catalogue never asked for is not the same as
        loosening the guard, which still sees and rejects anything unexpected.
        """
        findings = by_control.get(control_id, [])
        model_params = dict(supplied) if isinstance(supplied, dict) else {}

        control = self.catalog.get(control_id)
        if control is not None and model_params:
            declared = {spec.name for spec in control.params}
            undeclared = sorted(set(model_params) - declared)
            if undeclared:
                for key in undeclared:
                    model_params.pop(key, None)
                self.notes.append(PlanNote(
                    "info",
                    f"The model added {undeclared} to {control_id}, which the "
                    "control does not take. Dropped; the scan's own values were used.",
                ))

        if not findings:
            return model_params
        if len(findings) == 1:
            merged = dict(model_params)
            merged.update(findings[0].params)
            return merged

        # Several instances of the same control. Match on whatever the model
        # supplied; if nothing matches, take the first and note the ambiguity.
        for finding in findings:
            if all(str(finding.params.get(k)) == str(v) for k, v in model_params.items()):
                return dict(finding.params)

        self.notes.append(PlanNote(
            "warn",
            f"The model's parameters for {control_id} matched none of the "
            f"{len(findings)} findings; used the most severe one.",
        ))
        return dict(findings[0].params)

    def _append_forgotten(self, actions: list[PlannedAction], seen: set[str],
                          actionable: list[tuple[Finding, Control]],
                          deferred: dict[str, str], budget: int) -> list[PlannedAction]:
        """Add fixes the model neither planned nor gave a reason for skipping.

        A model this size will sometimes just stop generating, or lose an item
        from a list of twelve. That is a generation artefact, not a decision, and
        a security tool must not quietly leave a critical finding unfixed because
        of one. An explicit entry in "deferred" is respected; silence is not.
        """
        if len(actions) >= budget:
            return actions

        room = budget - len(actions)
        missed: list[tuple[Finding, Control]] = []
        for finding, control in sorted(actionable, key=_sort_key):
            key = f"{control.id}:{sorted(finding.params.items())}"
            if key in seen or control.id in deferred:
                continue
            missed.append((finding, control))

        for finding, control in missed[:room]:
            actions.append(PlannedAction(
                control_id=control.id,
                params=dict(finding.params),
                rationale=_builtin_rationale(finding, control),
                confidence=60,
                order=len(actions) + 1,
            ))

        if missed:
            self.notes.append(PlanNote(
                "info",
                f"{min(len(missed), room)} finding(s) the model did not mention were "
                "added by the built-in planner.",
            ))
        return actions


# --------------------------------------------------------------------------

def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _trim(text: str, limit: int = 400) -> str:
    """Shorten a rationale without cutting a word in half.

    The model writes to whatever length it likes and the display has a budget.
    Slicing at a fixed offset ended a real plan on "...which is reading the
    mem", which reads like the program broke rather than like a sentence was
    too long.
    """
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",;:")
    return f"{cut}..."


def _clamp_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(999, number))
