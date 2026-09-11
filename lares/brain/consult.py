"""The model-led investigation.

The ordinary cycle hands the model a finished scan and asks it to choose what
to fix. This is the other way round: the model is asked what it wants to look
at, the answers are fetched, and it is asked again, until it says it has seen
enough and gives a verdict. Nothing is looked at that it did not ask for, and
nothing is changed that it did not choose.

    round 1   "what do you want to look at on this machine?"
              -> {"ask": {"facts": true, "domains": ["network"]}}
    round 2   here is what those said. anything else?
              -> {"ask": {"controls": ["IDN-005", "SYS-001"]}}
    round 3   here is what those said. anything else?
              -> {"assessment": "...", "actions": [...]}

What it may ask for is bounded, and that is the point rather than a
limitation. It can request machine facts, a whole domain, or named controls -
and every one of those is a **detection probe from the catalogue**, written by
a person, read-only, with no parameters the model supplies. So the model
directs the investigation without being able to invent what the investigation
does. The same holds at the end: its verdict is put through exactly the same
guard as any other plan, and it can only name remediations that already exist.

Two practical notes. Each round is a full inference pass, so on the hardware
this targets - four cores and a few gigabytes - a three-round consultation is
several minutes of thinking. The round budget is therefore small and explicit.
And a model that never stops asking is a model that never answers, so when the
rounds run out it is told to give its verdict on what it has.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import logs
from ..catalog.loader import Catalog
from ..core import Finding, Plan, RiskTier, Scan
from .engine import Engine, extract_json
from .plan import Planner, PlanNote
from .retrieve import brief

#: Rounds of questions before the model is required to answer. Each one is a
#: full inference pass; three is already minutes on a slow CPU.
MAX_ROUNDS = 3

#: Probes to run in one request. A model that asks for everything gets the
#: scan it would have been handed anyway, which is a fine outcome but should
#: not take longer than that.
MAX_PROBES_PER_ASK = 12


CONSULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "ask": {
            "type": "object",
            "properties": {
                "facts": {"type": "boolean"},
                "domains": {"type": "array", "items": {"type": "string"}},
                "controls": {"type": "array", "items": {"type": "string"}},
            },
        },
        "why": {"type": "string"},
        "assessment": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "control_id": {"type": "string"},
                    "rationale": {"type": "string"},
                    "order": {"type": "integer"},
                },
                "required": ["control_id", "rationale"],
            },
        },
        "deferred": {"type": "object"},
    },
}


SYSTEM = """You are inspecting one Windows machine. You decide what to look at \
and what to do about what you find.

You cannot run commands. You ask for readings, and each reading is a \
pre-written, reviewed, read-only check from a fixed catalogue. Reply with \
exactly one JSON object and nothing else.

To look at something:

  {"ask": {"facts": true, "domains": ["network"], "controls": ["IDN-005"]},
   "why": "one sentence on what you are trying to establish"}

  facts     - what this machine is: Windows edition, accounts, network, disk
  domains   - every check in a domain: network, identity, defence, services, system
  controls  - named checks, by id

To give your verdict, when you have seen enough:

  {"assessment": "what is wrong with this machine, in plain English",
   "actions": [{"control_id": "NET-005", "rationale": "why this, now", "order": 1}],
   "deferred": {"DEF-007": "why you are leaving this alone"}}

Rules:
1. Every control_id you name, in actions or deferred, MUST be one you were \
shown. Do not invent ids. If something concerns you and has no control, say so \
in your assessment instead.
2. Only name a control in "actions" if its reading showed a problem.
3. Ask before you conclude. A verdict on a machine you have not looked at is \
worth nothing.
4. Prefer fewer, well-reasoned actions to a long list."""


@dataclass
class Round:
    """One exchange in the consultation, for the record."""

    number: int
    asked: dict[str, Any] = field(default_factory=dict)
    why: str = ""
    probed: list[str] = field(default_factory=list)
    findings: int = 0
    seconds: float = 0.0
    error: str = ""

    def describe(self) -> str:
        if self.error:
            return f"round {self.number}: {self.error}"
        if not self.asked:
            return f"round {self.number}: gave its verdict"
        wanted = []
        if self.asked.get("facts"):
            wanted.append("machine facts")
        for domain in self.asked.get("domains", []) or []:
            wanted.append(f"the {domain} domain")
        controls = self.asked.get("controls", []) or []
        if controls:
            wanted.append(", ".join(controls[:6]) + ("..." if len(controls) > 6 else ""))
        return (f"round {self.number}: asked for {'; '.join(wanted) or 'nothing'}"
                f" -> {self.findings} problem(s) in {len(self.probed)} check(s)")


@dataclass
class Consultation:
    """Everything that happened, and what came of it."""

    rounds: list[Round] = field(default_factory=list)
    scan: Scan = field(default_factory=Scan)
    plan: Plan = field(default_factory=Plan)
    assessment: str = ""
    notes: list[PlanNote] = field(default_factory=list)
    #: True when the model gave a verdict of its own rather than being made to.
    concluded: bool = False

    @property
    def probes_run(self) -> int:
        return sum(len(r.probed) for r in self.rounds)


class Consultant:
    """Runs a model-led investigation of one machine."""

    def __init__(self, catalog: Catalog, engine: Engine, *,
                 max_rounds: int = MAX_ROUNDS) -> None:
        self.catalog = catalog
        self.engine = engine
        self.max_rounds = max(1, max_rounds)
        self.planner = Planner(catalog, engine)
        self._verdict: dict[str, Any] | None = None

    # -- the loop -------------------------------------------------------

    def run(self, *, ceiling: RiskTier = RiskTier.CAUTION, elevated: bool = True,
            budget: int = 8, progress=None) -> Consultation:
        """Ask, look, ask again, then act on the verdict."""
        from ..sense import facts as facts_mod
        from ..sense import scanner

        log = logs.get()
        result = Consultation()
        transcript: list[str] = [self._opening()]
        seen_controls: set[str] = set()

        for number in range(1, self.max_rounds + 1):
            final = number == self.max_rounds
            if progress:
                progress(f"asking the model what to look at (round {number})")

            reply = self.engine.ask(
                SYSTEM,
                "\n\n".join(transcript) + ("\n\n" + _LAST_ROUND if final else ""),
                schema=CONSULT_SCHEMA,
            )
            round_ = Round(number=number, seconds=reply.seconds)

            if not reply.ok:
                round_.error = f"the model did not answer ({reply.error})"
                result.rounds.append(round_)
                log.warn("model", "Consultation round failed", round=number,
                         detail=reply.error)
                break

            answer = extract_json(reply.text)
            if answer is None:
                round_.error = "the model's answer was not usable JSON"
                result.rounds.append(round_)
                log.warn("model", "Consultation round returned unusable JSON",
                         round=number, preview=reply.text[:200])
                break

            self._record(reply, answer, number)

            # -- a verdict ------------------------------------------------
            if answer.get("actions") is not None or answer.get("assessment"):
                result.assessment = str(answer.get("assessment", "") or "").strip()
                result.concluded = True
                # Kept for _finalise, which puts it through the ordinary guard
                # rather than trusting it because it arrived by this route.
                self._verdict = answer
                result.rounds.append(round_)
                if progress:
                    progress("the model has reached a verdict")
                break

            # -- a request ------------------------------------------------
            wanted = answer.get("ask")
            if not isinstance(wanted, dict) or not wanted:
                round_.error = "the model neither asked for anything nor concluded"
                result.rounds.append(round_)
                break

            round_.asked = wanted
            round_.why = str(answer.get("why", "") or "")[:300]

            if wanted.get("facts") and not result.scan.facts:
                if progress:
                    progress("reading what this machine is")
                result.scan.facts = facts_mod.gather()
                transcript.append("MACHINE FACTS\n" + _render_facts(result.scan))

            controls = self._resolve(wanted, seen_controls)
            if controls:
                if progress:
                    progress(f"running {len(controls)} check(s) the model asked for")
                partial = scanner.scan(self.catalog,
                                       only=[c.id for c in controls])
                result.scan.findings.extend(partial.findings)
                result.scan.errors.update(partial.errors)
                round_.probed = [c.id for c in controls]
                round_.findings = len(partial.findings)
                seen_controls.update(round_.probed)
                transcript.append(self._render_readings(controls, partial))
            elif not wanted.get("facts"):
                transcript.append(
                    "Nothing matched what you asked for. Ask for a domain "
                    "(network, identity, defence, services, system) or name "
                    "controls from the list you were given.")

            result.rounds.append(round_)
            answer = None

        # -- turn the verdict into a plan the executor will take ----------
        result.plan = self._finalise(result, ceiling, elevated, budget)
        result.notes = list(self.planner.notes)
        log.info("model", "Consultation finished",
                 rounds=len(result.rounds), probes=result.probes_run,
                 concluded=result.concluded, actions=len(result.plan.actions))
        return result

    # -- pieces ---------------------------------------------------------

    def _opening(self) -> str:
        domains = ", ".join(self.catalog.domains)
        listing = "\n".join(
            f"  {c.id}  [{c.domain}] {c.title}" for c in sorted(
                self.catalog, key=lambda c: c.id))
        return (
            "This is a Windows machine you have not looked at yet.\n\n"
            f"Checks available, in domains {domains}:\n{listing}\n\n"
            "What would you like to look at first?"
        )

    def _resolve(self, wanted: dict[str, Any], already: set[str]) -> list:
        """Turn a request into real controls, ignoring anything invented."""
        chosen: dict[str, Any] = {}

        for domain in wanted.get("domains", []) or []:
            for control in self.catalog.in_domain(str(domain).strip().lower()):
                if control.id not in already:
                    chosen[control.id] = control

        for raw in wanted.get("controls", []) or []:
            control = self.catalog.get(str(raw).strip().upper())
            if control is not None and control.id not in already:
                chosen[control.id] = control

        return list(chosen.values())[:MAX_PROBES_PER_ASK]

    def _render_readings(self, controls: list, partial: Scan) -> str:
        """What the checks said, in the model's own terms."""
        problems = {f.control_id: f for f in partial.findings}
        lines = ["WHAT THOSE CHECKS FOUND"]
        for control in controls:
            finding = problems.get(control.id)
            if finding is not None:
                lines.append(
                    f"  {control.id}  PROBLEM ({finding.severity.value}): "
                    f"{finding.observed or control.title}")
            elif control.id in partial.errors:
                lines.append(f"  {control.id}  could not be read: "
                             f"{partial.errors[control.id][:120]}")
            else:
                lines.append(f"  {control.id}  fine: no problem found")

        if problems:
            lines.append("")
            lines.append("Detail on what is wrong:")
            for control in controls:
                if control.id in problems:
                    lines.append(brief(control, include_params=False))
        lines.append("")
        lines.append("Ask for more, or give your verdict.")
        return "\n".join(lines)

    def _record(self, reply, answer: dict[str, Any], number: int) -> None:
        try:
            logs.transcript().record(logs.Exchange(
                purpose=f"consult-{number}",
                model=self.engine.name,
                system=SYSTEM,
                prompt=f"(consultation round {number})",
                reply=reply.text,
                ok=reply.ok,
                error=reply.error,
                tokens=reply.tokens,
                seconds=reply.seconds,
                parsed={"kind": "verdict" if answer.get("actions") is not None
                                else "question"},
            ))
        except Exception:  # noqa: BLE001 - never fail a consultation over a log
            pass

    def _finalise(self, result: Consultation, ceiling: RiskTier,
                  elevated: bool, budget: int) -> Plan:
        """Put the model's verdict through the ordinary guard.

        Reusing the planner's validator is deliberate. A model-led
        consultation must not be a second, looser path into the executor: the
        same checks apply to what it decided here as to anything else, and
        require_model is on because the entire premise is that the model
        decides.
        """
        result.scan.findings = _dedupe(result.scan.findings)

        if not result.concluded:
            self.planner.notes = [PlanNote(
                "warn",
                "The model never reached a verdict, so nothing was planned. "
                "What it looked at is recorded above.")]
            return Plan(actions=[], summary=result.assessment or
                        "The model did not reach a verdict.",
                        model_name=self.engine.name)

        raw = self._verdict or {}
        plan = self.planner._validate(
            {"summary": result.assessment,
             "actions": raw.get("actions", []),
             "deferred": raw.get("deferred", {})},
            result.scan, ceiling, elevated, budget, require_model=True)
        plan.model_name = self.engine.name
        return plan


_LAST_ROUND = (
    "This is your last round. Do not ask for anything more - give your "
    "verdict now, on what you have seen."
)


def _render_facts(scan: Scan) -> str:
    return "\n".join(f"  {f.key}: {f.value}" for f in scan.facts) or "  (none read)"


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[str, Finding] = {}
    for finding in findings:
        key = finding.key()
        if key not in best or finding.severity.rank > best[key].severity.rank:
            best[key] = finding
    return sorted(best.values(), key=lambda f: (-f.severity.rank, f.control_id))
