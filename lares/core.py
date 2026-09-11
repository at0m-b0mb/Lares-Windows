"""Domain types shared by every layer of Lares.

The flow through these types is the whole architecture in miniature:

    sense/   produces  Fact + Finding
    brain/   consumes  Fact + Finding + Control  ->  produces Plan
    act/     consumes  Plan + Control            ->  produces Outcome
    journal  records   Outcome                   ->  enables rollback

Nothing in this module imports Windows, Qt, or the language model. It is pure
data so that the grading and planning logic can be tested on any machine.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Sequence


def utcnow() -> str:
    """ISO-8601 UTC timestamp, second resolution, always suffixed with Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------
# Severity — how bad the *problem* is
# --------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    # All four comparisons are defined, and that is not belt-and-braces.
    # Severity subclasses str so that it serialises cleanly, which means it
    # inherits str's comparison operators. Overriding only __lt__ leaves `>`
    # falling through to alphabetical string comparison, where "high" < "medium"
    # and max() of a set of findings returns the wrong one. That silently
    # mis-stated the worst finding on a machine in every report.
    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# --------------------------------------------------------------------------
# RiskTier — how dangerous the *fix* is
#
# This is deliberately a separate axis from Severity. A critical finding can
# have a perfectly safe fix (turn the firewall back on), and a low finding can
# have an intrusive one (rename the built-in Administrator account). The
# autonomous loop gates on RiskTier, never on Severity.
# --------------------------------------------------------------------------

class RiskTier(str, Enum):
    #: Reversible, no service interruption, no user-visible behaviour change.
    SAFE = "safe"
    #: Reversible but may interrupt a session or a service momentarily.
    CAUTION = "caution"
    #: Changes how the machine is reached or who can use it. Never autonomous.
    INTRUSIVE = "intrusive"

    @property
    def rank(self) -> int:
        return {RiskTier.SAFE: 0, RiskTier.CAUTION: 1, RiskTier.INTRUSIVE: 2}[self]


# --------------------------------------------------------------------------
# Outcome status
# --------------------------------------------------------------------------

class Status(str, Enum):
    #: Executor declined before running anything (guard, schema, or policy).
    REFUSED = "refused"
    #: Policy said do not act now (tier above autonomy ceiling, budget spent).
    SKIPPED = "skipped"
    #: Dry run only; nothing was changed.
    SIMULATED = "simulated"
    #: Applied and the detection probe confirms the problem is gone.
    VERIFIED = "verified"
    #: Applied, but the probe still reports the problem. Left in place.
    UNVERIFIED = "unverified"
    #: Applied then undone, because verification or a health check failed.
    ROLLED_BACK = "rolled_back"
    #: The remediation script itself errored. Rollback attempted.
    FAILED = "failed"

    @property
    def is_change(self) -> bool:
        """True if the machine was actually touched (even if later undone)."""
        return self in (Status.VERIFIED, Status.UNVERIFIED, Status.ROLLED_BACK, Status.FAILED)


# --------------------------------------------------------------------------
# Facts — what the machine *is*
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Fact:
    """One observed property of the system, for context and for the model.

    Facts are never graded. They answer "what is this machine", which is the
    half of the prompt that lets the model reason about whether a control even
    applies (a control that edits Server settings is pointless on Home).
    """

    key: str
    value: str
    domain: str = "system"
    #: Set when the value should not appear in exported reports verbatim.
    sensitive: bool = False

    def redacted(self) -> "Fact":
        if not self.sensitive:
            return self
        return Fact(self.key, "[redacted]", self.domain, True)


# --------------------------------------------------------------------------
# Findings — what is *wrong*
# --------------------------------------------------------------------------

@dataclass
class Finding:
    """A detected deviation from a hardened state.

    A Finding is always produced by a control's own detection probe, so
    ``control_id`` is the join key that lets the executor look up the matching
    remediation and, crucially, re-run the same probe afterwards to verify.
    """

    control_id: str
    title: str
    severity: Severity
    detail: str = ""
    #: Raw evidence: the command output or value that triggered the finding.
    evidence: str = ""
    #: Parameters the probe discovered, passed through to the remediation.
    #: e.g. {"port": 3389, "rule_name": "RDP-In"} — validated before use.
    params: dict[str, Any] = field(default_factory=dict)
    observed: str = ""
    expected: str = ""
    domain: str = "system"
    #: False when the catalogue has no remediation (report-only finding).
    remediable: bool = True
    detected_at: str = field(default_factory=utcnow)

    def key(self) -> str:
        """Stable identity for deduplication across scans."""
        if not self.params:
            return self.control_id
        bits = ",".join(f"{k}={self.params[k]}" for k in sorted(self.params))
        return f"{self.control_id}[{bits}]"


# --------------------------------------------------------------------------
# Controls — the vetted catalogue entry
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ParamSpec:
    """Declared shape of one remediation parameter.

    The executor validates model-supplied parameters against these before a
    single character reaches PowerShell. This is what makes it impossible for
    the model to smuggle a command through a parameter slot.
    """

    name: str
    type: str  # "int" | "string" | "enum" | "bool" | "path"
    required: bool = True
    minimum: int | None = None
    maximum: int | None = None
    #: Allowed values for type == "enum".
    choices: tuple[str, ...] = ()
    #: Full-match regex for type == "string" / "path".
    pattern: str | None = None
    description: str = ""


@dataclass(frozen=True)
class Control:
    """One hardening control: how to see it, how to fix it, how to undo it.

    Every field here is written and reviewed by a human. The language model
    selects and parameterizes controls; it does not author them. That is the
    single property that makes autonomous remediation reversible.
    """

    id: str
    title: str
    domain: str
    severity: Severity
    risk: RiskTier
    #: One paragraph, plain English, no jargon — shown to the user and given
    #: to the model as retrieval context.
    rationale: str
    #: PowerShell that prints a JSON object describing current state.
    detect: str
    #: PowerShell that applies the fix. May reference {param} placeholders.
    remediate: str = ""
    #: PowerShell that undoes exactly what remediate did.
    rollback: str = ""
    #: "script"       - rollback body undoes the change (the normal case)
    #: "additive"     - remediation only adds or refreshes state, so there is
    #:                  nothing to undo (refreshing AV signatures, say)
    #: "irreversible" - prior state is destroyed; never runs autonomously
    rollback_policy: str = "script"
    #: Required justification when rollback_policy is not "script".
    rollback_note: str = ""
    #: When the change actually starts working: "immediate", "logon" or
    #: "restart". This decides how the executor reads a detection probe that
    #: still reports the problem straight after a successful remediation - for
    #: a restart-scoped control that is expected, and undoing it would throw
    #: away a correct change.
    effective: str = "immediate"
    params: tuple[ParamSpec, ...] = ()
    #: Controls that must be applied before this one.
    depends_on: tuple[str, ...] = ()
    #: Free-text references (CIS benchmark item, Microsoft doc, CVE).
    references: tuple[str, ...] = ()
    #: Windows editions/versions this applies to; empty means all.
    applies_to: tuple[str, ...] = ()
    #: When true, applying this needs an elevated process.
    needs_admin: bool = True
    #: Human note on what could go wrong. Surfaced in the journal.
    blast_radius: str = ""
    tags: tuple[str, ...] = ()

    @property
    def has_remediation(self) -> bool:
        return bool(self.remediate.strip())

    @property
    def is_reversible(self) -> bool:
        """True when this change can be put back the way it was.

        "additive" counts as reversible for autonomy purposes: there is nothing
        to undo because nothing was replaced. Only "irreversible" destroys prior
        state, and that is what the autonomy gate actually cares about.
        """
        if self.rollback_policy == "irreversible":
            return False
        if self.rollback_policy == "additive":
            return True
        return bool(self.rollback.strip())

    @property
    def deferred_effect(self) -> bool:
        """True when the fix cannot possibly verify until a restart or re-logon."""
        return self.effective in ("restart", "logon")

    @property
    def autonomy_eligible(self) -> bool:
        """Whether the loop may ever apply this without a human present.

        Three independent conditions, all required: there is something to run,
        it can be put back, and it is not in the tier that changes how the
        machine is reached.
        """
        return (
            self.has_remediation
            and self.is_reversible
            and self.risk is not RiskTier.INTRUSIVE
        )

    def param(self, name: str) -> ParamSpec | None:
        for spec in self.params:
            if spec.name == name:
                return spec
        return None


# --------------------------------------------------------------------------
# Plan — what the model decided
# --------------------------------------------------------------------------

@dataclass
class PlannedAction:
    """One step the model wants taken, before any validation has happened."""

    control_id: str
    params: dict[str, Any] = field(default_factory=dict)
    #: The model's own words on why this, why now, why in this order.
    rationale: str = ""
    #: Model's confidence 0-100. Advisory only; policy never trusts it alone.
    confidence: int = 50
    order: int = 0


@dataclass
class Plan:
    """The model's full response for one scan, after schema validation."""

    actions: list[PlannedAction] = field(default_factory=list)
    #: Plain-English summary of the machine's posture, for the operator.
    summary: str = ""
    #: Controls the model explicitly chose to leave alone, and why.
    deferred: dict[str, str] = field(default_factory=dict)
    plan_id: str = field(default_factory=lambda: new_id("plan"))
    created_at: str = field(default_factory=utcnow)
    #: Which model produced it, for the journal.
    model_name: str = ""
    #: True when the planner fell back to catalogue ordering because the model
    #: was unavailable or returned nothing usable. The loop still runs.
    fallback: bool = False

    def ordered(self) -> list[PlannedAction]:
        return sorted(self.actions, key=lambda a: (a.order, a.control_id))


# --------------------------------------------------------------------------
# Outcome — what actually happened
# --------------------------------------------------------------------------

@dataclass
class Outcome:
    """The executor's record of one action attempt.

    This is what lands in the journal, and it carries everything needed to
    undo the change later without re-consulting the model.
    """

    control_id: str
    status: Status
    params: dict[str, Any] = field(default_factory=dict)
    #: Human-readable one-liner: what happened and why.
    message: str = ""
    #: Guard or validation reason when status is REFUSED.
    refusal_reason: str = ""
    #: Captured stdout/stderr from the remediation script.
    output: str = ""
    #: Identifier of the snapshot taken before this change.
    snapshot_id: str = ""
    #: The exact rollback script, with parameters already substituted.
    rollback_script: str = ""
    #: State the detection probe reported before and after.
    before: str = ""
    after: str = ""
    duration_ms: int = 0
    at: str = field(default_factory=utcnow)
    action_id: str = field(default_factory=lambda: new_id("act"))

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# --------------------------------------------------------------------------
# Scan — one full pass over the machine
# --------------------------------------------------------------------------

@dataclass
class Scan:
    facts: list[Fact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    #: Collectors that raised, keyed by collector name.
    errors: dict[str, str] = field(default_factory=dict)
    scan_id: str = field(default_factory=lambda: new_id("scan"))
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""
    #: True when the data came from demo_data rather than the live machine.
    demo: bool = False
    duration_ms: int = 0

    def by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.control_id))

    def counts(self) -> dict[Severity, int]:
        out = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def fact(self, key: str, default: str = "") -> str:
        for f in self.facts:
            if f.key == key:
                return f.value
        return default

    def facts_in(self, domain: str) -> list[Fact]:
        return [f for f in self.facts if f.domain == domain]

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


# --------------------------------------------------------------------------
# Cycle — one autonomous sense -> think -> act -> verify round
# --------------------------------------------------------------------------

@dataclass
class Cycle:
    scan: Scan
    plan: Plan
    outcomes: list[Outcome] = field(default_factory=list)
    cycle_id: str = field(default_factory=lambda: new_id("cyc"))
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""
    #: Set when the circuit breaker stopped the cycle early.
    halted: str = ""

    @property
    def changed(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.status.is_change]

    @property
    def fixed(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.status is Status.VERIFIED]

    @property
    def reverted(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.status is Status.ROLLED_BACK]

    def summary_line(self) -> str:
        return (
            f"{len(self.fixed)} fixed, {len(self.reverted)} rolled back, "
            f"{len(self.scan.findings)} findings, worst {self.scan.worst.value}"
        )


# --------------------------------------------------------------------------
# Serialisation helpers
# --------------------------------------------------------------------------

def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses and enums into JSON-safe values."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def dumps(obj: Any, indent: int | None = 2) -> str:
    return json.dumps(to_jsonable(obj), indent=indent, ensure_ascii=False)


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse findings that share a key, keeping the most severe."""
    best: dict[str, Finding] = {}
    for f in findings:
        k = f.key()
        if k not in best or f.severity.rank > best[k].severity.rank:
            best[k] = f
    return list(best.values())


def severity_of(findings: Sequence[Finding]) -> Severity:
    return max((f.severity for f in findings), key=lambda s: s.rank,
               default=Severity.INFO)
