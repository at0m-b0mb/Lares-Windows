"""Loading and validating the control catalogue.

The catalogue is the trust boundary of the whole application. The language
model can name a control and supply parameters; it can never introduce one.
Everything the executor is capable of doing is written here, in YAML, by a
human, with a rollback beside it.

Because that is the case, the catalogue is validated hard at load time:

* every control must declare a detection probe;
* every control with a remediation must also carry a rollback, unless it
  declares ``rollback_policy: additive`` (nothing is replaced, so there is
  nothing to undo) or ``rollback_policy: irreversible`` (which bars it from
  ever running autonomously);
* every ``{placeholder}`` in a script must correspond to a declared parameter,
  and every declared parameter must be used somewhere;
* string and path parameters must declare a regex, because an unconstrained
  one is a command-injection slot;
* parameter specs must be self-consistent (an enum needs choices, a bounded
  int needs sane bounds);
* no unrecognised keys, so that a typo in ``rollback`` or ``blast_radius`` is
  a loud failure rather than a silently dropped safety property.

A catalogue that fails any of these raises at startup rather than at 3am in
the middle of an unattended remediation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator

import yaml

from ..core import Control, ParamSpec, RiskTier, Severity

CONTROLS_DIR = Path(__file__).resolve().parent / "controls"

#: Parameter types the executor knows how to validate.
PARAM_TYPES = {"int", "string", "enum", "bool", "path"}

#: How a control's change can be undone. See Control.rollback_policy.
ROLLBACK_POLICIES = {"script", "additive", "irreversible"}

_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

_ID_RE = re.compile(r"^[A-Z]{2,6}-[0-9]{3}$")


class CatalogError(ValueError):
    """Raised when the catalogue on disk is not fit to execute from."""


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def _parse_param(raw: dict[str, Any], control_id: str) -> ParamSpec:
    name = str(raw.get("name", "")).strip()
    if not name or not name.isidentifier():
        raise CatalogError(f"{control_id}: parameter name {name!r} is not a valid identifier")

    ptype = str(raw.get("type", "string")).strip()
    if ptype not in PARAM_TYPES:
        raise CatalogError(f"{control_id}.{name}: unknown parameter type {ptype!r}")

    raw_choices = raw.get("choices")
    # YAML 1.1 reads bare Off/On/Yes/No/True/False as booleans, so a choice list
    # written as [Off, Warn, Block] silently becomes [False, 'Warn', 'Block'] and
    # then never matches what the probe reports. Catch it here rather than at the
    # moment a remediation is refused on a live machine.
    if isinstance(raw_choices, list):
        for choice in raw_choices:
            if isinstance(choice, bool):
                raise CatalogError(
                    f"{control_id}.{name}: the choice {choice!r} was parsed as a boolean. "
                    "YAML treats bare Off/On/Yes/No/True/False that way - quote it, "
                    'as in choices: ["Off", "Warn"].'
                )

    choices = _as_tuple(raw_choices)
    if ptype == "enum" and not choices:
        raise CatalogError(f"{control_id}.{name}: enum parameter needs a choices list")
    if ptype != "enum" and choices:
        raise CatalogError(f"{control_id}.{name}: choices only apply to enum parameters")
    if len(set(choices)) != len(choices):
        raise CatalogError(f"{control_id}.{name}: duplicate values in choices")

    minimum = raw.get("min")
    maximum = raw.get("max")
    if ptype != "int" and (minimum is not None or maximum is not None):
        raise CatalogError(f"{control_id}.{name}: min/max only apply to int parameters")
    if minimum is not None and maximum is not None and int(minimum) > int(maximum):
        raise CatalogError(f"{control_id}.{name}: min {minimum} exceeds max {maximum}")

    pattern = raw.get("pattern")
    if pattern is not None:
        if ptype not in ("string", "path"):
            raise CatalogError(f"{control_id}.{name}: pattern only applies to string/path")
        try:
            re.compile(str(pattern))
        except re.error as exc:
            raise CatalogError(f"{control_id}.{name}: bad pattern regex - {exc}") from exc
    if ptype in ("string", "path") and pattern is None:
        raise CatalogError(
            f"{control_id}.{name}: string and path parameters must declare a pattern; "
            "an unconstrained parameter is a command-injection slot"
        )

    return ParamSpec(
        name=name,
        type=ptype,
        required=bool(raw.get("required", True)),
        minimum=int(minimum) if minimum is not None else None,
        maximum=int(maximum) if maximum is not None else None,
        choices=choices,
        pattern=str(pattern) if pattern is not None else None,
        description=str(raw.get("description", "")).strip(),
    )


def _placeholders(script: str) -> set[str]:
    """Names used as ``{name}`` in a script body.

    PowerShell uses braces for script blocks and hashtables, so we only treat
    a brace pair as a placeholder when it wraps a bare lowercase identifier.
    That is why the placeholder grammar is deliberately narrow.
    """
    return set(_PLACEHOLDER.findall(script))


#: Every key a control YAML document may carry. A typo in a key name would
#: otherwise be silently ignored, and silently ignoring `blast_radius` or
#: `rollback` in a tool that edits system settings is not acceptable.
CONTROL_KEYS = {
    "id", "title", "domain", "severity", "risk", "rationale", "detect",
    "remediate", "rollback", "rollback_policy", "rollback_note", "params",
    "depends_on", "references", "applies_to", "needs_admin", "blast_radius",
    "tags", "effective",
}

#: When a control's change starts working. See Control.effective.
EFFECTIVE_KINDS = {"immediate", "logon", "restart"}


def parse_control(raw: dict[str, Any], source: Path) -> Control:
    cid = str(raw.get("id", "")).strip()
    if not _ID_RE.match(cid):
        raise CatalogError(f"{source.name}: control id {cid!r} must look like NET-001")

    unknown = set(raw) - CONTROL_KEYS
    if unknown:
        raise CatalogError(
            f"{cid}: unknown key(s) {sorted(unknown)} - check for a typo, since an "
            "unrecognised key is ignored rather than applied"
        )

    try:
        severity = Severity(str(raw.get("severity", "medium")).lower())
    except ValueError as exc:
        raise CatalogError(f"{cid}: unknown severity {raw.get('severity')!r}") from exc
    try:
        risk = RiskTier(str(raw.get("risk", "caution")).lower())
    except ValueError as exc:
        raise CatalogError(f"{cid}: unknown risk tier {raw.get('risk')!r}") from exc

    detect = str(raw.get("detect", "")).strip()
    if not detect:
        raise CatalogError(f"{cid}: every control needs a detect probe")

    remediate = str(raw.get("remediate", "") or "").strip()
    rollback = str(raw.get("rollback", "") or "").strip()
    policy = str(raw.get("rollback_policy", "script")).strip().lower()
    note = str(raw.get("rollback_note", "") or "").strip()

    if policy not in ROLLBACK_POLICIES:
        raise CatalogError(
            f"{cid}: unknown rollback_policy {policy!r}, expected one of "
            f"{sorted(ROLLBACK_POLICIES)}"
        )
    if remediate:
        if policy == "script" and not rollback:
            raise CatalogError(
                f"{cid}: has a remediation but no rollback. Write one, or declare "
                "rollback_policy: additive (nothing is replaced, so nothing needs "
                "undoing) or rollback_policy: irreversible (which bars it from "
                "running autonomously)."
            )
        if policy != "script" and rollback:
            raise CatalogError(
                f"{cid}: rollback_policy is {policy!r} but a rollback script is present"
            )
        if policy != "script" and not note:
            raise CatalogError(
                f"{cid}: rollback_policy {policy!r} must explain itself in rollback_note"
            )
        if policy == "irreversible" and risk is not RiskTier.INTRUSIVE:
            raise CatalogError(f"{cid}: an irreversible control must be risk: intrusive")
    elif rollback:
        raise CatalogError(f"{cid}: has a rollback but no remediation")

    effective = str(raw.get("effective", "immediate")).strip().lower()
    if effective not in EFFECTIVE_KINDS:
        raise CatalogError(
            f"{cid}: unknown effective {effective!r}, expected one of {sorted(EFFECTIVE_KINDS)}"
        )
    if effective != "immediate" and not remediate:
        raise CatalogError(f"{cid}: 'effective' is meaningless without a remediation")

    params = tuple(_parse_param(p, cid) for p in raw.get("params", []) or [])
    declared = {p.name for p in params}
    if len(declared) != len(params):
        raise CatalogError(f"{cid}: duplicate parameter names")

    used: set[str] = set()
    for label, body in (("detect", detect), ("remediate", remediate), ("rollback", rollback)):
        found = _placeholders(body)
        unknown = found - declared
        if unknown:
            raise CatalogError(
                f"{cid}.{label}: uses undeclared placeholder(s) {sorted(unknown)}"
            )
        used |= found

    unused = declared - used
    if unused:
        raise CatalogError(f"{cid}: declares unused parameter(s) {sorted(unused)}")

    control = Control(
        id=cid,
        title=str(raw.get("title", "")).strip() or cid,
        domain=str(raw.get("domain", "system")).strip(),
        severity=severity,
        risk=risk,
        rationale=str(raw.get("rationale", "")).strip(),
        detect=detect,
        remediate=remediate,
        rollback=rollback,
        rollback_policy=policy,
        rollback_note=note,
        effective=effective,
        params=params,
        depends_on=_as_tuple(raw.get("depends_on")),
        references=_as_tuple(raw.get("references")),
        applies_to=_as_tuple(raw.get("applies_to")),
        needs_admin=bool(raw.get("needs_admin", True)),
        blast_radius=str(raw.get("blast_radius", "")).strip(),
        tags=_as_tuple(raw.get("tags")),
    )

    if not control.rationale:
        raise CatalogError(
            f"{cid}: needs a rationale. It is what the model retrieves and what "
            "the operator reads in the report; a control without one is unusable."
        )
    return control


# --------------------------------------------------------------------------
# The catalogue
# --------------------------------------------------------------------------

class Catalog:
    """An immutable, integrity-stamped set of controls."""

    def __init__(self, controls: dict[str, Control], digest: str = "") -> None:
        self._controls = controls
        self.digest = digest

    # -- access ---------------------------------------------------------

    def __len__(self) -> int:
        return len(self._controls)

    def __iter__(self) -> Iterator[Control]:
        return iter(self._controls.values())

    def __contains__(self, control_id: object) -> bool:
        return control_id in self._controls

    def get(self, control_id: str) -> Control | None:
        return self._controls.get(control_id)

    def require(self, control_id: str) -> Control:
        control = self._controls.get(control_id)
        if control is None:
            raise KeyError(f"no such control: {control_id}")
        return control

    @property
    def ids(self) -> list[str]:
        return sorted(self._controls)

    def in_domain(self, domain: str) -> list[Control]:
        return [c for c in self if c.domain == domain]

    @property
    def domains(self) -> list[str]:
        return sorted({c.domain for c in self})

    def at_or_below(self, ceiling: RiskTier) -> list[Control]:
        return [c for c in self if c.risk.rank <= ceiling.rank]

    # -- ordering -------------------------------------------------------

    def resolve_order(self, control_ids: list[str]) -> list[str]:
        """Order ids so dependencies come first, otherwise leaving them alone.

        The caller's order carries real information - the planner has already
        sorted by severity and by how cheap each fix is to undo - so this is a
        stable topological sort that only ever moves a control *earlier*, to sit
        in front of something that depends on it. Sorting by id here instead
        would silently discard that prioritisation.

        Duplicate and unknown ids are dropped. A dependency cycle is broken at
        the point it is detected, so a malformed catalogue degrades to a stable
        order rather than hanging in the middle of an unattended run.
        """
        wanted: list[str] = []
        for cid in control_ids:
            if cid in self._controls and cid not in wanted:
                wanted.append(cid)
        position = {cid: i for i, cid in enumerate(wanted)}

        seen: set[str] = set()
        out: list[str] = []

        def visit(cid: str, stack: frozenset[str]) -> None:
            if cid in seen or cid in stack:
                return
            control = self._controls.get(cid)
            if control is None:
                return
            # Visit dependencies in the caller's own order, so that two
            # prerequisites of the same control keep their relative priority.
            for dep in sorted(control.depends_on, key=lambda d: position.get(d, 0)):
                if dep in position:
                    visit(dep, stack | {cid})
            if cid not in seen:
                seen.add(cid)
                out.append(cid)

        for cid in wanted:
            visit(cid, frozenset())
        return out


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load(directory: Path | None = None) -> Catalog:
    """Read, validate and fingerprint every control YAML in *directory*."""
    directory = directory or CONTROLS_DIR
    if not directory.is_dir():
        raise CatalogError(f"catalogue directory missing: {directory}")

    controls: dict[str, Control] = {}
    hasher = hashlib.sha256()

    for path in sorted(directory.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        hasher.update(path.name.encode("utf-8"))
        hasher.update(text.encode("utf-8"))
        try:
            documents = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise CatalogError(f"{path.name}: invalid YAML - {exc}") from exc
        if documents is None:
            continue
        if isinstance(documents, dict):
            documents = [documents]
        if not isinstance(documents, list):
            raise CatalogError(f"{path.name}: expected a list of controls")
        for raw in documents:
            if not isinstance(raw, dict):
                raise CatalogError(f"{path.name}: expected a mapping per control")
            control = parse_control(raw, path)
            if control.id in controls:
                raise CatalogError(f"duplicate control id {control.id} in {path.name}")
            controls[control.id] = control

    if not controls:
        raise CatalogError(f"no controls found in {directory}")

    _check_dependencies(controls)
    return Catalog(controls, digest=hasher.hexdigest())


def _check_dependencies(controls: dict[str, Control]) -> None:
    for control in controls.values():
        for dep in control.depends_on:
            if dep not in controls:
                raise CatalogError(f"{control.id}: depends on unknown control {dep}")
            if dep == control.id:
                raise CatalogError(f"{control.id}: depends on itself")


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render(script: str, params: dict[str, Any]) -> str:
    """Substitute validated parameters into a control script body.

    This deliberately does **not** use ``str.format``. PowerShell uses braces
    for script blocks and hashtables, so control bodies are full of constructs
    like ``if ($x -lt 0) { Remove-ItemProperty ... }`` - and Python's format
    grammar reads every one of those as a replacement field. Beyond breaking on
    ordinary scripts, ``str.format`` is far too powerful to point at
    model-influenced data at all: it walks attributes and indexes into objects.

    The substitution is done instead with the same narrow regex that
    :func:`_placeholders` uses to find them, so a brace pair is only ever
    touched when it wraps exactly one declared lowercase identifier. Every other
    brace in the script passes through untouched.

    Callers must have run the parameters through ``act.guard.validate_params``
    first; this function assumes the values are already safe.
    """
    if not script:
        return ""
    needed = _placeholders(script)
    missing = needed - set(params)
    if missing:
        raise CatalogError(f"cannot render script, missing parameter(s) {sorted(missing)}")

    def replace(match: "re.Match[str]") -> str:
        name = match.group(1)
        if name not in params:
            # A brace pair shaped like a placeholder that was never declared.
            # The loader rejects those at startup, so reaching here means the
            # script did not come from the catalogue.
            raise CatalogError(f"undeclared placeholder in control script: {name}")
        return str(params[name])

    return _PLACEHOLDER.sub(replace, script)


def with_defaults(control: Control, **overrides: Any) -> Control:
    """Return a copy of *control* with fields replaced. Test helper."""
    return replace(control, **overrides)
