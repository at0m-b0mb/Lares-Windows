"""The catalogue is the trust boundary, so its invariants are tested, not assumed.

Most of these run over every shipped control. A new control that breaks one of
these properties fails CI rather than failing on somebody's machine.
"""

from __future__ import annotations

import re

import pytest
import yaml

from lares.catalog import loader
from lares.catalog.loader import Catalog, CatalogError, parse_control, render
from lares.core import RiskTier, Severity


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return loader.load()


# --------------------------------------------------------------------------
# Shipped catalogue properties
# --------------------------------------------------------------------------

def test_catalogue_loads_and_is_not_trivial(catalog):
    assert len(catalog) >= 25
    assert len(catalog.domains) >= 4


def test_digest_is_stable(catalog):
    assert catalog.digest == loader.load().digest
    assert len(catalog.digest) == 64


def test_every_control_has_a_real_rationale(catalog):
    for control in catalog:
        assert len(control.rationale.split()) >= 25, (
            f"{control.id}: the rationale is what a person reads in the report and "
            "what the model retrieves; a sentence is not enough"
        )


def test_every_remediating_control_declares_its_blast_radius(catalog):
    for control in catalog:
        if control.has_remediation:
            assert control.blast_radius.strip(), (
                f"{control.id} changes the machine but does not say what that costs"
            )


def test_autonomous_controls_are_all_reversible(catalog):
    """The property the whole safety argument rests on."""
    for control in catalog:
        if control.autonomy_eligible:
            assert control.is_reversible, f"{control.id} may run unattended but cannot be undone"
            assert control.risk is not RiskTier.INTRUSIVE


def test_irreversible_controls_are_never_autonomous(catalog):
    for control in catalog:
        if control.rollback_policy == "irreversible":
            assert control.risk is RiskTier.INTRUSIVE
            assert not control.autonomy_eligible
            assert control.rollback_note.strip()


def test_report_only_controls_have_no_remediation(catalog):
    for control in catalog:
        if not control.has_remediation:
            assert not control.rollback
            assert control.blast_radius or control.rationale


def test_every_control_probe_emits_json(catalog):
    for control in catalog:
        assert "ConvertTo-Json" in control.detect, (
            f"{control.id}: the probe contract requires a JSON object on stdout"
        )
        assert "compliant" in control.detect


def test_dependencies_all_exist_and_do_not_cycle(catalog):
    for control in catalog:
        for dep in control.depends_on:
            assert dep in catalog, f"{control.id} depends on missing {dep}"
    # resolve_order must terminate and return each id at most once
    order = catalog.resolve_order(catalog.ids)
    assert len(order) == len(set(order))


def test_severity_and_risk_are_independent_axes(catalog):
    """A critical problem may have a safe fix, and vice versa.

    If these ever collapse into one axis, the autonomy gate silently starts
    keying off how bad the problem is rather than how dangerous the fix is.
    """
    pairs = {(c.severity, c.risk) for c in catalog}
    assert (Severity.CRITICAL, RiskTier.SAFE) in pairs or \
           (Severity.HIGH, RiskTier.SAFE) in pairs
    assert any(s.rank <= Severity.MEDIUM.rank and r is RiskTier.INTRUSIVE
               for s, r in pairs)


def test_string_and_path_parameters_are_all_constrained(catalog):
    for control in catalog:
        for spec in control.params:
            if spec.type in ("string", "path"):
                assert spec.pattern, f"{control.id}.{spec.name} has no pattern"
                # The pattern must be anchored, or it constrains only a prefix.
                assert spec.pattern.startswith("^") and spec.pattern.endswith("$"), (
                    f"{control.id}.{spec.name}: pattern must be anchored with ^ and $"
                )


def test_every_control_renders_with_plausible_parameters(catalog):
    """Every script must survive substitution without tripping the renderer."""
    for control in catalog:
        params = {}
        for spec in control.params:
            if spec.type == "int":
                params[spec.name] = spec.minimum if spec.minimum is not None else 1
            elif spec.type == "enum":
                params[spec.name] = spec.choices[0]
            elif spec.type == "bool":
                params[spec.name] = True
            else:
                params[spec.name] = "Sample_Value"
        for body in (control.detect, control.remediate, control.rollback):
            if body:
                rendered = render(body, params)
                # No placeholder may survive rendering, and PowerShell's own
                # braces must still be there afterwards.
                assert not re.search(r"\{[a-z_][a-z0-9_]*\}", rendered), (
                    f"{control.id}: a placeholder survived rendering"
                )
                # Every brace in the source is either a placeholder's own, which
                # is consumed, or PowerShell's, which must survive untouched.
                consumed = len(re.findall(r"\{[a-z_][a-z0-9_]*\}", body))
                assert rendered.count("}") == body.count("}") - consumed, (
                    f"{control.id}: rendering disturbed PowerShell's braces"
                )


def test_no_control_hardcodes_a_credential(catalog):
    """A hardening tool that ships a password is not a hardening tool."""
    suspicious = re.compile(
        r"(-Password|ConvertTo-SecureString\s+['\"][^'\"]{4,}|"
        r"\bP@ssw|\bpassword\s*=\s*['\"][^'\"]{3,})", re.IGNORECASE)
    for control in catalog:
        for body in (control.detect, control.remediate, control.rollback):
            assert not suspicious.search(body), f"{control.id} looks like it embeds a credential"


# --------------------------------------------------------------------------
# The validator refuses malformed controls
# --------------------------------------------------------------------------

def parse(text: str):
    return parse_control(yaml.safe_load(text), __import__("pathlib").Path("test.yaml"))


MINIMAL = """
id: TST-001
title: Test
domain: test
severity: high
risk: safe
rationale: >
  A rationale long enough to be useful to a reader and to the retrieval index,
  which is the whole reason the loader insists on one being present at all.
detect: |
  [pscustomobject]@{ compliant = $true } | ConvertTo-Json
"""


def test_minimal_control_parses():
    control = parse(MINIMAL)
    assert control.id == "TST-001"
    assert not control.has_remediation


@pytest.mark.parametrize("mutation,message", [
    ("id: bad-id", "must look like"),
    ("severity: catastrophic", "unknown severity"),
    ("risk: mild", "unknown risk"),
])
def test_malformed_headers_are_refused(mutation, message):
    key = mutation.split(":")[0]
    text = re.sub(rf"^{key}: .*$", mutation, MINIMAL, flags=re.MULTILINE)
    with pytest.raises(CatalogError, match=message):
        parse(text)


def test_missing_detect_is_refused():
    text = MINIMAL.split("detect:")[0]
    with pytest.raises(CatalogError, match="detect probe"):
        parse(text)


def test_remediation_without_rollback_is_refused():
    with pytest.raises(CatalogError, match="no rollback"):
        parse(MINIMAL + "\nremediate: |\n  Set-Thing\n")


def test_rollback_without_remediation_is_refused():
    with pytest.raises(CatalogError, match="rollback but no remediation"):
        parse(MINIMAL + "\nrollback: |\n  Undo-Thing\n")


def test_irreversible_must_be_intrusive():
    text = MINIMAL + (
        "\nremediate: |\n  Set-Thing\n"
        "rollback_policy: irreversible\n"
        "rollback_note: prior state is destroyed\n"
    )
    with pytest.raises(CatalogError, match="must be risk: intrusive"):
        parse(text)


def test_additive_must_explain_itself():
    text = MINIMAL + "\nremediate: |\n  Set-Thing\nrollback_policy: additive\n"
    with pytest.raises(CatalogError, match="rollback_note"):
        parse(text)


def test_undeclared_placeholder_is_refused():
    text = MINIMAL + "\nremediate: |\n  Set-Thing -Port {port}\nrollback: |\n  Undo {port}\n"
    with pytest.raises(CatalogError, match="undeclared placeholder"):
        parse(text)


def test_unused_parameter_is_refused():
    text = MINIMAL + (
        "\nremediate: |\n  Set-Thing\nrollback: |\n  Undo-Thing\n"
        "params:\n  - name: port\n    type: int\n    min: 1\n    max: 10\n"
    )
    with pytest.raises(CatalogError, match="unused parameter"):
        parse(text)


def test_unconstrained_string_parameter_is_refused():
    text = MINIMAL + (
        "\nremediate: |\n  Set-Thing '{label}'\nrollback: |\n  Undo '{label}'\n"
        "params:\n  - name: label\n    type: string\n"
    )
    with pytest.raises(CatalogError, match="injection slot"):
        parse(text)


def test_unknown_key_is_refused_rather_than_ignored():
    with pytest.raises(CatalogError, match="unknown key"):
        parse(MINIMAL + "\nblast_radiuss: typo here\n")


def test_yaml_boolean_choice_is_refused():
    """The bug that shipped: bare Off in a choices list becomes boolean false."""
    text = MINIMAL + (
        "\nremediate: |\n  Set-Thing {mode}\nrollback: |\n  Undo {mode}\n"
        "params:\n  - name: mode\n    type: enum\n    choices: [Off, Warn]\n"
    )
    with pytest.raises(CatalogError, match="parsed as a boolean"):
        parse(text)


def test_effective_without_remediation_is_refused():
    with pytest.raises(CatalogError, match="meaningless without a remediation"):
        parse(MINIMAL + "\neffective: restart\n")


# --------------------------------------------------------------------------
# Ordering
# --------------------------------------------------------------------------

def test_resolve_order_preserves_caller_priority(catalog):
    """The planner's severity ordering must survive dependency resolution."""
    given = ["SYS-004", "IDN-003", "NET-005", "DEF-005"]
    assert catalog.resolve_order(given) == given


def test_resolve_order_moves_dependencies_earlier(catalog):
    order = catalog.resolve_order(["NET-002", "NET-001"])
    assert order.index("NET-001") < order.index("NET-002")


def test_resolve_order_drops_unknown_and_duplicate_ids(catalog):
    assert catalog.resolve_order(["NOPE-999", "NET-005", "NET-005"]) == ["NET-005"]


# --------------------------------------------------------------------------
# Severity ordering
#
# Severity subclasses str so it serialises cleanly, which means it inherits
# str's comparison operators. That once made max() return the alphabetically
# largest name rather than the worst finding, and every report said so.
# --------------------------------------------------------------------------

ASCENDING = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
             Severity.HIGH, Severity.CRITICAL]


@pytest.mark.parametrize("lower,higher", list(zip(ASCENDING, ASCENDING[1:])))
def test_severity_compares_by_rank_not_alphabetically(lower, higher):
    assert lower < higher
    assert higher > lower
    assert lower <= higher
    assert higher >= lower
    assert not (higher < lower)
    assert not (lower > higher)


def test_max_severity_picks_the_worst():
    # "high" sorts before "medium" alphabetically, which is exactly the pair
    # that hid this bug.
    assert max([Severity.MEDIUM, Severity.HIGH], key=lambda s: s.rank) is Severity.HIGH
    assert max([Severity.MEDIUM, Severity.HIGH]) is Severity.HIGH
    assert max(ASCENDING) is Severity.CRITICAL
    assert min(ASCENDING) is Severity.INFO


def test_scan_worst_reports_the_worst_finding():
    from lares.core import Finding, Scan
    scan = Scan(findings=[
        Finding("A-001", "a", Severity.MEDIUM),
        Finding("B-001", "b", Severity.HIGH),
        Finding("C-001", "c", Severity.LOW),
    ])
    assert scan.worst is Severity.HIGH
    assert Scan().worst is Severity.INFO


# --------------------------------------------------------------------------
# The PowerShell itself
#
# None of this can run PowerShell, so it checks what is checkable statically.
# These are the mistakes that would otherwise surface as a runtime failure on
# a user's machine, in the middle of an unattended change.
# --------------------------------------------------------------------------

def test_every_probe_emits_json():
    """The executor parses probe output as JSON. A probe that prints prose
    reads as an unusable probe, and the control is silently never fixed."""
    catalog = loader.load()
    for control in catalog:
        assert "ConvertTo-Json" in control.detect, f"{control.id} probe emits no JSON"


def test_every_script_is_structurally_balanced():
    catalog = loader.load()
    for control in catalog:
        for label in ("detect", "remediate", "rollback"):
            body = getattr(control, label)
            if not body:
                continue
            text = "\n".join(
                line.split("#")[0] if line.strip().startswith("#") else line
                for line in body.splitlines()
            )
            for opener, closer, name in (("{", "}", "braces"),
                                         ("(", ")", "parentheses"),
                                         ("[", "]", "brackets")):
                assert text.count(opener) == text.count(closer), (
                    f"{control.id}.{label} has unbalanced {name}")
            assert text.count("'") % 2 == 0, (
                f"{control.id}.{label} has an odd number of single quotes")


def test_every_parameter_is_supplied_by_its_own_probe():
    """A remediation takes its parameters from the finding its probe produced.

    If the probe never emits a parameter the fix needs, rendering fails at the
    moment of remediation - after the snapshot, with the machine already
    committed to the attempt. The loader cannot catch this because it only
    checks that placeholders are *declared*, not that they are ever *filled*.
    """
    catalog = loader.load()
    for control in catalog:
        if not control.params:
            continue
        emitted = set(re.findall(r"\b([a-z_][a-z0-9_]*)\s*=", control.detect))
        for spec in control.params:
            assert spec.name in emitted, (
                f"{control.id} needs '{spec.name}' but its probe never emits it")


def test_the_readme_describes_the_domains_that_exist():
    """The table claimed the services domain covered WinRM. No control does.

    A security tool's list of what it checks is a promise about what it
    checks, and a reader who believes WinRM is covered stops looking at WinRM.
    """
    import re
    from pathlib import Path

    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(
        encoding="utf-8")
    catalog = loader.load()

    rows = re.findall(r"^\| `(\w+)` \| (.+?) \|$", readme, re.M)
    described = {domain for domain, _ in rows}
    assert described == set(catalog.domains), described ^ set(catalog.domains)

    corpus = " ".join(
        f"{c.id} {c.title} {c.rationale} {c.detect} {c.remediate}" for c in catalog
    ).lower()
    for domain, claim in rows:
        # Every capitalised noun phrase in a claim should be findable in the
        # catalogue it describes.
        for term in re.findall(r"\b(?:WinRM|SMBv1|LLMNR|BitLocker|LSASS|WDigest)\b", claim):
            assert term.lower() in corpus, \
                f"the {domain} row claims {term} and no control mentions it"
