#!/usr/bin/env python3
"""Build the fine-tuning set for the Lares planner.

Every example here is generated from the control catalogue - the same YAML the
application executes from. Nothing is invented, and nothing is scraped. That
matters for two reasons: the targets are correct by construction, and when the
catalogue grows the training set grows with it rather than going stale.

Six kinds of example, each teaching a different failure mode out of the model:

    plan          a synthetic scan, and the plan a correct planner produces
    parameters    findings that carry discovered values, which must be copied
                  through exactly rather than guessed at
    defer         scans containing controls that must NOT be planned - report
                  only, irreversible, or above the ceiling - each with a reason
    unknown       problems with no matching control, where the right answer is
                  to say so instead of inventing a control id
    explain       a control, and the plain-English account of why it matters
    script        a hardening task, and the vetted PowerShell that does it

Usage:

    python training/build_dataset.py --out training/data --count 4000
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lares.brain import prompt as prompt_mod  # noqa: E402
from lares.brain.plan import builtin_plan  # noqa: E402
from lares.brain.retrieve import Index, context_for  # noqa: E402
from lares.catalog import loader  # noqa: E402
from lares.catalog.loader import Catalog  # noqa: E402
from lares.core import Control, Fact, Finding, RiskTier, Scan, Severity  # noqa: E402
from lares.demo_data import PROBES  # noqa: E402

# Machines the synthetic scans are drawn from. Varying these is what teaches the
# model that a control can be irrelevant rather than merely unfixed.
EDITIONS = [
    "Microsoft Windows 11 Pro", "Microsoft Windows 11 Home",
    "Microsoft Windows 10 Pro", "Microsoft Windows 10 Home",
    "Microsoft Windows Server 2022 Standard",
]
MEMORY = ["4.0 GB", "8.0 GB", "16.0 GB", "32.0 GB"]
NETWORKS = [
    "Wi-Fi, profile Public", "Wi-Fi, profile Private",
    "Ethernet, profile Domain", "Wi-Fi, profile Private",
]

#: Problems a person might describe that the catalogue has no control for. The
#: correct answer to all of them is to defer with an explanation, and a model
#: that has never seen one will invent a plausible-looking control id instead.
UNCOVERED = [
    ("A browser extension is injecting adverts into pages",
     "Lares has no control for browser extensions; they are per-user and per-browser."),
    ("The machine has an out-of-date BIOS",
     "Firmware updates are vendor-specific and cannot be applied safely from here."),
    ("A user keeps writing passwords in a text file on the desktop",
     "This is a practice, not a setting, and no control changes it."),
    ("An old VPN client is installed that nobody uses",
     "Removing third-party software is outside the catalogue."),
    ("The Wi-Fi network uses WPA2 rather than WPA3",
     "The access point is the thing that would need changing, not this machine."),
    ("Someone has physical access to the machine overnight",
     "Physical access is not a configuration problem; encryption is the nearest control."),
    ("There is no backup of the user's documents",
     "Lares does not manage backups."),
    ("A shared folder contains payroll data readable by everyone",
     "Deciding who should read which data is a judgement Lares does not make."),
]


# --------------------------------------------------------------------------
# Synthetic scans
# --------------------------------------------------------------------------

def _observed_for(control: Control, rng: random.Random) -> tuple[str, dict]:
    """Realistic probe output for a control.

    Uses the demo data where it exists, since that was written to look like real
    probe output. Falls back to the control's own title so a newly added control
    still generates usable examples.
    """
    probe = PROBES.get(control.id)
    if probe and not probe.get("compliant", True):
        instances = probe.get("instances")
        if isinstance(instances, list) and instances:
            chosen = rng.choice(instances)
            return (str(chosen.get("observed", control.title)),
                    dict(chosen.get("params", {})))
        return str(probe.get("observed", control.title)), dict(probe.get("params", {}))

    params = {}
    for spec in control.params:
        if spec.type == "int":
            low = spec.minimum if spec.minimum is not None else 0
            high = spec.maximum if spec.maximum is not None else low + 10
            params[spec.name] = rng.randint(low, min(high, low + 64))
        elif spec.type == "enum":
            params[spec.name] = rng.choice(list(spec.choices))
        elif spec.type == "bool":
            params[spec.name] = rng.choice([True, False])
        else:
            params[spec.name] = "SampleValue"
    return f"{control.title} (detected on this machine)", params


def make_scan(catalog: Catalog, rng: random.Random, *, include: list[Control] | None = None,
              size: tuple[int, int] = (3, 12)) -> Scan:
    """A believable scan of a machine with a random set of problems."""
    edition = rng.choice(EDITIONS)
    scan = Scan(demo=True)
    scan.facts = [
        Fact("Host name", f"DESKTOP-{rng.randrange(10**6):06X}", "system", True),
        Fact("Operating system", edition, "system"),
        Fact("Version", rng.choice(["10.0.26100 (24H2)", "10.0.19045 (22H2)"]), "system"),
        Fact("Domain joined", rng.choice(["No (workgroup WORKGROUP)", "Yes (corp.local)"]), "system"),
        Fact("Signed in as", "DESKTOP\\user", "identity", True),
        Fact("Running elevated", "Yes", "identity"),
        Fact("Memory", rng.choice(MEMORY), "hardware"),
        Fact("Active network", rng.choice(NETWORKS), "network"),
        Fact("Last update installed", f"KB50{rng.randrange(10000, 99999)}, "
                                      f"{rng.randrange(1, 120)} days ago", "software"),
    ]

    pool = [c for c in catalog]
    chosen = list(include or [])
    wanted = rng.randint(*size)
    rng.shuffle(pool)
    for control in pool:
        if len(chosen) >= wanted:
            break
        if control not in chosen:
            chosen.append(control)

    for control in chosen:
        observed, params = _observed_for(control, rng)
        scan.findings.append(Finding(
            control_id=control.id,
            title=control.title,
            severity=control.severity,
            detail=control.rationale,
            observed=observed,
            params=params,
            domain=control.domain,
            remediable=control.has_remediation,
        ))
    scan.findings.sort(key=lambda f: (-f.severity.rank, f.control_id))
    return scan


def first_sentence(text: str, limit: int = 190) -> str:
    flat = " ".join(text.split())
    for stop in (". ", " - "):
        if stop in flat:
            candidate = flat.split(stop)[0].strip()
            if 30 <= len(candidate) <= limit:
                return candidate + ("." if stop == ". " else "")
    return flat[:limit].rsplit(" ", 1)[0] + "..."


def rationale_for(finding: Finding, control: Control) -> str:
    """A one-sentence justification, grounded in the catalogue's own words."""
    what = finding.observed or control.title
    why = first_sentence(control.rationale, 150)
    return f"{what}. {why}"


def summary_for(scan: Scan, planned: int, deferred: int) -> str:
    counts = scan.counts()
    edition = scan.fact("Operating system", "this machine")
    worst = scan.worst.value
    return (
        f"{edition} has {len(scan.findings)} open finding(s), the most serious at "
        f"{worst} severity ({counts[Severity.CRITICAL]} critical, "
        f"{counts[Severity.HIGH]} high). Lares will apply {planned} reversible "
        f"change(s) now and leave {deferred} for a person, because they change how "
        "the machine is reached or cannot be undone. These are the controls Lares "
        "checks, not a statement that the machine is secure."
    )


# --------------------------------------------------------------------------
# Example builders
# --------------------------------------------------------------------------

def _prompt_for(scan: Scan, index: Index, ceiling: RiskTier, elevated: bool,
                budget: int) -> str:
    queries = [f.observed or f.title for f in scan.by_severity()[:prompt_mod.MAX_FINDINGS]]
    must = {f.control_id for f in scan.findings}
    context = context_for(index, queries, must, limit=min(12, len(must) + 3))
    return prompt_mod.build(scan, context, ceiling.value, elevated, budget)


def _target(scan: Scan, catalog: Catalog, ceiling: RiskTier, elevated: bool,
            budget: int, extra_deferred: dict[str, str] | None = None) -> str:
    plan = builtin_plan(scan, catalog, ceiling=ceiling, elevated=elevated, budget=budget)
    by_id = {f.control_id: f for f in scan.findings}

    actions = []
    for action in plan.ordered():
        control = catalog.require(action.control_id)
        finding = by_id.get(action.control_id)
        actions.append({
            "control_id": action.control_id,
            "params": action.params,
            "rationale": rationale_for(finding, control) if finding else control.title,
            "confidence": 80 if control.risk is RiskTier.SAFE else 70,
            "order": action.order,
        })

    deferred = dict(plan.deferred)
    if extra_deferred:
        deferred.update(extra_deferred)

    return json.dumps({
        "summary": summary_for(scan, len(actions), len(deferred)),
        "actions": actions,
        "deferred": deferred,
    }, ensure_ascii=False)


def example(system: str, user: str, assistant: str, kind: str) -> dict:
    return {
        "kind": kind,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
    }


def build_plan_examples(catalog: Catalog, index: Index, rng: random.Random,
                        count: int, kind: str = "plan") -> list[dict]:
    out = []
    for _ in range(count):
        ceiling = rng.choices(
            [RiskTier.SAFE, RiskTier.CAUTION, RiskTier.INTRUSIVE], weights=[2, 6, 1])[0]
        elevated = rng.random() > 0.15
        budget = rng.choice([3, 5, 6, 8, 8, 10])
        scan = make_scan(catalog, rng)
        out.append(example(
            prompt_mod.SYSTEM,
            _prompt_for(scan, index, ceiling, elevated, budget),
            _target(scan, catalog, ceiling, elevated, budget),
            kind,
        ))
    return out


def build_parameter_examples(catalog: Catalog, index: Index, rng: random.Random,
                             count: int) -> list[dict]:
    """Scans built around controls that carry discovered parameters.

    This is the single most common way a small model breaks the executor: it
    writes a sensible-looking port number instead of the one the probe actually
    found, and the guard refuses the action.
    """
    parameterised = [c for c in catalog if c.params and c.autonomy_eligible]
    if not parameterised:
        return []
    out = []
    for _ in range(count):
        focus = rng.sample(parameterised, k=min(len(parameterised), rng.randint(2, 4)))
        scan = make_scan(catalog, rng, include=focus, size=(4, 8))
        out.append(example(
            prompt_mod.SYSTEM,
            _prompt_for(scan, index, RiskTier.CAUTION, True, 8),
            _target(scan, catalog, RiskTier.CAUTION, True, 8),
            "parameters",
        ))
    return out


def build_defer_examples(catalog: Catalog, index: Index, rng: random.Random,
                         count: int) -> list[dict]:
    """Scans dominated by controls the model must refuse to plan."""
    never = [c for c in catalog if not c.autonomy_eligible]
    if not never:
        return []
    out = []
    for _ in range(count):
        focus = rng.sample(never, k=min(len(never), rng.randint(2, 4)))
        scan = make_scan(catalog, rng, include=focus, size=(4, 9))
        out.append(example(
            prompt_mod.SYSTEM,
            _prompt_for(scan, index, RiskTier.CAUTION, True, 8),
            _target(scan, catalog, RiskTier.CAUTION, True, 8),
            "defer",
        ))
    return out


def build_unknown_examples(catalog: Catalog, index: Index, rng: random.Random,
                           count: int) -> list[dict]:
    """Scans containing a problem with no control, which must not be invented."""
    out = []
    for _ in range(count):
        scan = make_scan(catalog, rng, size=(2, 6))
        problem, reason = rng.choice(UNCOVERED)

        # Append the uncovered problem as a finding with an id that is not in
        # the catalogue, exactly as an operator note would arrive.
        scan.findings.append(Finding(
            control_id="OBSERVED",
            title=problem,
            severity=Severity.MEDIUM,
            observed=problem,
            remediable=False,
        ))
        target = _target(scan, catalog, RiskTier.CAUTION, True, 8,
                         extra_deferred={"OBSERVED": reason})
        out.append(example(
            prompt_mod.SYSTEM,
            _prompt_for(scan, index, RiskTier.CAUTION, True, 8),
            target,
            "unknown",
        ))
    return out


EXPLAIN_SYSTEM = (
    "You explain Windows security settings to the person who owns the machine. "
    "Plain English, no jargon, no bullet points. Say what the setting does, what "
    "goes wrong without it, and what changing it costs them. Never claim a "
    "machine is secure."
)


def build_explain_examples(catalog: Catalog, rng: random.Random) -> list[dict]:
    out = []
    questions = [
        "What is {id} and why does it matter?",
        "Explain {title} in plain English.",
        "Why would I want to fix: {title}?",
        "What happens if I leave {title} alone?",
        "What does fixing {id} cost me?",
    ]
    for control in catalog:
        for template in questions:
            answer = " ".join(control.rationale.split())
            if control.blast_radius:
                answer += " " + " ".join(control.blast_radius.split())
            out.append(example(
                EXPLAIN_SYSTEM,
                template.format(id=control.id, title=control.title.lower()),
                answer,
                "explain",
            ))
    rng.shuffle(out)
    return out


def build_script_examples(catalog: Catalog, rng: random.Random) -> list[dict]:
    """The Expert lane: vetted PowerShell as the target.

    Only the catalogue's own scripts are used, so every target has been read by
    a person and passes the guard.
    """
    out = []
    asks = {
        "detect": ["Write PowerShell that checks whether {title_l}.",
                   "How do I detect {title_l} on Windows?"],
        "remediate": ["Write PowerShell that fixes {title_l}.",
                      "Give me a script to remediate {id}."],
        "rollback": ["Write PowerShell that undoes the fix for {id}.",
                     "How do I revert {title_l} back to how it was?"],
    }
    for control in catalog:
        for field, templates in asks.items():
            body = getattr(control, field)
            if not body:
                continue
            header = (
                f"# {control.id} - {control.title}\n"
                f"# {first_sentence(control.blast_radius or control.rationale)}\n"
            )
            for template in templates:
                out.append(example(
                    prompt_mod.EXPERT_SYSTEM,
                    template.format(id=control.id, title_l=control.title.lower()),
                    header + body.strip(),
                    "script",
                ))
    rng.shuffle(out)
    return out


# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default=str(ROOT / "training" / "data"))
    parser.add_argument("--count", type=int, default=4000,
                        help="total planning-style examples to generate")
    parser.add_argument("--seed", type=int, default=7724)
    parser.add_argument("--holdout", type=float, default=0.08,
                        help="fraction held back for evaluation")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    catalog = loader.load()
    index = Index.build(catalog)

    print(f"Catalogue: {len(catalog)} controls, digest {catalog.digest[:12]}")

    plan_n = int(args.count * 0.45)
    param_n = int(args.count * 0.22)
    defer_n = int(args.count * 0.22)
    unknown_n = args.count - plan_n - param_n - defer_n

    rows: list[dict] = []
    rows += build_plan_examples(catalog, index, rng, plan_n)
    rows += build_parameter_examples(catalog, index, rng, param_n)
    rows += build_defer_examples(catalog, index, rng, defer_n)
    rows += build_unknown_examples(catalog, index, rng, unknown_n)
    rows += build_explain_examples(catalog, rng)
    rows += build_script_examples(catalog, rng)

    rng.shuffle(rows)
    split = int(len(rows) * (1 - args.holdout))
    train, evaluate = rows[:split], rows[split:]

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, part in (("train", train), ("eval", evaluate)):
        path = out_dir / f"{name}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for row in part:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"  {path.relative_to(ROOT)}: {len(part)} examples")

    tally: dict[str, int] = {}
    for row in rows:
        tally[row["kind"]] = tally.get(row["kind"], 0) + 1
    print("\nBy kind:")
    for kind, n in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {kind:<12} {n:>6}")

    chars = sum(len(m["content"]) for row in rows for m in row["messages"])
    print(f"\n{len(rows)} examples, roughly {chars // 4_000_000:.1f}M tokens "
          f"({chars // len(rows)} characters each on average)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
