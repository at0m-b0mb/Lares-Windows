#!/usr/bin/env python3
"""Score a model on the job Lares actually asks it to do.

The useful question is not "does this read well" - it is "would the executor
have accepted this". So the judge here is the real guard: every action the model
proposes is put through ``validate_params`` and ``check_policy``, exactly as it
would be on a live machine. A plan that the guard refuses scores zero for that
action no matter how sensible the prose around it was.

Six measures, each corresponding to a way the loop degrades:

    parseable    did it return JSON at all
    real         every control_id exists in the catalogue
    accepted     the guard would let every action run
    faithful     parameters match what the probe actually discovered
    restraint    it did not plan anything above the ceiling or report-only
    coverage     of the findings it could have fixed, how many did it plan

Run it against the built-in planner first to see what a perfect score looks
like, then against a model:

    python training/evaluate.py --baseline
    python training/evaluate.py --model ~/.local/share/lares/models/qwen...gguf
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lares.act.guard import Context, Refused, check_policy, validate_params  # noqa: E402
from lares.brain import prompt as prompt_mod  # noqa: E402
from lares.brain.engine import Engine, extract_json  # noqa: E402
from lares.brain.models import BY_KEY, ModelSpec  # noqa: E402
from lares.catalog import loader  # noqa: E402
from lares.core import RiskTier  # noqa: E402


@dataclass
class Tally:
    n: int = 0
    parseable: int = 0
    actions_total: int = 0
    actions_real: int = 0
    actions_accepted: int = 0
    actions_faithful: int = 0
    restraint_violations: int = 0
    coverage_num: int = 0
    coverage_den: int = 0
    seconds: float = 0.0
    failures: list[str] = field(default_factory=list)

    def pct(self, num: int, den: int) -> float:
        return 100.0 * num / den if den else 0.0

    def report(self, name: str) -> str:
        lines = [
            f"  {name}",
            f"    parseable    {self.pct(self.parseable, self.n):6.1f}%   "
            f"({self.parseable}/{self.n} answers were valid JSON)",
            f"    real         {self.pct(self.actions_real, self.actions_total):6.1f}%   "
            f"({self.actions_real}/{self.actions_total} control ids exist)",
            f"    accepted     {self.pct(self.actions_accepted, self.actions_total):6.1f}%   "
            f"(the guard would run them)",
            f"    faithful     {self.pct(self.actions_faithful, self.actions_total):6.1f}%   "
            f"(parameters match the probe)",
            f"    restraint    {self.restraint_violations:6d}     "
            f"actions planned that should have been deferred",
            f"    coverage     {self.pct(self.coverage_num, self.coverage_den):6.1f}%   "
            f"({self.coverage_num}/{self.coverage_den} fixable findings planned)",
        ]
        if self.seconds:
            lines.append(f"    speed        {self.seconds / max(1, self.n):6.1f}s   per plan")
        return "\n".join(lines)


def judge(raw: dict, expected: dict, catalog, tally: Tally) -> None:
    """Score one answer against the catalogue and the guard."""
    ctx = Context(elevated=True, ceiling=RiskTier.CAUTION, autonomous=True,
                  change_budget=99)

    expected_actions = {a["control_id"]: a for a in expected.get("actions", [])}
    fixable = len(expected_actions)
    tally.coverage_den += fixable

    actions = raw.get("actions")
    if not isinstance(actions, list):
        tally.failures.append("actions was not a list")
        return

    planned_ids = set()
    for item in actions:
        if not isinstance(item, dict):
            continue
        tally.actions_total += 1
        control_id = str(item.get("control_id", "")).strip().upper()
        control = catalog.get(control_id)

        if control is None:
            tally.failures.append(f"invented control {control_id!r}")
            continue
        tally.actions_real += 1
        planned_ids.add(control_id)

        params = item.get("params") if isinstance(item.get("params"), dict) else {}
        try:
            clean = validate_params(control, params)
            check_policy(control, ctx)
            tally.actions_accepted += 1
        except Refused as refusal:
            tally.failures.append(f"{control_id}: {refusal.reason}")
            if not control.autonomy_eligible:
                tally.restraint_violations += 1
            continue

        want = expected_actions.get(control_id)
        if want is None:
            # Planned something the reference planner did not. Not wrong on its
            # own - the guard accepted it - but it cannot be scored as faithful.
            continue
        if all(str(clean.get(k)) == str(v) for k, v in want.get("params", {}).items()):
            tally.actions_faithful += 1
        else:
            tally.failures.append(
                f"{control_id}: parameters {clean} do not match the probe's "
                f"{want.get('params')}")

    tally.coverage_num += len(planned_ids & set(expected_actions))


def run(rows: list[dict], catalog, engine: Engine | None, limit: int) -> Tally:
    tally = Tally()
    for row in rows[:limit]:
        user = row["messages"][1]["content"]
        expected = json.loads(row["messages"][2]["content"])
        tally.n += 1

        if engine is None:
            # The baseline: the reference answer itself. This is what a perfect
            # score looks like, and it confirms the judge is not broken.
            raw = expected
        else:
            started = time.monotonic()
            reply = engine.ask(prompt_mod.SYSTEM, user, schema=prompt_mod.PLAN_SCHEMA)
            tally.seconds += time.monotonic() - started
            if not reply.ok:
                tally.failures.append(f"model error: {reply.error}")
                continue
            parsed = extract_json(reply.text)
            if parsed is None:
                tally.failures.append("answer was not valid JSON")
                continue
            raw = parsed

        tally.parseable += 1
        judge(raw, expected, catalog, tally)
    return tally


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--data", default=str(ROOT / "training" / "data" / "eval.jsonl"))
    parser.add_argument("--model", help="path to a GGUF file to score")
    parser.add_argument("--tier", help=f"or a ladder key: {sorted(BY_KEY)}")
    parser.add_argument("--baseline", action="store_true",
                        help="score the reference answers, to sanity-check the judge")
    parser.add_argument("--limit", type=int, default=60)
    parser.add_argument("--kind", default="", help="only examples of this kind")
    args = parser.parse_args()

    path = Path(args.data)
    if not path.exists():
        print(f"No evaluation set at {path}.\nRun: python training/build_dataset.py")
        return 1

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    planning_kinds = {"plan", "parameters", "defer", "unknown"}
    rows = [r for r in rows if r.get("kind") in planning_kinds]
    if args.kind:
        rows = [r for r in rows if r.get("kind") == args.kind]
    if not rows:
        print("No planning examples matched.")
        return 1

    catalog = loader.load()
    print(f"Catalogue {len(catalog)} controls, digest {catalog.digest[:12]}")
    print(f"Scoring {min(len(rows), args.limit)} of {len(rows)} planning examples\n")

    if args.baseline or not (args.model or args.tier):
        tally = run(rows, catalog, None, args.limit)
        print(tally.report("built-in planner (reference)"))
        _show_failures(tally)
        if not (args.model or args.tier):
            print("\nPass --model or --tier to score a language model against this.")
        return 0

    if args.tier:
        spec: ModelSpec | None = BY_KEY.get(args.tier)
        if spec is None:
            print(f"No such tier {args.tier!r}. Choose from {sorted(BY_KEY)}")
            return 1
    else:
        target = Path(args.model).expanduser()
        if not target.exists():
            print(f"No model at {target}")
            return 1
        from dataclasses import replace
        spec = replace(BY_KEY["3b"], filename=target.name)
        # Point the spec at the file the user actually named.
        object.__setattr__(spec, "filename", target.name)
        if target.parent != spec.path.parent:
            print(f"Note: loading {target}")

    engine = Engine(spec)
    if not engine.load():
        print(f"Could not load the model: {engine.status}")
        return 1

    tally = run(rows, catalog, engine, args.limit)
    print(tally.report(engine.name))
    _show_failures(tally)
    return 0


def _show_failures(tally: Tally) -> None:
    if not tally.failures:
        return
    print(f"\n  First refusals and mismatches ({len(tally.failures)} total):")
    seen = set()
    shown = 0
    for failure in tally.failures:
        key = failure.split(":")[0]
        if key in seen:
            continue
        seen.add(key)
        print(f"    {failure[:120]}")
        shown += 1
        if shown >= 10:
            break


if __name__ == "__main__":
    sys.exit(main())
