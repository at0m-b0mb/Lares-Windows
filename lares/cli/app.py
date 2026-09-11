"""Lares, the terminal application.

A standalone program. It scans, it decides, it fixes, it records - and with
``lares watch`` it does all of that on a schedule until told to stop, which is
the headless form of the agent. Nothing here prompts for a decision; the point
of the tool is that it does not need one.

Uses rich when it is installed and degrades to plain text when it is not, because
"runs on a slow machine with nothing installed" is a design requirement and a
missing dependency should not be the thing that stops a machine getting hardened.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from .. import config as config_mod
from ..autonomy.breaker import Breaker
from ..autonomy.loop import Agent, Event, build
from ..brain import download, models
from ..brain.engine import Engine, strip_fence
from ..brain.plan import Planner
from ..brain.prompt import EXPERT_SYSTEM, expert
from ..act.execute import Executor
from ..act.guard import Context, screen_script
from ..act.journal import Journal
from ..catalog import loader
from ..core import RiskTier, Scan, Severity, Status, dumps
from ..report import write_report
from ..sense import scanner
from ..version import VERSION
from ..winsys import current_user, is_demo, is_elevated, set_demo
from .render import Console

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO]


# --------------------------------------------------------------------------
# Shared setup
# --------------------------------------------------------------------------

def _settings_from(args: argparse.Namespace) -> config_mod.Settings:
    settings = config_mod.load()
    for name in ("ceiling", "budget", "interval_minutes", "model_tier"):
        value = getattr(args, name, None)
        if value not in (None, ""):
            setattr(settings, name, value)
    if getattr(args, "dry_run", False):
        settings.dry_run = True
    if getattr(args, "domain", None):
        settings.domains = list(args.domain)
    corrections = settings.validate()
    return settings


def _banner(console: Console, settings: config_mod.Settings, note: str) -> None:
    console.rule(f"Lares {VERSION}")
    mode = "report only" if settings.dry_run else f"applying up to {settings.ceiling}"
    console.field("Machine", current_user())
    console.field("Elevated", "yes" if is_elevated() else
                  "no - remediation needing admin will be skipped")
    console.field("Model", note)
    console.field("Mode", mode)
    if is_demo():
        console.warn("Demo mode: this is synthetic data and nothing will be changed.")
    console.blank()


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    catalog = loader.load()
    settings = _settings_from(args)
    console.rule(f"Lares {VERSION} - scan")

    with console.status("Checking the machine") as status:
        scan = scanner.scan(
            catalog,
            domains=settings.domains or None,
            progress=lambda cid, i, n: status(f"Checking {cid} ({i}/{n})"),
        )

    _show_scan(console, scan, catalog, verbose=args.verbose)

    if args.report:
        path = write_report(scan, None, args.report)
        console.blank()
        console.ok(f"Report written to {path}")
    if args.json:
        print(dumps(scan))
    return 0


def _show_scan(console: Console, scan: Scan, catalog, verbose: bool = False) -> None:
    console.blank()
    console.section("This machine")
    for fact in scan.facts:
        shown = fact.redacted() if (fact.sensitive and not verbose) else fact
        console.field(shown.key, shown.value)

    console.blank()
    verdict, detail = scanner.posture(scan)
    console.verdict(verdict, detail)

    counts = scan.counts()
    console.blank()
    console.field("Checked", f"{len(catalog)} controls in {scan.duration_ms} ms")
    console.field("Open findings", ", ".join(
        f"{counts[s]} {s.value}" for s in SEVERITY_ORDER if counts[s]) or "none")

    if scan.errors:
        console.blank()
        console.warn(f"{len(scan.errors)} probe(s) could not be read:")
        for cid, error in list(scan.errors.items())[:6]:
            console.bullet(f"{cid}: {error[:100]}")

    if not scan.findings:
        return

    console.blank()
    console.section("Findings")
    for finding in scan.by_severity():
        control = catalog.get(finding.control_id)
        fixable = "auto" if control and control.autonomy_eligible else "manual"
        console.finding(finding.severity.value, finding.control_id,
                        finding.observed or finding.title, fixable)
        if verbose and finding.evidence:
            console.detail(finding.evidence)


def cmd_plan(args: argparse.Namespace, console: Console) -> int:
    catalog = loader.load()
    settings = _settings_from(args)
    engine, decision = Engine.autoselect(prefer=settings.model_tier)
    note = decision.reason if decision.spec else "no model"
    _banner(console, settings, engine.status if decision.spec else note)

    with console.status("Checking the machine") as status:
        scan = scanner.scan(catalog, domains=settings.domains or None,
                            progress=lambda cid, i, n: status(f"Checking {cid} ({i}/{n})"))

    console.field("Findings", str(len(scan.findings)))
    with console.status("Deciding what to do"):
        planner = Planner(catalog, engine)
        plan = planner.plan(scan, ceiling=settings.risk_ceiling,
                            elevated=is_elevated(), budget=settings.budget)

    _show_plan(console, plan, catalog, planner)
    return 0


def _show_plan(console: Console, plan, catalog, planner=None) -> None:
    console.blank()
    console.section("Assessment")
    console.paragraph(plan.summary)

    console.blank()
    console.section(f"Planned this cycle ({len(plan.actions)})")
    if not plan.actions:
        console.bullet("Nothing to change.")
    for action in plan.ordered():
        control = catalog.get(action.control_id)
        console.step(action.order, action.control_id,
                     control.title if control else "", action.rationale,
                     control.risk.value if control else "")
        if action.params:
            console.detail("with " + ", ".join(f"{k}={v}" for k, v in action.params.items()))

    if plan.deferred:
        console.blank()
        console.section(f"Left alone ({len(plan.deferred)})")
        for cid, why in sorted(plan.deferred.items()):
            console.bullet(f"{cid}: {why}")

    if planner and planner.notes:
        console.blank()
        for note in planner.notes:
            (console.warn if note.level == "warn" else console.dim)(note.text)


def cmd_run(args: argparse.Namespace, console: Console) -> int:
    catalog = loader.load()
    settings = _settings_from(args)
    agent, note = build(settings, catalog, listener=_make_listener(console),
                        with_model=not args.no_model)
    _banner(console, settings, note)

    if agent.breaker.open:
        console.warn(agent.breaker.explain())
        console.dim("Run 'lares reset' once the machine has been looked at.")

    cycle = agent.run_cycle()
    _show_cycle(console, cycle, catalog)

    if args.report:
        path = write_report(cycle.scan, cycle, args.report)
        console.ok(f"Report written to {path}")
    return 0


def cmd_watch(args: argparse.Namespace, console: Console) -> int:
    catalog = loader.load()
    settings = _settings_from(args)
    agent, note = build(settings, catalog, listener=_make_listener(console),
                        with_model=not args.no_model)
    _banner(console, settings, note)
    console.ok(f"Running every {settings.interval_minutes} minutes. Ctrl-C to stop.")
    console.blank()

    try:
        agent.run_forever()
    except KeyboardInterrupt:
        agent.stop()
        console.blank()
        console.ok("Stopped.")
    return 0


def _make_listener(console: Console):
    def listener(event: Event) -> None:
        if event.kind == "scan" and event.progress:
            console.progress(event.message, *event.progress)
        elif event.kind == "action":
            console.event(event.message, event.detail)
        elif event.kind == "plan":
            console.dim(event.message)
        elif event.kind == "error":
            console.error(event.message)
        elif event.kind == "wait":
            console.dim(event.message)
    return listener


def _show_cycle(console: Console, cycle, catalog) -> None:
    console.blank()
    console.section("Result")
    if cycle.halted:
        console.warn(cycle.halted)

    for outcome in cycle.outcomes:
        console.outcome(outcome.status.value, outcome.control_id, outcome.message)

    console.blank()
    console.field("Fixed", str(len(cycle.fixed)))
    console.field("Rolled back", str(len(cycle.reverted)))
    console.field("Still open", str(len(cycle.scan.findings) - len(cycle.fixed)))

    remaining = [f for f in cycle.scan.findings
                 if f.control_id not in {o.control_id for o in cycle.fixed}]
    manual = [f for f in remaining
              if (c := catalog.get(f.control_id)) and not c.autonomy_eligible]
    if manual:
        console.blank()
        console.section("Needs a person")
        for finding in manual[:8]:
            control = catalog.get(finding.control_id)
            console.bullet(f"{finding.control_id}: {finding.observed or finding.title}")
            if control and control.blast_radius:
                console.detail(" ".join(control.blast_radius.split())[:180])


def cmd_journal(args: argparse.Namespace, console: Console) -> int:
    journal = Journal()
    entries = journal.recent(args.limit)
    console.rule("Journal")
    if not entries:
        console.dim("Nothing recorded yet.")
        return 0
    for entry in entries:
        console.outcome(entry.outcome.status.value, entry.outcome.control_id,
                        entry.outcome.message, when=entry.at)
        if args.verbose:
            console.detail(f"id {entry.outcome.action_id} | "
                           f"snapshot {entry.outcome.snapshot_id or 'none'}")
    console.blank()
    stats = journal.stats()
    console.field("Totals", ", ".join(f"{v} {k}" for k, v in stats.items() if v))
    console.field("Undoable", str(len(journal.undoable())))
    return 0


def cmd_undo(args: argparse.Namespace, console: Console) -> int:
    journal = Journal()
    catalog = loader.load()

    if args.action_id:
        entry = journal.find(args.action_id)
        if entry is None:
            console.error(f"No journal entry with id {args.action_id}")
            return 1
        targets = [entry]
    else:
        targets = journal.undoable(limit=args.last)
        if not targets:
            console.dim("There is nothing to undo.")
            return 0

    console.rule("Undo")
    executor = Executor(catalog, Context(elevated=is_elevated(), autonomous=False))
    failures = 0
    for entry in targets:
        console.event(f"{entry.outcome.control_id}: undoing", entry.control_title)
        outcome = executor.undo_recorded(entry.outcome.rollback_script,
                                         entry.outcome.control_id)
        console.outcome(outcome.status.value, outcome.control_id, outcome.message)
        journal.record(outcome, control_title=entry.control_title,
                       rationale=f"undo of {entry.outcome.action_id}")
        if outcome.status is not Status.VERIFIED:
            failures += 1
    return 1 if failures else 0


def cmd_model(args: argparse.Namespace, console: Console) -> int:
    console.rule("Model")
    hardware = models.measure()
    console.field("This machine", hardware.describe())
    if hardware.notes:
        for note in hardware.notes:
            console.dim(note)

    if args.download:
        decision = models.choose(hardware, prefer=args.tier)
        if not decision.spec:
            console.error(decision.reason)
            return 1
        spec = decision.spec
        console.blank()
        console.field("Fetching", f"{spec.name}, about {spec.size_mb} MB")
        console.dim(spec.url)
        started = time.monotonic()

        def progress(done: int, total: int) -> None:
            console.progress(f"{done // 2**20}/{total // 2**20} MB", done, total)

        result = download.fetch(spec, progress, force=args.force)
        console.blank()
        if result.ok:
            console.ok(f"{result.message} ({time.monotonic() - started:.0f}s)")
        else:
            console.error(result.message)
            return 1
        return 0

    console.blank()
    console.section("Ladder")
    decision = models.choose(hardware)
    for spec in models.LADDER:
        state = "installed" if spec.path.exists() else f"{spec.size_mb} MB download"
        marker = "selected" if decision.spec and decision.spec.key == spec.key else ""
        console.model_row(spec.key, spec.name, state, spec.expect_tps, marker)
        console.detail(spec.note)

    console.blank()
    console.paragraph(decision.reason)
    engine, _ = Engine.autoselect(prefer=args.tier)
    console.field("Status", engine.status)
    if not decision.present and decision.spec:
        console.dim(f"Download it with:  lares model --download"
                    f"{' --tier ' + args.tier if args.tier else ''}")
    return 0


def cmd_ask(args: argparse.Namespace, console: Console) -> int:
    """The Expert lane: the model writes PowerShell, and a person reads it."""
    console.rule("Expert lane")
    console.warn(
        "This lane asks the model to write a script from scratch. It is screened "
        "for dangerous operations and printed, never run. Read it before you do "
        "anything with it."
    )
    console.blank()

    engine, decision = Engine.autoselect()
    if not engine.available:
        console.error(engine.status)
        console.dim("Download a model first:  lares model --download")
        return 1

    scan = None
    if args.context:
        with console.status("Reading the machine for context"):
            scan = scanner.scan(loader.load())

    with console.status(f"Asking {engine.name}"):
        reply = engine.ask(EXPERT_SYSTEM, expert(args.question, scan),
                           max_tokens=1400, temperature=0.3)

    if not reply.ok:
        console.error(reply.error)
        return 1

    script = strip_fence(reply.text)
    console.script(script)
    console.blank()

    screened = screen_script(script)
    if screened.ok:
        console.ok("No forbidden operation found. That is not the same as correct.")
    else:
        console.error("This script contains operations Lares will not perform:")
        for rule in screened.hits:
            console.bullet(f"{rule.name}: {rule.why}")
    console.dim(f"{engine.name}, {reply.seconds:.1f}s, {reply.tps:.1f} tokens/s")
    return 0


def cmd_reset(args: argparse.Namespace, console: Console) -> int:
    breaker = Breaker()
    if not breaker.open:
        console.ok("Autonomy is already armed; nothing to reset.")
        return 0
    console.warn(breaker.explain())
    breaker.reset()
    console.ok("Autonomy re-armed. The next cycle will change things again.")
    return 0


def cmd_config(args: argparse.Namespace, console: Console) -> int:
    settings = config_mod.load()
    if args.set:
        for pair in args.set:
            if "=" not in pair:
                console.error(f"expected name=value, got {pair!r}")
                return 1
            name, _, value = pair.partition("=")
            name = name.strip()
            if not hasattr(settings, name):
                console.error(f"no such setting {name!r}")
                return 1
            current = getattr(settings, name)
            try:
                setattr(settings, name, _coerce(value.strip(), current))
            except ValueError as exc:
                console.error(str(exc))
                return 1
        for correction in settings.validate():
            console.warn(correction)
        config_mod.save(settings)
        console.ok(f"Saved to {config_mod.path()}")
        console.blank()

    console.rule("Settings")
    for label, value in config_mod.describe(settings):
        console.field(label, value)
    console.blank()
    console.dim(str(config_mod.path()))
    return 0


def _coerce(value: str, current: Any) -> Any:
    if isinstance(current, bool):
        low = value.lower()
        if low in ("true", "yes", "on", "1"):
            return True
        if low in ("false", "no", "off", "0"):
            return False
        raise ValueError(f"{value!r} is not true or false")
    if isinstance(current, int):
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"{value!r} is not a number") from None
    if isinstance(current, list):
        return [v.strip() for v in value.split(",") if v.strip()]
    return value


def cmd_controls(args: argparse.Namespace, console: Console) -> int:
    catalog = loader.load()
    console.rule(f"Catalogue - {len(catalog)} controls")
    console.dim(f"digest {catalog.digest[:16]}")

    if args.show:
        control = catalog.get(args.show.upper())
        if control is None:
            console.error(f"no control {args.show!r}")
            return 1
        console.control_detail(control)
        return 0

    for domain in catalog.domains:
        console.blank()
        console.section(domain)
        for control in catalog.in_domain(domain):
            how = ("automatic" if control.autonomy_eligible
                   else "report only" if not control.has_remediation
                   else "needs a person")
            console.control_row(control.id, control.severity.value,
                                control.risk.value, how, control.title)
    return 0


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lares",
        description="Lares - an autonomous Windows hardening agent with a local model.",
        epilog="Run 'lares run' once to see what it does, then 'lares watch' to leave it running.",
    )
    parser.add_argument("--version", action="version", version=f"Lares {VERSION}")
    parser.add_argument("--demo", action="store_true",
                        help="use synthetic data and change nothing")
    parser.add_argument("--plain", action="store_true",
                        help="plain text output, no colour or boxes")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--ceiling", choices=[t.value for t in RiskTier],
                       help="highest risk tier to apply without a person")
        p.add_argument("--budget", type=int, help="maximum changes this cycle")
        p.add_argument("--domain", action="append",
                       help="restrict to a catalogue domain (repeatable)")
        p.add_argument("--dry-run", action="store_true",
                       help="decide everything, change nothing")

    p = sub.add_parser("scan", help="look at the machine and report")
    common(p)
    p.add_argument("-v", "--verbose", action="store_true", help="show evidence and unredacted facts")
    p.add_argument("--report", metavar="PATH", help="write an HTML or JSON report")
    p.add_argument("--json", action="store_true", help="print the scan as JSON")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("plan", help="show what it would do, and why")
    common(p)
    p.add_argument("--model-tier", help="force a model tier")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("run", help="one full cycle: scan, decide, fix, verify")
    common(p)
    p.add_argument("--model-tier", help="force a model tier")
    p.add_argument("--no-model", action="store_true", help="use the built-in planner")
    p.add_argument("--report", metavar="PATH", help="write a report afterwards")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("watch", help="run cycles on a schedule until stopped")
    common(p)
    p.add_argument("--interval-minutes", type=int, help="minutes between cycles")
    p.add_argument("--model-tier", help="force a model tier")
    p.add_argument("--no-model", action="store_true", help="use the built-in planner")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("journal", help="what Lares has done to this machine")
    p.add_argument("-n", "--limit", type=int, default=30)
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_journal)

    p = sub.add_parser("undo", help="put a change back")
    p.add_argument("action_id", nargs="?", help="a journal action id")
    p.add_argument("--last", type=int, default=1, help="undo the N most recent changes")
    p.set_defaults(func=cmd_undo)

    p = sub.add_parser("model", help="show, choose or download the local model")
    p.add_argument("--download", action="store_true")
    p.add_argument("--tier", default="", help=f"one of {sorted(models.BY_KEY)}")
    p.add_argument("--force", action="store_true", help="re-download even if present")
    p.set_defaults(func=cmd_model)

    p = sub.add_parser("ask", help="have the model write a script for you to read")
    p.add_argument("question")
    p.add_argument("--context", action="store_true", help="include machine facts")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("controls", help="browse the control catalogue")
    p.add_argument("--show", metavar="ID", help="show one control in full")
    p.set_defaults(func=cmd_controls)

    p = sub.add_parser("reset", help="re-arm autonomy after the breaker halted it")
    p.set_defaults(func=cmd_reset)

    p = sub.add_parser("config", help="show or change settings")
    p.add_argument("--set", action="append", metavar="NAME=VALUE")
    p.set_defaults(func=cmd_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.demo:
        set_demo(True)

    console = Console(plain=args.plain)
    try:
        return args.func(args, console)
    except loader.CatalogError as exc:
        console.error(f"The control catalogue is not usable: {exc}")
        return 2
    except KeyboardInterrupt:
        console.blank()
        console.dim("Stopped.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
