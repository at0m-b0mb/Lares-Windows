"""Lares Freehand - the model writes every fix, and you watch it happen.

A separate program from ``lares`` on purpose. The two have different answers to
the question that matters most about a tool like this - who wrote the code that
runs on your machine - and a flag is too quiet a way to switch between them.

    lares            the model chooses from remediations a person wrote.
                     It cannot author a character of what executes.

    lares-freehand   the model writes the PowerShell. There is no catalogue
                     here, nothing canned, nothing pre-approved. The
                     application reads the machine, asks, and runs the answer.

Everything is printed as it happens: what was read, the exact prompt, the reply
arriving one token at a time, the three scripts the model wrote, what the
screen made of them, every stage of applying them, and the result.

The window on the right of that trade is worth naming plainly. A model-written
fix that is merely wrong will run. The screen stops catastrophes, not mistakes,
and the undo is written by the same model that wrote the fix. Everything is
kept verbatim in the journal so a person can read exactly what ran.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from typing import Any

from .. import logs
from ..brain.engine import Engine
from ..brain.freehand import DEFAULT_BUDGET, Freehand, Session
from ..brain.replay import FREEHAND_ANSWERS, Replay
from ..core import Status
from ..sense import surface as surface_mod
from ..version import VERSION
from ..winsys import current_user, is_elevated, set_demo
from . import interactive, live as live_mod
from .render import Console

#: How the outcome of one attempt reads in the summary.
HOW = {
    Status.VERIFIED: ("ok", "fixed, and the model's own check proves it"),
    Status.SKIPPED: ("dim", "already in the state the model wanted"),
    Status.SIMULATED: ("dim", "decided, not applied"),
    Status.UNVERIFIED: ("warn", "applied, nothing proves it worked"),
    Status.ROLLED_BACK: ("warn", "applied, did not work, put back"),
    Status.REFUSED: ("warn", "not run"),
    Status.FAILED: ("error", "failed"),
}


def _header(console: Console, engine: Engine, args) -> None:
    console.rule(f"Lares Freehand {VERSION}")
    console.paragraph(
        "There is no catalogue in this program. It reads your machine, asks "
        "the model what is wrong with it, and runs the PowerShell the model "
        "writes back. Every word in both directions is printed below.")
    console.blank()
    console.field("Machine", current_user())
    console.field("Rights", "administrator" if is_elevated()
                  else "standard user - nothing can be changed")
    console.field("Model", engine.name)
    console.field("Decides", "the model, entirely")
    console.field("Writes the fixes", "the model, entirely")
    console.field("This program", "reads, screens, runs, verifies, records")
    console.field("Issues per pass", str(args.budget))
    console.field("Mode", "dry run - nothing will be changed" if args.dry_run
                  else "applying what the model writes")
    console.blank()
    if args.dry_run and not args.recorded:
        console.detail(
            "A dry run still runs the model's own check script, because that "
            "is how it knows whether a fix is needed at all. The check is "
            "screened like anything else and is meant to be read-only, but it "
            "is model-written code and it does run.")
    console.warn(
        "The screen refuses a short list of catastrophes - formatting a disk, "
        "deleting shadow copies, downloading and running code, turning the "
        "firewall off. It cannot tell a wrong fix from a right one.")


def _survey(console: Console, args, live: bool) -> surface_mod.Surface:
    console.blank()
    console.rule("1.  what is on this machine")
    console.paragraph(
        "Six read-only readings. Installed software and versions, every "
        "listening port and who owns it, running services, local accounts, "
        "and the settings that decide what is reachable from elsewhere. "
        "Nothing here has an opinion; it is the raw material.")
    console.blank()

    only = [p.strip() for p in args.only.split(",")] if args.only else None
    with live_mod.progress(console, True, "Reading") as report:
        found = surface_mod.survey(progress=report, only=only)

    console.blank()
    for section in found.sections:
        if section.error:
            console.warn(f"{section.title}: could not be read ({section.error})")
        else:
            console.field(section.title, f"{len(section.rows)} entries")

    ports = found.get("ports")
    if ports and ports.rows:
        exposed = [r for r in ports.rows if r.get("exposed")]
        console.blank()
        console.section(f"Listening, reachable from the network ({len(exposed)})")
        for row in exposed[:20]:
            console.bullet(f"{row.get('proto')}/{row.get('port')} - "
                           f"{row.get('process') or 'unknown process'}")
        if len(exposed) > 20:
            console.dim(f"  ... and {len(exposed) - 20} more")

    console.blank()
    if live:
        # Deliberately not printed here. The live view prints the prompt in
        # full a moment later, and that prompt contains this reading verbatim -
        # so printing a second rendering of it, built with different arguments,
        # would be showing something that merely resembles what gets sent. One
        # of them would eventually be wrong and there would be no way to tell
        # which.
        console.dim("  The full reading is below, inside the prompt it is sent in.")
    else:
        console.section("Everything that was read")
        console.script(found.render(limit=args.show))
        console.dim("  What is sent to the model is trimmed to fit its context "
                    "window, so it may be shorter than this.")
    return found


def _assessment(console: Console, session: Session) -> None:
    console.blank()
    console.rule("3.  what the model says is wrong")
    if session.error:
        console.error(session.error)
        return
    console.paragraph(session.summary or "It gave no summary.")
    console.blank()
    if not session.issues:
        console.ok("It found nothing it would act on.")
        return
    console.section(f"Issues ({len(session.issues)})")
    for issue in session.issues:
        console.bullet(issue.headline())
        if issue.why:
            console.detail(issue.why)
        if issue.evidence:
            console.detail(f"from the reading: {issue.evidence}")


def _remedy(console: Console, remedy) -> None:
    console.blank()
    console.rule(f"{remedy.issue.id}  the code the model wrote")
    console.field("Problem", remedy.issue.title)
    console.field("Written in", f"{remedy.seconds:.1f}s")
    if remedy.explain:
        console.blank()
        console.paragraph(remedy.explain)

    for label, body in (("Its check - does this need doing?", remedy.check),
                        ("Its fix - what will run", remedy.fix),
                        ("Its undo - how it puts it back", remedy.undo)):
        console.blank()
        console.section(label)
        if body.strip():
            console.script(body)
        else:
            console.dim("    (the model wrote none)")

    console.blank()
    console.section("What the screen made of it")
    if remedy.refused:
        console.error(f"Refused: {remedy.refused}")
        for screened in (remedy.fix_screen, remedy.undo_screen):
            if screened is not None and not screened.ok:
                for rule in screened.hits:
                    console.bullet(f"{rule.name}: {rule.why}")
    else:
        console.ok("No forbidden operation found. That is not the same as correct.")


def _attempt(console: Console, attempt) -> None:
    console.blank()
    style, meaning = HOW.get(attempt.status, ("dim", attempt.status.value))
    line = f"{attempt.remedy.issue.id}: {meaning}"
    getattr(console, style if style != "dim" else "dim")(line)
    console.detail(attempt.outcome.message)
    if attempt.before:
        console.field("  check before", attempt.before.splitlines()[0][:90])
    if attempt.after:
        console.field("  check after", attempt.after.splitlines()[0][:90])


def _summary(console: Console, session: Session, args) -> None:
    console.blank()
    console.rule("what happened")
    counts = session.counts()
    if not session.attempts:
        console.dim("Nothing was attempted.")
    for status, count in sorted(counts.items(), key=lambda kv: kv[0].value):
        console.field(HOW.get(status, ("", status.value))[1], str(count))

    console.blank()
    console.field("Journal", "lares journal -v")
    console.field("The conversation", "lares transcript -v")
    console.field("Put something back", "lares undo --last 1")
    console.blank()
    if args.dry_run:
        console.dim("This was a dry run. Nothing on this machine was changed.")
    if args.recorded:
        console.paragraph(
            "Those answers were written out for this walkthrough rather than "
            "produced by a model reading this machine. Everything they passed "
            "through - the screen, the check, the apply, the verify - is the "
            "code that runs for real; only the answers were not live.")
    else:
        console.paragraph(
            "Every script above was written by the model during this run and "
            "is kept verbatim in the journal, including the undo.")


def dispatch(argv: list[str], console: Console) -> int:
    args = build_parser().parse_args(argv)
    if args.demo:
        set_demo(True)

    logs.record_startup("lares-freehand")
    logs.get().info("cli", "Freehand started", budget=args.budget,
                    dry_run=args.dry_run)

    if args.recorded:
        # Forced, and not negotiable. These answers were written for this
        # walkthrough rather than produced by a model looking at this machine,
        # and running them against a real one would be acting on a decision
        # nothing made about it.
        args.dry_run = True
        engine: Any = Replay(list(FREEHAND_ANSWERS), pace=max(0.0, args.pace))
        console.warn(
            "Recorded walkthrough: no model is running. The answers below are "
            "written-out examples in the shape a model returns, not a capture "
            "of one, and nothing will be changed.")
    else:
        engine, decision = Engine.autoselect(prefer=args.model_tier)

    if not engine.available:
        console.rule(f"Lares Freehand {VERSION}")
        console.error("This program is nothing without the model, and there "
                      "is no model here.")
        console.advice(engine.status, indent=2)
        console.advice(
            "Use lares-freehand-full-x64.exe or lares-freehand-full-arm64.exe, "
            "which carry the model inside them, or run "
            "'lares model --download' to fetch one.", indent=2)
        return 1

    if not is_elevated() and not args.dry_run:
        args.dry_run = True
        console.warn("Not running as administrator, so this is a dry run: it "
                     "will read, ask and show, and change nothing.")
        console.advice("Right-click the executable and choose 'Run as "
                       "administrator' to let it apply what the model writes.",
                       indent=2)

    live = not args.no_live
    _header(console, engine, args)
    found = _survey(console, args, live)

    console.blank()
    console.rule("2.  the conversation")
    console.paragraph(
        "What follows is the exchange itself. The prompt is the prompt that "
        "was sent, and the reply arrives one token at a time because that is "
        "the speed the model produces it.")
    if live:
        engine.watch = live_mod.watch(console)

    agent = Freehand(engine, budget=args.budget, dry_run=args.dry_run,
                     timeout=args.timeout)

    def stage(remedy, name: str, detail: str) -> None:
        console.event(f"{remedy.issue.id}: {name}", detail)

    session = agent.run(
        found,
        progress=lambda text: console.dim(f"  {text}"),
        on_assessment=lambda s: _assessment(console, s),
        on_remedy=lambda r: _remedy(console, r),
        on_stage=stage,
        on_attempt=lambda a: _attempt(console, a),
    )

    _summary(console, session, args)
    return 0 if not session.error else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lares-freehand",
        description="Lares Freehand - reads your machine, asks the model what "
                    "is wrong, and runs the PowerShell it writes back.",
        epilog="Nothing in this program is pre-written. Start with --dry-run "
               "if you would like to read what it would do first.",
    )
    parser.add_argument("--version", action="version",
                        version=f"Lares Freehand {VERSION}")
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET,
                        help=f"issues to act on in one pass (default {DEFAULT_BUDGET})")
    parser.add_argument("--dry-run", action="store_true",
                        help="read, ask and show the scripts; change nothing")
    parser.add_argument("--timeout", type=int, default=240,
                        help="seconds any one script may run for")
    parser.add_argument("--only", default="",
                        help="restrict the reading, e.g. ports,software")
    parser.add_argument("--show", type=int, default=40,
                        help="rows per reading to print and to send")
    parser.add_argument("--model-tier", default="",
                        help="force a model tier instead of choosing one")
    parser.add_argument("--recorded", action="store_true",
                        help="walk through the lane with written-out answers, "
                             "on a machine with no model; implies --dry-run")
    parser.add_argument("--pace", type=float, default=0.012,
                        help="seconds between fragments of a recorded reply; "
                             "0 prints it at once (default 0.012)")
    parser.add_argument("--no-live", action="store_true",
                        help="do not stream the reply token by token")
    parser.add_argument("--plain", action="store_true",
                        help="no colour, no spinner")
    parser.add_argument("--demo", action="store_true",
                        help="synthetic machine data; changes nothing")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point, written so a double-clicked window cannot vanish.

    The same lesson as the main application: an exception on the way out of a
    console program launched from Explorer closes the window before anyone can
    read what it said, which makes the one piece of information that mattered
    the one piece nobody gets.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    console = Console(plain="--plain" in argv)
    standalone = interactive.owns_console_alone() and argv == []

    try:
        code = dispatch(argv, console)
    except KeyboardInterrupt:
        console.blank()
        console.dim("Stopped.")
        code = 130
    except SystemExit as exit_:          # argparse
        code = int(exit_.code or 0)
    except Exception as exc:             # noqa: BLE001 - the window must survive
        report = logs.get().error("cli", "Freehand failed", exc=exc)
        console.blank()
        console.error(f"It stopped: {exc}")
        console.detail(f"Saved as {report.error_id} - see it with "
                       f"'lares errors --show {report.error_id}'")
        if "--debug" in argv:
            console.script(traceback.format_exc())
        code = 1

    if standalone:
        interactive.pause_before_closing(console)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
