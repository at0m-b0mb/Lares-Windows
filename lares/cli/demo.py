"""A narrated walkthrough of one full round trip.

Everything Lares does to a machine passes through the same seven stages, and
most of it is invisible - the prompt is assembled and thrown away, the model's
answer is parsed and discarded, the PowerShell is rendered straight into a
subprocess. This command does exactly what a cycle does and shows the working
at every step:

    1  what it reads off the machine
    2  what it asks the model, and whether that fits
    3  what the model answers, verbatim
    4  what the guard makes of that
    5  the exact PowerShell that would run, and its undo
    6  applying it: probe, snapshot, apply, verify, health, keep or undo
    7  what was written down afterwards

It is the honest version of a demo: the artefacts are real. The prompt shown
is the prompt sent, the reply shown is the reply received, and the script
shown is the script that would execute, character for character.

With a model installed it queries it for real. Without one it uses a recorded
answer - a real reply from Qwen2.5-Coder 1.5B, kept verbatim, including the
mistake it made - and says so clearly rather than pretending.
"""

from __future__ import annotations

import json

from .. import logs
from ..act.execute import Executor
from ..act.guard import Context, Refused, clear_to_run, screen_script
from ..brain import engine as engine_mod
from ..brain import prompt as prompt_mod
from ..brain.engine import Engine, extract_json
from ..brain.plan import Planner
from ..brain.retrieve import Index, context_for
from ..catalog.loader import render
from ..core import RiskTier, Status
from ..sense import scanner
from ..version import VERSION
from ..winsys import is_demo, is_elevated
from .render import Console

#: A real answer from Qwen2.5-Coder 1.5B Q4_K_M, kept exactly as it came back,
#: including the invented control id. A demo that only ever shows the model
#: getting it right teaches the wrong lesson about what this guard is for.
RECORDED_REPLY = """{
  "summary": "This machine answers multicast name requests, which hands an attacker on the same network a password hash for the asking. It also lets any user install a printer driver as SYSTEM. Both are reversible and worth fixing now. BitLocker is off, but starting encryption is not something to do unattended.",
  "actions": [
    {"control_id": "NET-005", "params": {}, "rationale": "LLMNR lets anyone on this network answer a name lookup and collect an authentication attempt. DNS already works here, so the fallback buys nothing.", "confidence": 90, "order": 1},
    {"control_id": "SVC-003", "params": {}, "rationale": "Any user being able to make the print spooler install a driver as SYSTEM is a local administrator in one step.", "confidence": 85, "order": 2}
  ],
  "deferred": {
    "DEF-007": "Starting BitLocker rewrites the drive and needs a recovery key stored somewhere safe. A person should do this.",
    "SYS-006": "The audit log is not large enough."
  }
}"""


def _heading(console: Console, number: int, title: str) -> None:
    console.blank()
    console.rule(f"{number}.  {title}")


def _block(console: Console, text: str, limit: int = 2000) -> None:
    shown = text if len(text) <= limit else text[:limit] + "\n... (truncated for display)"
    console.script(shown)


def run(args, console: Console, catalog) -> int:
    """Walk through one round trip, showing the working."""
    log = logs.get()
    log.info("cli", "Running the narrated demonstration")

    console.rule(f"Lares {VERSION} - how it works")
    console.paragraph(
        "One full round trip, with the working shown. Every artefact below is "
        "the real one: the prompt is what gets sent, the reply is what comes "
        "back, and the PowerShell is what would run.")
    if is_demo():
        console.blank()
        console.warn("Demo mode: the machine data is synthetic and nothing "
                     "will be changed.")

    # -- 1 ---------------------------------------------------------------
    _heading(console, 1, "What it reads off the machine")
    console.paragraph(
        "Every control in the catalogue carries its own detection probe - a "
        "read-only PowerShell script written by a person. The scanner runs "
        "them and turns each non-compliant answer into a finding.")

    with console.status("Checking the machine") as status:
        scan = scanner.scan(catalog,
                            progress=lambda cid, i, n: status(f"{cid} ({i}/{n})"))

    console.blank()
    console.field("Controls checked", str(len(catalog)))
    console.field("Findings", str(len(scan.findings)))
    console.blank()
    for finding in scan.by_severity()[:5]:
        console.finding(finding.severity.value, finding.control_id,
                        finding.observed or finding.title, "")
    if len(scan.findings) > 5:
        console.dim(f"... and {len(scan.findings) - 5} more")

    example = catalog.require("NET-005")
    console.blank()
    console.section(f"The probe behind {example.id}, in full")
    _block(console, example.detect)

    # -- 2 ---------------------------------------------------------------
    _heading(console, 2, "What it asks the model")

    engine, decision = Engine.autoselect()
    window = engine.spec.context if engine.spec else 4096
    index = Index.build(catalog)
    queries = [f.observed or f.title for f in scan.by_severity()[:prompt_mod.MAX_FINDINGS]]
    must = {f.control_id for f in scan.findings}
    context = context_for(index, queries, must, limit=min(12, len(must) + 3))

    char_budget = prompt_mod.budget_for(window, engine_mod.PLAN_TOKENS,
                                        prompt_mod.SYSTEM)
    user = prompt_mod.build(scan, context, "caution", is_elevated(), 8,
                            char_budget=char_budget)

    console.paragraph(
        "The model is not asked to remember Windows security. The facts come "
        "from the catalogue, retrieved by relevance, so its job is judgement "
        "rather than recall - which is what small models are actually good at.")
    console.blank()

    system_tokens = prompt_mod.estimate_tokens(prompt_mod.SYSTEM)
    user_tokens = prompt_mod.estimate_tokens(user)
    reply_room = prompt_mod.answer_room(window, engine_mod.PLAN_TOKENS)
    console.field("Model", engine.name)
    console.field("Context window", f"{window} tokens")
    console.field("System prompt", f"{system_tokens} tokens")
    console.field("This machine's data", f"{user_tokens} tokens")
    console.field("Reserved for the reply", f"{reply_room} tokens")
    total = system_tokens + user_tokens + reply_room
    console.field("Total", f"{total} of {window} tokens "
                           f"({'fits' if total <= window else 'OVERFLOWS'})")
    console.detail("An oversized prompt is not refused - its front is dropped, "
                   "and the front is where the rules are.")

    console.blank()
    console.section("The rules it is given")
    _block(console, prompt_mod.SYSTEM, limit=1400)

    console.blank()
    console.section("What it is told about this machine")
    _block(console, user, limit=2200)

    # -- 3 ---------------------------------------------------------------
    _heading(console, 3, "What the model answers")

    if engine.available and not args.recorded:
        console.paragraph(f"Asking {engine.name}. On a slow CPU this takes a "
                          "minute or two.")
        with console.status("Thinking"):
            reply = engine.ask(prompt_mod.SYSTEM, user,
                               schema=prompt_mod.PLAN_SCHEMA,
                               max_tokens=reply_room)
        if reply.ok:
            raw_text = reply.text
            console.blank()
            console.field("Answered in", f"{reply.seconds:.1f}s")
            console.field("Speed", f"{reply.tps:.1f} tokens/s")
            source = "live"
        else:
            console.warn(f"The model did not answer ({reply.error}).")
            console.dim("Falling back to the recorded reply.")
            raw_text, source = RECORDED_REPLY, "recorded"
    else:
        reason = ("--recorded was given" if args.recorded
                  else f"no model is loaded here ({engine.status})")
        console.paragraph(
            f"Using a recorded reply, because {reason}. It is a real answer "
            "from Qwen2.5-Coder 1.5B, kept verbatim - including the mistake it "
            "made, because a demonstration where the model never errs teaches "
            "the wrong lesson about what the next stage is for.")
        raw_text, source = RECORDED_REPLY, "recorded"

    console.blank()
    console.section(f"Raw reply ({source}), exactly as received")
    _block(console, raw_text, limit=2200)

    # -- 4 ---------------------------------------------------------------
    _heading(console, 4, "What the guard makes of it")
    console.paragraph(
        "The model can name a control and supply parameters. It can never "
        "introduce one. Everything it said is checked against the catalogue "
        "before a single character reaches PowerShell.")

    parsed = extract_json(raw_text)
    if parsed is None:
        console.error("The reply was not usable JSON, so nothing would run.")
        return 1

    planner = Planner(catalog, engine)
    plan = planner._validate(parsed, scan, RiskTier.CAUTION, is_elevated(), 8)

    console.blank()
    console.section("Accepted")
    for action in plan.ordered():
        control = catalog.get(action.control_id)
        console.step(action.order, action.control_id,
                     control.title if control else "", action.rationale,
                     control.risk.value if control else "")

    proposed = {str(a.get("control_id", "")).upper()
                for a in parsed.get("actions", []) if isinstance(a, dict)}
    deferred_raw = {str(k).upper() for k in (parsed.get("deferred") or {})}
    invented = sorted((proposed | deferred_raw) - set(catalog.ids))

    console.blank()
    console.section("Refused, and why")
    if invented:
        for control_id in invented:
            console.bullet(f"{control_id}: not in the catalogue. The model "
                           "invented it; Lares did not check for it and will "
                           "not claim it did.")
    for note in planner.notes:
        # The invented ids are listed above in the demo's own words; repeating
        # the planner's note about them reads as a stutter.
        if note.level == "warn" and "not in the catalogue" not in note.text:
            console.bullet(note.text)
    if not invented and not any(n.level == "warn" for n in planner.notes):
        console.dim("Nothing was refused this time.")

    # -- 5 ---------------------------------------------------------------
    _heading(console, 5, "The exact PowerShell that would run")

    if not plan.actions:
        console.dim("Nothing was accepted, so there is nothing to show.")
        return 0

    first = plan.ordered()[0]
    control = catalog.require(first.control_id)
    ctx = Context(elevated=is_elevated(), ceiling=RiskTier.CAUTION, autonomous=True)

    try:
        clean = clear_to_run(control, first.params, ctx)
    except Refused as refusal:
        console.error(f"{control.id} was refused: {refusal.reason}")
        return 0

    remediation = render(control.remediate, clean)
    rollback = render(control.rollback, clean) if control.rollback else ""

    console.field("Control", f"{control.id} - {control.title}")
    console.field("Risk", control.risk.value)
    console.field("Parameters", json.dumps(clean) if clean else "none")
    console.field("Screened", "passed" if screen_script(remediation).ok else "REFUSED")
    console.blank()
    console.section("Remediation")
    _block(console, remediation)
    if rollback:
        console.blank()
        console.section("Its undo, rendered at the same time")
        _block(console, rollback)
        console.detail("This is stored in the journal before the change is "
                       "made, so it can be undone months later without the "
                       "model, the catalogue, or the original finding.")

    # -- 6 ---------------------------------------------------------------
    _heading(console, 6, "Applying it")
    console.paragraph(
        "Nothing here is a confirmation dialog. What replaces one is that "
        "every step is measured and the change is undone on the spot if it "
        "did not work or made something else worse.")
    console.blank()
    for stage, what in [
        ("probe", "re-read the state. Already fixed? Then do nothing."),
        ("baseline", "read the health signals while the machine is known good."),
        ("snapshot", "export the registry keys, rules and services it will touch."),
        ("apply", "run the remediation."),
        ("verify", "re-run the same probe that found the problem."),
        ("health", "re-read the signals. Did anything that worked stop working?"),
        ("decide", "keep it, or put it back, now."),
    ]:
        console.field(f"  {stage}", what)

    console.blank()
    executor = Executor(catalog, ctx, dry_run=True,
                        listener=lambda r: console.event(
                            f"{r.control_id}: {r.stage}", r.message))
    outcome = executor.apply(first)

    console.blank()
    console.field("Outcome", outcome.status.value)
    console.field("Message", outcome.message)
    if outcome.status is Status.SIMULATED:
        console.detail("A dry run: decided everything, changed nothing.")

    # -- 7 ---------------------------------------------------------------
    _heading(console, 7, "What gets written down")
    console.paragraph(
        "Three records, kept apart because they answer different questions.")
    console.blank()
    console.field("Journal", "what changed, and the rendered script to undo it")
    console.field("Activity log", "what happened, in order")
    console.field("Transcript", "what was asked, what came back, and which of "
                                "its choices survived the guard")
    console.blank()
    console.dim("lares journal    lares logs    lares transcript -v    lares errors")

    console.blank()
    console.rule("End")
    console.paragraph(
        "That is the whole loop. The model chose from a catalogue a person "
        "wrote, the guard checked every word of its answer, the change was "
        "verified against the same probe that found the problem, and an undo "
        "was written down before anything was touched.")
    return 0
