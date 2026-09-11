"""What we actually say to the model.

Two things shape everything here. First, the model runs on a laptop CPU, so a
prompt that is twice as long is a cycle that takes twice as long - every line has
to earn its place. Second, it is a 1.5B-to-7B model, which means it follows
concrete rules far better than it follows tone. So the instructions are short,
numbered, and phrased as hard constraints rather than preferences.

The model is never asked to write PowerShell in the planning path. It is asked to
choose from a menu and explain itself. Keeping the job that narrow is what makes
a small model good enough for it.
"""

from __future__ import annotations

import json
from typing import Any

from ..core import Fact, Finding, Scan

#: Cap on how many findings go into one prompt. Beyond this the context window
#: on the small tiers overflows and the model starts dropping the schema.
MAX_FINDINGS = 18

PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "control_id": {"type": "string"},
                    "params": {"type": "object"},
                    "rationale": {"type": "string"},
                    "confidence": {"type": "integer"},
                    "order": {"type": "integer"},
                },
                "required": ["control_id", "rationale", "order"],
            },
        },
        "deferred": {"type": "object"},
    },
    "required": ["summary", "actions"],
}


SYSTEM = """You are the planner inside Lares, a Windows hardening agent. You do not \
run commands. You read a security scan and decide which of a fixed set of \
pre-written, pre-reviewed controls should be applied, in what order.

Rules, all of them absolute:
1. Every control_id you output MUST appear in the CONTROLS section below. If a \
problem has no matching control, do not invent one - say so in "deferred".
2. Supply exactly the parameters the control declares, with values of the \
declared type and inside the declared range. Never add a parameter that is not \
listed. Use the values the scan already discovered when it supplies them.
3. Never write PowerShell, shell commands, registry paths or file paths. The \
scripts already exist and you cannot change them.
4. Do not plan a control marked report-only, or one marked as never applied \
automatically. Put those in "deferred" with a short reason.
5. Order matters. Use "order" starting at 1. Apply a control's dependencies \
before it. Put the cheapest reversible fixes for the most exploitable problems \
first, so that a cycle cut short still leaves the machine better off.
6. "rationale" is one sentence, plain English, addressed to the person who owns \
this machine. Say what changes and why it is worth it. No jargon, no filler.
7. "summary" is two or three sentences about this specific machine's posture. \
Never claim the machine is secure or safe. Describe what was checked and what is \
still open.
8. Reply with one JSON object and nothing else. No markdown fence, no commentary \
before or after."""


def _facts_block(facts: list[Fact], limit: int = 22) -> str:
    lines = []
    for fact in facts[:limit]:
        shown = fact.redacted() if fact.sensitive else fact
        lines.append(f"- {shown.key}: {shown.value}")
    return "\n".join(lines)


def _findings_block(findings: list[Finding]) -> str:
    lines = []
    for finding in findings[:MAX_FINDINGS]:
        parts = [f"- [{finding.severity.value.upper()}] {finding.control_id}: {finding.observed or finding.title}"]
        if finding.params:
            parts.append(f"  discovered parameters: {json.dumps(finding.params)}")
        lines.append("\n".join(parts))
    extra = len(findings) - MAX_FINDINGS
    if extra > 0:
        lines.append(f"- ...and {extra} more, which will be planned on the next cycle.")
    return "\n".join(lines)


def build(scan: Scan, controls_context: str, ceiling: str, elevated: bool,
          budget: int) -> str:
    """The user message for one planning call."""
    findings = scan.by_severity()
    machine = _facts_block(scan.facts)

    constraints = [
        f"- You may plan at most {budget} actions this cycle.",
        f"- Controls with risk above '{ceiling}' must be deferred, not planned.",
    ]
    if not elevated:
        constraints.append(
            "- This process is NOT running as administrator, so any control "
            "needing admin rights must be deferred."
        )

    return f"""MACHINE
{machine}

OPEN FINDINGS ({len(findings)} total, most severe first)
{_findings_block(findings)}

CONTROLS AVAILABLE TO YOU
{controls_context}

CONSTRAINTS THIS CYCLE
{chr(10).join(constraints)}

Reply with one JSON object:
{{"summary": "...", "actions": [{{"control_id": "...", "params": {{}}, "rationale": "...", "confidence": 0-100, "order": 1}}], "deferred": {{"CONTROL-ID": "reason"}}}}"""


# --------------------------------------------------------------------------
# The Expert lane
# --------------------------------------------------------------------------

EXPERT_SYSTEM = """You are a Windows systems engineer writing PowerShell for a \
security hardening tool. You write scripts that a human being will read before \
running.

Rules:
1. Windows PowerShell 5.1 compatible. No modules that are not present on a \
default Windows install.
2. The script must be idempotent - running it twice must be safe.
3. Every script must begin with a comment block saying what it changes and how \
to undo it.
4. Never format a disk, delete a directory tree, remove a user, delete shadow \
copies, edit boot configuration, restart the machine, disable antivirus, or \
download and execute anything.
5. Never use Invoke-Expression or an encoded command.
6. Prefer reading and reporting over changing. If the request cannot be done \
safely, say so in a comment instead of writing something risky.
7. Output only the script."""


def expert(question: str, scan: Scan | None = None) -> str:
    """User message for the Expert lane, where the model does write script.

    Whatever comes back is screened by ``act.guard`` and shown to a person. It is
    never executed by the autonomous loop - that is the whole point of it being a
    separate lane.
    """
    context = ""
    if scan is not None:
        context = f"\n\nFor context, this machine:\n{_facts_block(scan.facts, limit=12)}"
    return f"{question}{context}"
