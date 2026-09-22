"""Reports you could hand to someone else.

HTML, JSON or plain text, chosen from the filename. The HTML is a single
self-contained file with no external references - no fonts fetched from a CDN,
no scripts - because a security report that phones somewhere when opened is a
poor advertisement for the tool that wrote it.

Sensitive facts are redacted by default. A report is the artefact most likely to
be emailed to somebody, and the machine's hostname, address and username are not
needed to understand what was wrong with it.
"""

from __future__ import annotations

import html
from dataclasses import replace
from pathlib import Path

from .core import Cycle, Scan, Severity, Status, dumps
from .version import NAME, VERSION

SEVERITY_COLOUR = {
    Severity.CRITICAL: "#8C1D18",
    Severity.HIGH: "#A8471C",
    Severity.MEDIUM: "#8A6D1F",
    Severity.LOW: "#5B6670",
    Severity.INFO: "#5B6670",
}

STATUS_WORD = {
    Status.VERIFIED: "Fixed",
    Status.UNVERIFIED: "Applied, pending restart",
    Status.SIMULATED: "Would fix",
    Status.ROLLED_BACK: "Undone automatically",
    Status.FAILED: "Failed",
    Status.REFUSED: "Refused",
    Status.SKIPPED: "Skipped",
}


def write_report(scan: Scan, cycle: Cycle | None, path: str,
                 redact: bool = True) -> Path:
    """Write a report, choosing the format from the file extension."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    suffix = target.suffix.lower()

    if suffix == ".json":
        # Redacted like every other format. This branch used to ignore the
        # flag completely, so the one format most likely to be attached to a
        # ticket or posted in a thread was the one that carried the hostname
        # and the account names out unredacted - while the top of this file
        # said facts are redacted by default.
        payload = {"scan": _redacted(scan) if redact else scan}
        if cycle:
            payload["cycle"] = cycle
        target.write_text(dumps(payload), encoding="utf-8")
    elif suffix in (".txt", ".text", ".md"):
        target.write_text(as_text(scan, cycle, redact), encoding="utf-8")
    else:
        if not suffix:
            target = target.with_suffix(".html")
        target.write_text(as_html(scan, cycle, redact), encoding="utf-8")
    return target


def _redacted(scan: Scan) -> Scan:
    """The same scan with its sensitive facts masked.

    A copy, because the caller's scan is used again afterwards - by the
    console, by the desktop pages - and quietly blanking its facts in place
    because someone asked for a report would be a surprising thing for a
    write function to do.
    """
    return replace(scan, facts=[f.redacted() if f.sensitive else f
                                for f in scan.facts])


# --------------------------------------------------------------------------
# Plain text
# --------------------------------------------------------------------------

def as_text(scan: Scan, cycle: Cycle | None = None, redact: bool = True) -> str:
    from .sense.scanner import posture

    lines = [f"{NAME} {VERSION} - hardening report", f"Generated {scan.started_at}", ""]
    if scan.demo:
        lines += ["DEMO MODE: this report describes synthetic data.", ""]

    verdict, detail = posture(scan)
    lines += [verdict.upper(), detail, "", "MACHINE", ""]
    for fact in scan.facts:
        shown = fact.redacted() if (redact and fact.sensitive) else fact
        lines.append(f"  {shown.key:<24} {shown.value}")

    counts = scan.counts()
    lines += ["", "FINDINGS", ""]
    lines.append("  " + ", ".join(f"{counts[s]} {s.value}" for s in Severity if counts[s]))
    lines.append("")
    for finding in scan.by_severity():
        lines.append(f"  [{finding.severity.value.upper():<8}] {finding.control_id}  "
                     f"{finding.observed or finding.title}")

    if cycle:
        lines += ["", "WHAT LARES DID", ""]
        if not cycle.outcomes:
            lines.append("  Nothing was changed.")
        for outcome in cycle.outcomes:
            word = STATUS_WORD.get(outcome.status, outcome.status.value)
            lines.append(f"  {word:<26} {outcome.control_id}  "
                         f"{' '.join(outcome.message.split())}")
        if cycle.halted:
            lines += ["", f"  Halted: {cycle.halted}"]

    lines += ["", "This report covers the controls Lares checks. A clean result "
                  "means those checks passed, not that the machine is secure.", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_CSS = """
:root {
  --paper: #F3F1EC; --card: #FFFFFF; --ink: #1A1916; --muted: #6B6558;
  --rule: #DDD8CD; --gold: #B8860B; --gold-soft: #F0E6CC;
}
@media (prefers-color-scheme: dark) {
  :root { --paper: #000000; --card: #121212; --ink: #ECEAE4; --muted: #9A948A;
          --rule: #2A2A2A; --gold: #D4A73A; --gold-soft: #2A2316; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink);
       font: 15px/1.6 -apple-system, "Segoe UI", Roboto, sans-serif; }
.wrap { max-width: 60rem; margin: 0 auto; padding: 3rem 1.5rem 5rem; }
h1 { font-family: Georgia, "Times New Roman", serif; font-weight: 500;
     font-size: 2.1rem; margin: 0 0 .2rem; letter-spacing: -.01em; }
h2 { font-size: .75rem; text-transform: uppercase; letter-spacing: .1em;
     color: var(--gold); margin: 2.5rem 0 .75rem; font-weight: 700; }
.sub { color: var(--muted); margin: 0 0 2.5rem; }
.card { background: var(--card); border: 1px solid var(--rule);
        border-radius: 3px; padding: 1.25rem 1.5rem; }
.verdict { border-left: 3px solid var(--gold); }
.verdict strong { font-family: Georgia, serif; font-size: 1.5rem;
                  font-weight: 500; display: block; margin-bottom: .35rem; }
table { width: 100%; border-collapse: collapse; }
td, th { padding: .6rem .75rem; text-align: left; vertical-align: top;
         border-bottom: 1px solid var(--rule); }
th { font-size: .7rem; text-transform: uppercase; letter-spacing: .08em;
     color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: none; }
.facts td:first-child { color: var(--muted); width: 34%; }
.sev { font-weight: 600; font-size: .78rem; text-transform: uppercase;
       letter-spacing: .04em; white-space: nowrap; }
.cid { font-family: ui-monospace, "SF Mono", Consolas, monospace;
       font-size: .82rem; color: var(--muted); white-space: nowrap; }
.tally { display: flex; gap: 2rem; flex-wrap: wrap; }
.tally div { min-width: 5rem; }
.tally b { font-family: Georgia, serif; font-size: 1.9rem; font-weight: 500;
           display: block; line-height: 1.1; }
.tally span { font-size: .72rem; text-transform: uppercase;
              letter-spacing: .08em; color: var(--muted); }
.note { color: var(--muted); font-size: .85rem; }
footer { margin-top: 3.5rem; padding-top: 1.25rem; border-top: 1px solid var(--rule);
         color: var(--muted); font-size: .82rem; }
.flag { background: var(--gold-soft); border: 1px solid var(--gold);
        border-radius: 3px; padding: .75rem 1rem; margin-bottom: 2rem;
        font-size: .88rem; }
"""


def as_html(scan: Scan, cycle: Cycle | None = None, redact: bool = True) -> str:
    from .sense.scanner import posture

    e = html.escape
    verdict, detail = posture(scan)
    counts = scan.counts()

    facts = "".join(
        f"<tr><td>{e(f.key)}</td><td>{e((f.redacted() if redact and f.sensitive else f).value)}</td></tr>"
        for f in scan.facts
    )

    findings = "".join(
        f'<tr><td class="sev" style="color:{SEVERITY_COLOUR[f.severity]}">'
        f"{e(f.severity.value)}</td>"
        f'<td class="cid">{e(f.control_id)}</td>'
        f"<td>{e(f.observed or f.title)}</td></tr>"
        for f in scan.by_severity()
    ) or '<tr><td colspan="3" class="note">No findings.</td></tr>'

    tally = "".join(
        f'<div><b style="color:{SEVERITY_COLOUR[s]}">{counts[s]}</b>'
        f"<span>{e(s.value)}</span></div>"
        for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    )

    actions_section = ""
    if cycle and cycle.outcomes:
        rows = "".join(
            f"<tr><td>{e(STATUS_WORD.get(o.status, o.status.value))}</td>"
            f'<td class="cid">{e(o.control_id)}</td>'
            f"<td>{e(' '.join(o.message.split()))}</td></tr>"
            for o in cycle.outcomes
        )
        halted = (f'<p class="note">Halted: {e(cycle.halted)}</p>' if cycle.halted else "")
        actions_section = (
            "<h2>What Lares did</h2>"
            f'<div class="card"><table><tr><th>Outcome</th><th>Control</th>'
            f"<th>Detail</th></tr>{rows}</table></div>{halted}"
        )

    demo = ('<div class="flag">Demo mode. This report describes synthetic data; '
            "nothing on a real machine was examined or changed.</div>"
            if scan.demo else "")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{NAME} report</title><style>{_CSS}</style></head>
<body><div class="wrap">
<h1>{NAME}</h1>
<p class="sub">Hardening report &middot; {e(scan.started_at)}</p>
{demo}
<div class="card verdict"><strong>{e(verdict)}</strong>{e(detail)}</div>

<h2>Findings</h2>
<div class="card"><div class="tally">{tally}</div></div>
<div class="card" style="margin-top:.75rem"><table>
<tr><th>Severity</th><th>Control</th><th>What was found</th></tr>
{findings}</table></div>

{actions_section}

<h2>Machine</h2>
<div class="card"><table class="facts">{facts}</table></div>

<footer>
Generated by {NAME} {VERSION}. This report covers the {len(scan.findings)} open
finding(s) among the controls Lares checks. A clean result means those particular
checks passed &mdash; it is not a statement that the machine is secure.
{'Identifying details are redacted.' if redact else ''}
</footer>
</div></body></html>"""
