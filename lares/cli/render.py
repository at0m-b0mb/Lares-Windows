"""Terminal output.

Deliberately quiet. No boxes around everything, no emoji, no progress bar that
redraws four times a second on a machine that is already struggling. One accent
colour - a dim gold, the same accent the desktop application uses - and the rest
carried by spacing and alignment.

rich is used when present and is not required. On a bare Python install the same
calls fall through to plain ``print``, because a machine with nothing installed is
exactly the machine that most needs hardening.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
from typing import Any, Iterator

try:
    from rich.console import Console as RichConsole
    from rich.text import Text
    _RICH = True
except ImportError:  # pragma: no cover - exercised on bare installs
    _RICH = False

#: The house accent: a deep brass that stays readable on both light and dark
#: terminals. Bright gold is unreadable on a white background.
GOLD = "#B8860B"
DIM = "grey50"

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": DIM,
    "info": DIM,
}

STATUS_STYLE = {
    "verified": "green",
    "unverified": "yellow",
    "simulated": "cyan",
    "skipped": DIM,
    "refused": DIM,
    "rolled_back": "yellow",
    "failed": "bold red",
}

#: Words, not symbols. A screen reader reads these; a glyph it does not.
STATUS_WORD = {
    "verified": "fixed",
    "unverified": "applied",
    "simulated": "would fix",
    "skipped": "skipped",
    "refused": "refused",
    "rolled_back": "undone",
    "failed": "failed",
}


class Console:
    """Terminal writer with a rich path and a plain path."""

    def __init__(self, plain: bool = False) -> None:
        self.plain = plain or not _RICH or not sys.stdout.isatty()
        self._rich = RichConsole(highlight=False, soft_wrap=False) if _RICH and not plain else None
        self.width = shutil.get_terminal_size((88, 24)).columns

    # -- primitives -----------------------------------------------------

    def _write(self, text: str, style: str = "") -> None:
        if self._rich and style:
            self._rich.print(Text(text, style=style))
        elif self._rich:
            self._rich.print(Text(text))
        else:
            print(text)

    def blank(self) -> None:
        print()

    def rule(self, title: str) -> None:
        line = "-" * max(0, min(self.width, 78) - len(title) - 1)
        self._write(f"{title} {line}", GOLD)

    def section(self, title: str) -> None:
        self._write(title.upper(), f"bold {GOLD}")

    def field(self, label: str, value: str) -> None:
        self._write(f"  {label:<22} {value}")

    def paragraph(self, text: str) -> None:
        body = " ".join(text.split())
        width = min(self.width, 78) - 2
        line = ""
        for word in body.split():
            if len(line) + len(word) + 1 > width:
                self._write("  " + line)
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            self._write("  " + line)

    def bullet(self, text: str) -> None:
        self._write(f"  - {text}")

    def detail(self, text: str) -> None:
        self._write(f"      {' '.join(text.split())[:150]}", DIM)

    def advice(self, text: str, indent: int = 6) -> None:
        """Wrapped, indented prose. For guidance that will not fit on one line.

        ``detail`` truncates on purpose, because it sits under findings where a
        long tail would bury the list. Remedies are the opposite case: the whole
        point is the sentence that says what to do, so it wraps instead.
        """
        pad = " " * indent
        width = min(self.width, 78) - indent
        for block in text.split("\n"):
            block = block.strip()
            if not block:
                continue
            # A line that is already laid out - an indented command, say - is
            # passed through rather than reflowed into a paragraph.
            if block.startswith(("pip ", "lares ", "python ", "  ")):
                self._write(pad + block, DIM)
                continue
            line = ""
            for word in block.split():
                if len(line) + len(word) + 1 > width:
                    self._write(pad + line, DIM)
                    line = word
                else:
                    line = f"{line} {word}".strip()
            if line:
                self._write(pad + line, DIM)

    def dim(self, text: str) -> None:
        self._write(f"  {text}", DIM)

    def ok(self, text: str) -> None:
        self._write(f"  {text}", "green")

    def warn(self, text: str) -> None:
        self._write(f"  {text}", "yellow")

    def error(self, text: str) -> None:
        self._write(f"  {text}", "bold red")

    # -- domain-specific ------------------------------------------------

    def verdict(self, headline: str, detail: str) -> None:
        self._write(f"  {headline}", f"bold {GOLD}")
        self.paragraph(detail)

    def finding(self, severity: str, control_id: str, text: str, fixable: str) -> None:
        style = SEVERITY_STYLE.get(severity, "")
        label = f"  {severity:<9}"
        rest = f"{control_id:<9} {text}"
        if self._rich:
            line = Text(label, style=style)
            line.append(rest)
            line.append(f"  [{fixable}]", style=DIM)
            self._rich.print(line)
        else:
            print(f"{label}{rest}  [{fixable}]")

    def outcome(self, status: str, control_id: str, message: str, when: str = "") -> None:
        word = STATUS_WORD.get(status, status)
        style = STATUS_STYLE.get(status, "")
        stamp = f"{when[:19].replace('T', ' ')}  " if when else ""
        if self._rich:
            line = Text(f"  {stamp}", style=DIM)
            line.append(f"{word:<10}", style=style)
            line.append(f"{control_id:<9} ")
            line.append(" ".join(message.split())[:200], style=DIM)
            self._rich.print(line)
        else:
            print(f"  {stamp}{word:<10}{control_id:<9} {' '.join(message.split())[:200]}")

    def step(self, order: int, control_id: str, title: str, rationale: str,
             risk: str = "") -> None:
        head = f"  {order:>2}. {control_id}  {title}"
        if self._rich:
            line = Text(f"  {order:>2}. ", style=DIM)
            line.append(control_id, style=f"bold {GOLD}")
            line.append(f"  {title}")
            if risk:
                line.append(f"  ({risk})", style=DIM)
            self._rich.print(line)
        else:
            print(head + (f"  ({risk})" if risk else ""))
        if rationale:
            self.detail(rationale)

    def event(self, message: str, detail: str = "") -> None:
        self._write(f"  {message}", DIM)
        if detail:
            self.detail(detail)

    def progress(self, message: str, done: int, total: int) -> None:
        if self.plain or not sys.stdout.isatty():
            return
        width = 24
        filled = int(width * done / total) if total else 0
        bar = "#" * filled + "." * (width - filled)
        sys.stdout.write(f"\r  [{bar}] {message[:44]:<44}")
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\r" + " " * (width + 52) + "\r")
            sys.stdout.flush()

    def model_row(self, key: str, name: str, state: str, speed: str, marker: str) -> None:
        if self._rich:
            line = Text(f"  {key:<6}", style=f"bold {GOLD}" if marker else "")
            line.append(f"{name:<42}")
            line.append(f"{state:<18}", style=DIM)
            line.append(speed, style=DIM)
            if marker:
                line.append(f"  <- {marker}", style=GOLD)
            self._rich.print(line)
        else:
            suffix = f"  <- {marker}" if marker else ""
            print(f"  {key:<6}{name:<42}{state:<18}{speed}{suffix}")

    def control_row(self, cid: str, severity: str, risk: str, how: str, title: str) -> None:
        if self._rich:
            line = Text(f"  {cid:<9}")
            line.append(f"{severity:<9}", style=SEVERITY_STYLE.get(severity, ""))
            line.append(f"{risk:<10}{how:<14}", style=DIM)
            line.append(title[:40])
            self._rich.print(line)
        else:
            print(f"  {cid:<9}{severity:<9}{risk:<10}{how:<14}{title[:40]}")

    def control_detail(self, control: Any) -> None:
        self.blank()
        self.section(f"{control.id} - {control.title}")
        self.field("Domain", control.domain)
        self.field("Severity", control.severity.value)
        self.field("Risk of the fix", control.risk.value)
        self.field("Takes effect", control.effective)
        self.field("Can be undone", "yes" if control.is_reversible else "no")
        self.field("Runs unattended", "yes" if control.autonomy_eligible else "no")
        self.blank()
        self.section("Why it matters")
        self.paragraph(control.rationale)
        if control.blast_radius:
            self.blank()
            self.section("What it costs")
            self.paragraph(control.blast_radius)
        if control.params:
            self.blank()
            self.section("Parameters")
            for spec in control.params:
                self.bullet(f"{spec.name} ({spec.type}): {spec.description}")
        if control.references:
            self.blank()
            self.section("References")
            for ref in control.references:
                self.bullet(ref)
        self.blank()
        self.section("Detection")
        self.script(control.detect)
        if control.remediate:
            self.blank()
            self.section("Remediation")
            self.script(control.remediate)
        if control.rollback:
            self.blank()
            self.section("Rollback")
            self.script(control.rollback)

    def script(self, text: str) -> None:
        for line in text.rstrip().splitlines():
            self._write(f"    {line}", DIM)

    # -- status spinner -------------------------------------------------

    @contextlib.contextmanager
    def status(self, message: str) -> Iterator[Any]:
        """Show a transient status line, yielding a callable to update it."""
        if self.plain or not sys.stdout.isatty():
            yield lambda text="": None
            return

        state = {"text": message}

        def update(text: str = "") -> None:
            if text:
                state["text"] = text
            sys.stdout.write(f"\r  {state['text'][:70]:<72}")
            sys.stdout.flush()

        update()
        try:
            yield update
        finally:
            sys.stdout.write("\r" + " " * 74 + "\r")
            sys.stdout.flush()
