"""Did the things Lares fixed stay fixed?

The journal says what was changed and when. It does not say whether the change
is still there, and on a real machine that is a different question with a
different answer. An installer re-enables a protocol. A group policy refresh
overwrites a registry value at three in the morning. Somebody turns the
firewall off to make a printer work and never turns it back on.

None of that shows up in a scan summary, because a scan reports the machine's
state and not its history - a control that Lares fixed in March and that came
undone in April simply reads as "open" again, indistinguishable from one that
was never touched. The difference matters. A control that has never been fixed
is work. A control that was fixed and has come undone is either something on
this machine actively fighting the change, or a change that never held in the
first place, and both are worth knowing before it is applied for the fourth
time.

So this reads the journal, takes every control Lares believes it left in place,
and re-runs that control's own detection probe - the same probe that found the
problem and the same one that verified the fix. Nothing here decides anything.
It reports three states and refuses to guess between them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .. import logs
from ..act.execute import read_probe
from ..act.journal import Entry, Journal
from ..catalog.loader import Catalog
from ..core import Status, utcnow

#: States a previously-applied control can be in now.
HELD = "held"
UNDONE = "undone"
UNKNOWN = "unknown"
GONE = "gone"

#: Journal statuses that mean "we left a change on this machine". UNVERIFIED is
#: included deliberately: the change was applied and nothing proved it worked,
#: so whether it is still in place is exactly the open question.
APPLIED = (Status.VERIFIED, Status.UNVERIFIED)

Progress = Callable[[str, int, int], None]


@dataclass
class Drifted:
    """One control Lares applied, and what became of it."""

    control_id: str
    title: str
    state: str
    applied_at: str
    action_id: str = ""
    detail: str = ""
    #: How many times the journal shows this control being applied. Repeated
    #: entries for one control are the strongest signal available here: it did
    #: not hold the last three times either.
    applications: int = 1

    @property
    def repeated(self) -> bool:
        return self.applications > 1


@dataclass
class Report:
    """Every control with a history, and where it stands now."""

    checked: list[Drifted] = field(default_factory=list)
    at: str = field(default_factory=utcnow)
    duration_ms: int = 0

    def of(self, state: str) -> list[Drifted]:
        return [d for d in self.checked if d.state == state]

    @property
    def undone(self) -> list[Drifted]:
        return self.of(UNDONE)

    def headline(self) -> tuple[str, str]:
        """A verdict and a supporting sentence."""
        undone = len(self.undone)
        unknown = len(self.of(UNKNOWN)) + len(self.of(GONE))
        if not self.checked:
            return ("Nothing to check",
                    "Lares has not applied anything to this machine yet.")
        if undone:
            repeated = sum(1 for d in self.undone if d.repeated)
            tail = (f" {repeated} of them had come undone before."
                    if repeated else "")
            return (f"{undone} change(s) have come undone",
                    f"Lares applied these and they are no longer in place.{tail}")
        if unknown:
            return ("Held, as far as could be checked",
                    f"{unknown} could not be re-checked and are not counted either way.")
        return ("Everything held",
                f"All {len(self.checked)} changes Lares made are still in place.")


def applied_controls(journal: Journal, limit: int = 2000) -> dict[str, list[Entry]]:
    """Every control the journal shows being applied, newest entry first."""
    out: dict[str, list[Entry]] = {}
    for entry in journal.recent(limit=limit):
        if entry.outcome.status not in APPLIED:
            continue
        out.setdefault(entry.outcome.control_id, []).append(entry)
    return out


def check(catalog: Catalog, journal: Journal | None = None, *,
          only: list[str] | None = None,
          progress: Progress | None = None) -> Report:
    """Re-run the probe for every control Lares has applied."""
    started = time.monotonic()
    report = Report()
    history = applied_controls(journal or Journal())

    wanted = {c.strip().upper() for c in only} if only else None
    ids = sorted(k for k in history if wanted is None or k in wanted)

    for index, control_id in enumerate(ids, start=1):
        entries = history[control_id]
        newest = entries[0]
        if progress:
            progress(control_id, index, len(ids))

        control = catalog.get(control_id)
        if control is None:
            # The control was applied by a version of Lares whose catalogue had
            # it and this one does not. The change is still on the machine and
            # there is no probe left to ask about it, which is worth saying
            # rather than quietly dropping.
            report.checked.append(Drifted(
                control_id=control_id,
                title=newest.control_title or control_id,
                state=GONE, applied_at=newest.at,
                action_id=newest.outcome.action_id,
                applications=len(entries),
                detail="no longer in the catalogue, so it cannot be re-checked"))
            continue

        reading = read_probe(control)
        if not reading.usable:
            state, detail = UNKNOWN, reading.error or "the probe could not run"
        elif reading.compliant:
            state, detail = HELD, reading.observed or "still in the desired state"
        else:
            state, detail = UNDONE, reading.observed or "no longer compliant"

        report.checked.append(Drifted(
            control_id=control_id, title=control.title, state=state,
            applied_at=newest.at, action_id=newest.outcome.action_id,
            applications=len(entries), detail=detail))

    report.duration_ms = int((time.monotonic() - started) * 1000)
    logs.get().info("scan", "Checked whether applied changes held",
                    checked=len(report.checked), undone=len(report.undone))
    return report
