"""What this machine looked like last time, so that what changed can be seen.

A hardening tool that fixes something once and never looks again is half a
tool. Machines drift: an installer re-enables a protocol, someone turns the
firewall off for an afternoon and forgets, a service appears, an account is
promoted. None of that is caught by running the same thirty checks and getting
the same thirty answers, because the answers are about the controls - not about
what else showed up.

So every reading of the attack surface is kept, and any two can be compared.
The comparison is deliberately dumb: no severity, no opinion, no alerting
thresholds. "Port 4444 is listening now and was not before" is a fact, and
facts are what this file produces. Whether it matters is the model's problem,
or a person's.

Identity is per-section and is the interesting part. Two readings of "the same"
port are the same row when protocol, port and address match; two readings of
the same installed product are the same row when the name matches, and a
different *version* is a change rather than a removal and an addition. Getting
that wrong turns every Windows update into forty spurious findings, which is
how a change report becomes something people stop reading.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import logs
from ..winsys import state_dir, write_json_atomic
from .surface import Section, Surface

#: Readings to keep. Enough to answer "when did this appear" over a few weeks
#: of daily cycles without turning the state directory into an archive.
KEEP = 30

#: How a row is identified within its section, and what counts as its value.
#: A row whose key matches and whose value differs is a change; a key that is
#: new or gone is an addition or a removal.
IDENTITY: dict[str, tuple[Callable[[dict], str], Callable[[dict], str]]] = {
    "ports": (
        lambda r: f"{r.get('proto')}/{r.get('port')} on {r.get('address')}",
        lambda r: f"{r.get('process') or 'unknown process'}",
    ),
    "software": (
        lambda r: str(r.get("name", "")),
        lambda r: str(r.get("version", "") or "unknown version"),
    ),
    "services": (
        lambda r: str(r.get("name", "")),
        lambda r: f"{r.get('start')} as {r.get('account')} - {r.get('path')}",
    ),
    "accounts": (
        lambda r: str(r.get("name", "")),
        lambda r: ("enabled" if r.get("enabled") else "disabled")
                  + (", administrator" if r.get("admin") else ""),
    ),
    "exposure": (
        lambda r: str(r.get("setting", "")),
        lambda r: str(r.get("value", "")),
    ),
    "system": (
        lambda r: str(r.get("item", "")),
        lambda r: str(r.get("value", "")),
    ),
}


@dataclass
class Change:
    """One difference between two readings of the same view."""

    section: str
    kind: str          # "appeared" | "gone" | "changed"
    subject: str
    before: str = ""
    after: str = ""

    def describe(self) -> str:
        if self.kind == "appeared":
            return f"{self.subject} appeared ({self.after})" if self.after else \
                   f"{self.subject} appeared"
        if self.kind == "gone":
            return f"{self.subject} is gone"
        return f"{self.subject}: {self.before} -> {self.after}"


@dataclass
class Comparison:
    """Everything that differs between two readings."""

    before_at: str = ""
    after_at: str = ""
    changes: list[Change] = field(default_factory=list)
    #: Sections that could not be compared, and why. A view that failed to read
    #: in either pass is not a view where nothing changed.
    skipped: dict[str, str] = field(default_factory=dict)

    @property
    def quiet(self) -> bool:
        return not self.changes

    def by_section(self) -> dict[str, list[Change]]:
        out: dict[str, list[Change]] = {}
        for change in self.changes:
            out.setdefault(change.section, []).append(change)
        return out


def directory() -> Path:
    return state_dir("baselines")


def _rows(section: Section | None) -> dict[str, str] | None:
    """A view as {identity: value}, or None when it cannot be compared."""
    if section is None or not section.ok:
        return None
    key_of, value_of = IDENTITY.get(section.key, (None, None))
    if key_of is None:
        return None
    out: dict[str, str] = {}
    for row in section.rows:
        try:
            key = key_of(row)
        except Exception:  # noqa: BLE001 - a malformed row is not a crash
            continue
        if key:
            out[key] = value_of(row)
    return out


def compare(before: Surface, after: Surface) -> Comparison:
    """What changed between two readings."""
    result = Comparison(before_at=before.at, after_at=after.at)
    keys = [k for k in IDENTITY if before.get(k) or after.get(k)]

    for key in keys:
        old = _rows(before.get(key))
        new = _rows(after.get(key))
        if old is None or new is None:
            # Saying nothing changed because one side was unreadable is the
            # worst answer available here: it is silence that looks like an
            # all-clear.
            which = "the earlier" if old is None else "this"
            result.skipped[key] = f"{which} reading could not be compared"
            continue

        for subject in sorted(set(new) - set(old)):
            result.changes.append(Change(key, "appeared", subject, after=new[subject]))
        for subject in sorted(set(old) - set(new)):
            result.changes.append(Change(key, "gone", subject, before=old[subject]))
        for subject in sorted(set(old) & set(new)):
            if old[subject] != new[subject]:
                result.changes.append(
                    Change(key, "changed", subject, before=old[subject], after=new[subject]))

    return result


def save(surface: Surface) -> Path | None:
    """Keep this reading, and drop the oldest once there are too many."""
    if surface.demo:
        # Writing synthetic readings into the real history would make every
        # later comparison against them a fiction.
        return None

    payload = {
        "at": surface.at,
        "duration_ms": surface.duration_ms,
        "sections": [
            {"key": s.key, "title": s.title, "error": s.error, "note": s.note,
             "rows": s.rows}
            for s in surface.sections
        ],
    }
    # The filename carries the timestamp so the directory sorts chronologically
    # without opening anything, and a colon is not a filename character on
    # Windows.
    stamp = surface.at.replace(":", "").replace("-", "").replace(".", "")[:15]
    path = directory() / f"surface-{stamp}.json"
    if not write_json_atomic(path, payload):
        return None

    _prune()
    logs.get().info("scan", "Recorded a reading of the attack surface",
                    path=str(path), sections=len(surface.sections))
    return path


#: How stale the newest reading may get before a cycle takes another. A cycle
#: runs every four hours by default and the six collectors are not free, so
#: surveying on every one would add a fifth to the cost of a pass to answer a
#: question nobody asks that often.
MAX_AGE_HOURS = 12


def _age_hours(stamp: str) -> float | None:
    """How old a reading is, or None when its timestamp cannot be read."""
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds() / 3600


def due(max_age_hours: float = MAX_AGE_HOURS) -> bool:
    """Whether a fresh reading is worth taking.

    An unreadable timestamp counts as due. The alternative - treating a
    reading whose date cannot be parsed as recent - means one corrupt file
    stops the history ever growing again, silently.
    """
    newest = latest()
    if newest is None:
        return True
    age = _age_hours(newest.at)
    return age is None or age >= max_age_hours


def _prune() -> None:
    try:
        kept = sorted(directory().glob("surface-*.json"))
    except OSError:
        return
    for path in kept[:-KEEP]:
        try:
            path.unlink()
        except OSError:
            continue


def _load(path: Path) -> Surface | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None

    surface = Surface(at=str(raw.get("at", "")),
                      duration_ms=int(raw.get("duration_ms", 0) or 0))
    for entry in raw.get("sections") or []:
        if not isinstance(entry, dict):
            continue
        surface.sections.append(Section(
            key=str(entry.get("key", "")),
            title=str(entry.get("title", "")),
            rows=[r for r in (entry.get("rows") or []) if isinstance(r, dict)],
            error=str(entry.get("error", "") or ""),
            note=str(entry.get("note", "") or ""),
        ))
    return surface


def history() -> list[Path]:
    """Every kept reading, oldest first."""
    try:
        return sorted(directory().glob("surface-*.json"))
    except OSError:
        return []


def latest(before: Path | None = None) -> Surface | None:
    """The most recent readable reading, optionally excluding one file."""
    for path in reversed(history()):
        if before is not None and path == before:
            continue
        surface = _load(path)
        if surface is not None and surface.sections:
            return surface
    return None


def summarise(comparison: Comparison) -> str:
    """One line for a log or a listener."""
    if comparison.skipped and comparison.quiet:
        return "nothing comparable changed; some views could not be compared"
    if comparison.quiet:
        return "nothing changed"
    kinds: dict[str, int] = {}
    for change in comparison.changes:
        kinds[change.kind] = kinds.get(change.kind, 0) + 1
    parts = [f"{n} {kind}" for kind, n in sorted(kinds.items())]
    return ", ".join(parts)
