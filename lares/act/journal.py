"""The append-only record of everything Lares has done.

An autonomous tool that changes system settings while nobody is watching earns
trust in exactly one way: by being able to tell you afterwards what it did, when,
why, and how to put it back. That is this module.

The journal is a JSON-lines file. Append-only, one entry per action attempt,
including the ones that were refused and the ones that failed - a record that
only contains successes is not a record. Each entry carries the fully rendered
rollback script, so an action can be undone months later without the model, the
catalogue, or the original finding still being available.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ..core import Outcome, Status, utcnow
from ..winsys import state_dir

#: Roll the file over past this size so a long-running agent cannot fill a disk.
MAX_BYTES = 8 * 1024 * 1024
KEEP_ROTATIONS = 5


@dataclass
class Entry:
    """One journalled action, as read back from disk."""

    outcome: Outcome
    cycle_id: str = ""
    control_title: str = ""
    rationale: str = ""
    model: str = ""
    host: str = ""
    at: str = field(default_factory=utcnow)

    @property
    def undoable(self) -> bool:
        """True when this entry left a change in place that we could still undo."""
        return (
            self.outcome.status in (Status.VERIFIED, Status.UNVERIFIED)
            and bool(self.outcome.rollback_script.strip())
        )


class Journal:
    """Reads and writes the action log."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (state_dir("journal") / "actions.jsonl")

    # -- writing --------------------------------------------------------

    def record(
        self,
        outcome: Outcome,
        *,
        cycle_id: str = "",
        control_title: str = "",
        rationale: str = "",
        model: str = "",
        host: str = "",
    ) -> None:
        payload = {
            "at": utcnow(),
            "cycle_id": cycle_id,
            "control_title": control_title,
            "rationale": rationale,
            "model": model,
            "host": host,
            "outcome": outcome.as_dict(),
        }
        self._rotate_if_needed()
        line = json.dumps(payload, ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _rotate_if_needed(self) -> None:
        try:
            if not self.path.exists() or self.path.stat().st_size < MAX_BYTES:
                return
        except OSError:
            return
        for index in range(KEEP_ROTATIONS - 1, 0, -1):
            older = self.path.with_suffix(f".{index}.jsonl")
            newer = self.path.with_suffix(f".{index + 1}.jsonl")
            if older.exists():
                older.replace(newer)
        self.path.replace(self.path.with_suffix(".1.jsonl"))

    # -- reading --------------------------------------------------------

    def __iter__(self) -> Iterator[Entry]:
        if not self.path.exists():
            return iter(())
        return self._read()

    def _read(self) -> Iterator[Entry]:
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    raw = payload["outcome"]
                except (ValueError, KeyError, TypeError):
                    # A torn final line from an interrupted write is expected
                    # and is not a reason to lose the rest of the history.
                    continue
                try:
                    status = Status(raw.get("status", "failed"))
                except ValueError:
                    status = Status.FAILED
                outcome = Outcome(
                    control_id=raw.get("control_id", ""),
                    status=status,
                    params=raw.get("params", {}) or {},
                    message=raw.get("message", ""),
                    refusal_reason=raw.get("refusal_reason", ""),
                    output=raw.get("output", ""),
                    snapshot_id=raw.get("snapshot_id", ""),
                    rollback_script=raw.get("rollback_script", ""),
                    before=raw.get("before", ""),
                    after=raw.get("after", ""),
                    duration_ms=int(raw.get("duration_ms", 0) or 0),
                    at=raw.get("at", ""),
                    action_id=raw.get("action_id", ""),
                )
                yield Entry(
                    outcome=outcome,
                    cycle_id=payload.get("cycle_id", ""),
                    control_title=payload.get("control_title", ""),
                    rationale=payload.get("rationale", ""),
                    model=payload.get("model", ""),
                    host=payload.get("host", ""),
                    at=payload.get("at", ""),
                )

    def recent(self, limit: int = 50) -> list[Entry]:
        entries = list(self)
        return entries[-limit:][::-1]

    def find(self, action_id: str) -> Entry | None:
        for entry in self:
            if entry.outcome.action_id == action_id:
                return entry
        return None

    def undoable(self, limit: int = 100) -> list[Entry]:
        """Changes still in place, newest first.

        A control that was applied and then undone later shows up twice; only
        the most recent entry for a given control and parameter set matters, so
        earlier ones are filtered out.
        """
        seen: set[str] = set()
        out: list[Entry] = []
        for entry in reversed(list(self)):
            key = f"{entry.outcome.control_id}:{sorted(entry.outcome.params.items())}"
            if key in seen:
                continue
            seen.add(key)
            if entry.undoable:
                out.append(entry)
            if len(out) >= limit:
                break
        return out

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Status}
        for entry in self:
            counts[entry.outcome.status.value] = counts.get(entry.outcome.status.value, 0) + 1
        return counts
