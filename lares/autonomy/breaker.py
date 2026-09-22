"""Knowing when to stop.

An autonomous loop that keeps trying is the failure mode that turns a helpful
tool into a destructive one. If a change gets rolled back, something about this
machine does not match what the catalogue expected, and the correct response is
to try the rest - and then, if it keeps happening, to stop changing things
altogether and keep reporting.

The rule is deliberately blunt and easy to reason about: count consecutive bad
cycles, halt at the threshold, and require a person to say go again. A bad cycle
is one where something was rolled back or a remediation failed outright. A cycle
that simply found nothing to do is neither good nor bad and leaves the count
alone, so a machine that is already clean never drifts towards a trip.

State is on disk, because the halt has to survive the agent restarting - and an
agent that has just wedged something is exactly the one likely to be restarted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..core import Cycle, Status, utcnow
from .. import logs
from ..winsys import data_dir, read_json, write_json_atomic


@dataclass
class State:
    consecutive_bad: int = 0
    tripped: bool = False
    tripped_at: str = ""
    reason: str = ""
    #: Recent cycles, newest last, as {at, open, fixed, reverted, failed,
    #: verdict}. Structured rather than prose because the desktop application
    #: draws the machine's history from it - the backlog coming down over time
    #: is the clearest evidence that the agent is doing its job.
    cycles: list[dict] = field(default_factory=list)
    #: Human-readable notes that are not cycles: halts, resets.
    history: list[str] = field(default_factory=list)
    last_cycle_at: str = ""
    total_cycles: int = 0
    total_fixed: int = 0
    total_rolled_back: int = 0


def _path() -> Path:
    return data_dir() / "breaker.json"


def load() -> State:
    raw = read_json(_path())
    if not isinstance(raw, dict):
        return State()
    try:
        return State(**{k: v for k, v in raw.items() if k in State.__dataclass_fields__})
    except TypeError:
        return State()


def save(state: State) -> bool:
    """Persist the breaker atomically. Returns whether it stuck.

    This one matters more than the other state files. Every loader here treats
    an unparseable file as "use the defaults", and the default for `tripped` is
    False - so a breaker.json torn by a power cut would silently re-arm
    autonomy on the machine that had just halted itself. An atomic replace
    means a reader sees the old state or the new one, never a fragment.

    The return value used to be discarded, which made a disk that refused the
    write into a breaker that came back armed: this process believed it had
    halted, and the next one read a file that said otherwise. A breaker is
    only worth having if it fails closed.
    """
    return write_json_atomic(_path(), asdict(state))


class Breaker:
    """Consecutive-failure circuit breaker for the autonomous loop."""

    def __init__(self, threshold: int = 2, state: State | None = None) -> None:
        self.threshold = max(1, threshold)
        self.state = state if state is not None else load()

    # -- reading --------------------------------------------------------

    @property
    def open(self) -> bool:
        """True when autonomy is halted and only reporting should happen."""
        return self.state.tripped

    def explain(self) -> str:
        if not self.state.tripped:
            remaining = self.threshold - self.state.consecutive_bad
            return f"armed; {remaining} more bad cycle(s) would halt changes"
        return (
            f"halted since {self.state.tripped_at}: {self.state.reason} "
            "Lares is still scanning and reporting, but will not change anything "
            "until it is reset."
        )

    # -- writing --------------------------------------------------------

    def record(self, cycle: Cycle) -> None:
        """Judge one completed cycle and update the breaker."""
        rolled_back = len(cycle.reverted)
        failed = sum(1 for o in cycle.outcomes if o.status is Status.FAILED)
        fixed = len(cycle.fixed)

        self.state.total_cycles += 1
        self.state.total_fixed += fixed
        self.state.total_rolled_back += rolled_back
        self.state.last_cycle_at = utcnow()

        if rolled_back or failed:
            verdict = f"bad ({rolled_back} rolled back, {failed} failed)"
            self.state.consecutive_bad += 1
            if self.state.consecutive_bad >= self.threshold and not self.state.tripped:
                self.state.tripped = True
                self.state.tripped_at = utcnow()
                self.state.reason = (
                    f"{self.state.consecutive_bad} cycles in a row ended with a change "
                    "being undone or failing, which means this machine does not behave "
                    "the way the catalogue expects."
                )
        elif fixed:
            verdict = f"good ({fixed} fixed)"
            self.state.consecutive_bad = 0
        else:
            # Nothing attempted. Not evidence either way, so the count stands.
            verdict = "quiet"

        self.state.cycles.append({
            "at": utcnow(),
            "open": len(cycle.scan.findings),
            "fixed": fixed,
            "reverted": rolled_back,
            "failed": failed,
            "verdict": verdict.split()[0],
        })
        self.state.cycles = self.state.cycles[-40:]
        save(self.state)

    def reset(self, note: str = "reset by the operator") -> None:
        self.state.tripped = False
        self.state.consecutive_bad = 0
        self.state.tripped_at = ""
        self.state.reason = ""
        self.state.history.append(f"{utcnow()} {note}")
        self.state.history = self.state.history[-20:]
        save(self.state)

    def trip(self, reason: str) -> None:
        """Halt autonomy immediately, for a reason outside the cycle count.

        A trip is monotonic. The file is re-read first and a trip already
        recorded by another process is kept, because writing this whole object
        over the top of it is last-writer-wins - and the loser of that race,
        on a machine where two copies of Lares are running, is a machine that
        halted itself and then carried on.
        """
        self.state.tripped = True
        self.state.tripped_at = utcnow()
        self.state.reason = reason
        self.state.history.append(f"{utcnow()} halted: {reason}")
        self.state.history = self.state.history[-20:]

        on_disk = load()
        if on_disk.tripped and on_disk.tripped_at:
            # Keep whichever trip came first, and both explanations.
            self.state.tripped_at = min(self.state.tripped_at, on_disk.tripped_at)
            if on_disk.reason and on_disk.reason != reason:
                self.state.reason = f"{on_disk.reason}; {reason}"
        self.state.consecutive_bad = max(self.state.consecutive_bad,
                                         on_disk.consecutive_bad)

        if not save(self.state):
            # In memory this process is halted, and it will stay halted. The
            # next process will not know, so say so where someone will see it
            # rather than leaving a silent fail-open.
            logs.get().error(
                "system", "The circuit breaker tripped but could not be written",
                exc=OSError(f"could not write {_path()}"),
                reason=reason)
