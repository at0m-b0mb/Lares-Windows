"""Settings, with defaults chosen for a machine nobody is watching.

Stored as JSON next to the journal so both applications - the terminal one and
the desktop one - read and write the same configuration and cannot disagree
about what the agent is allowed to do.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from .core import RiskTier
from .winsys import data_dir, read_json, write_json_atomic


@dataclass
class Settings:
    # -- what it may do -------------------------------------------------
    #: Highest risk tier applied without a person present. "intrusive" is
    #: accepted but deliberately not the default: those are the controls that
    #: change how the machine is reached, and a health check cannot tell the
    #: difference between "the remote operator is fine" and "the remote operator
    #: is locked out and cannot tell us".
    ceiling: str = "caution"
    #: Changes per cycle. A cap means a bad scan cannot rewrite the machine in
    #: one pass, and it spreads a large backlog over several cycles with a
    #: verification between each.
    budget: int = 8
    #: Never change anything; scan, plan and report only.
    dry_run: bool = False
    #: Restrict to these catalogue domains. Empty means all of them.
    domains: list[str] = field(default_factory=list)
    #: Control ids Lares must never touch on this machine.
    excluded: list[str] = field(default_factory=list)

    # -- when it runs ---------------------------------------------------
    interval_minutes: int = 240
    #: Run a cycle as soon as the agent starts, rather than waiting an interval.
    scan_on_start: bool = True
    start_on_boot: bool = True

    # -- the model ------------------------------------------------------
    #: "" selects automatically from measured hardware. Otherwise a ladder key.
    model_tier: str = ""
    #: Release the model weights between cycles. Costs a reload each time and
    #: saves a couple of gigabytes of resident memory in between, which is the
    #: right trade on the hardware this targets.
    unload_between_cycles: bool = True

    # -- stopping -------------------------------------------------------
    #: Consecutive bad cycles before autonomy halts and Lares reports only.
    breaker_threshold: int = 2

    # -- presentation ---------------------------------------------------
    #: "light", "dark" or "auto". The choice is stored, never the resolved value.
    theme: str = "auto"

    # -- derived --------------------------------------------------------

    @property
    def risk_ceiling(self) -> RiskTier:
        try:
            return RiskTier(self.ceiling.lower())
        except ValueError:
            return RiskTier.CAUTION

    def validate(self) -> list[str]:
        """Clamp anything out of range, returning what was corrected."""
        fixed: list[str] = []
        if self.ceiling.lower() not in {t.value for t in RiskTier}:
            fixed.append(f"ceiling {self.ceiling!r} is not a risk tier; using 'caution'")
            self.ceiling = "caution"
        if not 1 <= self.budget <= 40:
            fixed.append(f"budget {self.budget} out of range; using 8")
            self.budget = 8
        if not 5 <= self.interval_minutes <= 10080:
            fixed.append(f"interval {self.interval_minutes} out of range; using 240")
            self.interval_minutes = 240
        if not 1 <= self.breaker_threshold <= 10:
            fixed.append(f"breaker threshold {self.breaker_threshold} out of range; using 2")
            self.breaker_threshold = 2
        if self.theme not in ("light", "dark", "auto"):
            fixed.append(f"theme {self.theme!r} unknown; using 'auto'")
            self.theme = "auto"
        return fixed


def path() -> Path:
    return data_dir() / "settings.json"


def load() -> Settings:
    """Read settings, falling back to defaults for anything missing or broken."""
    raw = read_json(path())
    if not isinstance(raw, dict):
        return Settings()

    known = {f.name for f in fields(Settings)}
    settings = Settings(**{k: v for k, v in raw.items() if k in known})
    settings.validate()
    return settings


def save(settings: Settings) -> bool:
    """Persist settings atomically.

    Returns whether it stuck. A half-written settings file parses as broken and
    falls back to defaults, which would quietly discard an excluded-control list
    and start applying controls the operator had turned off.
    """
    settings.validate()
    return write_json_atomic(path(), asdict(settings))


def describe(settings: Settings) -> list[tuple[str, str]]:
    """Settings as label/value pairs, for the about screens."""
    return [
        ("Autonomy ceiling", settings.ceiling),
        ("Changes per cycle", str(settings.budget)),
        ("Interval", f"every {settings.interval_minutes} minutes"),
        ("Mode", "report only (dry run)" if settings.dry_run else "apply fixes"),
        ("Domains", ", ".join(settings.domains) if settings.domains else "all"),
        ("Excluded controls", ", ".join(settings.excluded) or "none"),
        ("Model", settings.model_tier or "chosen from hardware"),
        ("Start with Windows", "yes" if settings.start_on_boot else "no"),
        ("Halt after", f"{settings.breaker_threshold} consecutive bad cycles"),
    ]
