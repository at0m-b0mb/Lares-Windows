"""What Lares writes down about itself.

There are three records, kept apart on purpose because they answer three
different questions.

``journal``      What was *changed* on this machine, and how to undo it.
                 Lives in ``act/journal.py``; it is the legal record and it is
                 never mixed with diagnostics.

``lares.log``    What *happened*, in order. The running narrative: cycles
                 starting, probes failing, the breaker tripping. Plain text for
                 reading, with a JSON-lines twin for machine consumption.

``transcript``   What was *said to the model and what it said back* - and,
                 crucially, what Lares then did with the answer. See
                 :class:`Transcript`.

Every error additionally gets its own numbered file under ``errors/`` holding
the full traceback and the state around it. The short id of that file is what
gets shown in the interface, so a user who sees "failed (LR-4f2a91)" can find
the whole story on disk instead of a truncated toast message.

Nothing in this module may raise. A tool that crashes because it could not
write a log entry is worse than one that quietly loses the entry, so every
write is wrapped and failures degrade to a best-effort stderr note.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from .winsys import state_dir

#: Roll over past this size, keeping a handful of generations.
MAX_BYTES = 4 * 1024 * 1024
KEEP_ROTATIONS = 4

#: Transcripts are much larger per entry, so they get their own budget.
TRANSCRIPT_MAX_BYTES = 16 * 1024 * 1024


class Level(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"

    @property
    def rank(self) -> int:
        return {Level.DEBUG: 0, Level.INFO: 1, Level.WARN: 2, Level.ERROR: 3}[self]


def _stamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _local_stamp() -> str:
    """Human-facing time. The text log is read by people, in their own zone."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


#: Monotonic within this process, and part of every error report filename.
#: Timestamps alone are not enough to order two reports written moments apart:
#: Windows' system clock granularity is coarse enough that two calls inside one
#: test return the *same* microsecond value, and the ordering then falls back to
#: the random hex in the id - which listed the older report first. A counter
#: does not depend on how fine the platform's clock happens to be.
_error_sequence = 0
_sequence_lock = threading.Lock()


def _file_stamp() -> str:
    """Sortable stamp plus a sequence number, for error report filenames."""
    global _error_sequence
    with _sequence_lock:
        _error_sequence += 1
        sequence = _error_sequence
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    return f"{stamp}-{sequence:06d}"


def _ensure_dir(path: Path) -> None:
    """Best-effort mkdir. A log that cannot be created must not raise."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass


def new_error_id() -> str:
    """Short, sayable, greppable. Shown in the interface, found on disk."""
    return "LR-" + uuid.uuid4().hex[:6].upper()


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass
class Record:
    """One line of the running narrative, as read back from disk."""

    at: str
    level: Level
    area: str
    message: str
    fields: dict[str, Any] = field(default_factory=dict)
    error_id: str = ""

    @property
    def local_time(self) -> str:
        """The timestamp rendered for display, falling back to the raw value."""
        try:
            parsed = datetime.fromisoformat(self.at.replace("Z", "+00:00"))
        except ValueError:
            return self.at
        return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    def one_line(self) -> str:
        suffix = f"  [{self.error_id}]" if self.error_id else ""
        return f"{self.local_time}  {self.level.value.upper():5}  {self.area:7}  {self.message}{suffix}"


@dataclass
class ErrorReport:
    """The full story of one failure, written to its own file."""

    error_id: str
    at: str
    area: str
    message: str
    exception_type: str = ""
    exception_text: str = ""
    traceback_text: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    #: Platform detail, captured at failure time rather than reconstructed later.
    environment: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "error_id": self.error_id,
            "at": self.at,
            "area": self.area,
            "message": self.message,
            "exception_type": self.exception_type,
            "exception_text": self.exception_text,
            "traceback": self.traceback_text,
            "context": self.context,
            "environment": self.environment,
        }

    def summary(self) -> str:
        head = f"{self.error_id}  {self.area}: {self.message}"
        if self.exception_type:
            head += f"\n  {self.exception_type}: {self.exception_text}"
        return head


# --------------------------------------------------------------------------
# The log
# --------------------------------------------------------------------------

class Log:
    """The running narrative plus per-error files.

    One instance is shared process-wide (see :func:`get`), and it is used from
    the GUI thread, the agent worker thread and the scheduler, so every write
    takes a lock. The lock is held only for the duration of a file append,
    which is short enough not to matter and simple enough to be obviously
    correct.
    """

    def __init__(self, directory: Path | None = None, *, level: Level = Level.INFO,
                 echo: bool = False) -> None:
        self.dir = directory or state_dir("logs")
        # state_dir creates its own, but an explicitly supplied directory - a
        # frozen build's fresh LOCALAPPDATA, a test, a --log-dir - may not exist
        # yet, and every write would then fail silently.
        _ensure_dir(self.dir)
        self.text_path = self.dir / "lares.log"
        self.json_path = self.dir / "lares.jsonl"
        self.errors_dir = self.dir / "errors"
        self.level = level
        #: Mirror to stderr. The terminal application turns this on with -v.
        self.echo = echo
        self._lock = threading.Lock()
        self._listeners: list[Any] = []

    # -- listeners ------------------------------------------------------

    def subscribe(self, callback) -> None:
        """Call *callback* with each new Record. Used by the desktop log page."""
        self._listeners.append(callback)

    def unsubscribe(self, callback) -> None:
        if callback in self._listeners:
            self._listeners.remove(callback)

    def _notify(self, record: Record) -> None:
        for callback in list(self._listeners):
            try:
                callback(record)
            except Exception:  # noqa: BLE001 - a broken view must not break logging
                pass

    # -- writing --------------------------------------------------------

    def write(self, level: Level, area: str, message: str, *,
              error_id: str = "", **fields: Any) -> Record:
        record = Record(_stamp(), level, area, message, dict(fields), error_id)
        if level.rank < self.level.rank:
            return record
        self._append(record)
        self._notify(record)
        if self.echo:
            print(record.one_line(), file=sys.stderr, flush=True)
        return record

    def debug(self, area: str, message: str, **fields: Any) -> Record:
        return self.write(Level.DEBUG, area, message, **fields)

    def info(self, area: str, message: str, **fields: Any) -> Record:
        return self.write(Level.INFO, area, message, **fields)

    def warn(self, area: str, message: str, **fields: Any) -> Record:
        return self.write(Level.WARN, area, message, **fields)

    def error(self, area: str, message: str, *, exc: BaseException | None = None,
              **context: Any) -> ErrorReport:
        """Record a failure and write a full report file for it.

        Returns the :class:`ErrorReport` so the caller can put ``report.error_id``
        in whatever it shows the user. That id is the whole point: it turns "it
        failed" into something a person can look up.
        """
        report = ErrorReport(
            error_id=new_error_id(),
            at=_stamp(),
            area=area,
            message=message,
            context=_safe_fields(context),
            environment=_environment(),
        )
        if exc is not None:
            report.exception_type = type(exc).__name__
            report.exception_text = str(exc)[:2000]
            report.traceback_text = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            )[:20000]

        self._write_error_file(report)
        self.write(
            Level.ERROR, area, message,
            error_id=report.error_id,
            exception=report.exception_type,
            detail=report.exception_text[:200],
        )
        return report

    def exception(self, area: str, message: str, **context: Any) -> ErrorReport:
        """Record the exception currently being handled."""
        return self.error(area, message, exc=sys.exc_info()[1], **context)

    # -- files ----------------------------------------------------------

    def _append(self, record: Record) -> None:
        payload = {
            "at": record.at,
            "level": record.level.value,
            "area": record.area,
            "message": record.message,
            **({"error_id": record.error_id} if record.error_id else {}),
            **({"fields": _safe_fields(record.fields)} if record.fields else {}),
        }
        with self._lock:
            try:
                _rotate(self.text_path, MAX_BYTES, KEEP_ROTATIONS)
                _rotate(self.json_path, MAX_BYTES, KEEP_ROTATIONS)
                with self.text_path.open("a", encoding="utf-8") as fh:
                    fh.write(record.one_line() + "\n")
                with self.json_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
            except OSError as exc:
                # Losing a log line is survivable; crashing over it is not.
                print(f"lares: could not write log ({exc})", file=sys.stderr)

    def _write_error_file(self, report: ErrorReport) -> None:
        try:
            self.errors_dir.mkdir(parents=True, exist_ok=True)
            # The filename has to sort chronologically, because listing errors
            # newest-first is done by sorting the directory. A date alone ties
            # for every error on the same day and then orders them by random
            # hex, so the stamp carries microseconds.
            path = self.errors_dir / f"{_file_stamp()}-{report.error_id}.json"
            path.write_text(
                json.dumps(report.as_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            _prune(self.errors_dir, keep=200)
        except OSError as exc:
            print(f"lares: could not write error report ({exc})", file=sys.stderr)

    # -- reading --------------------------------------------------------

    def tail(self, limit: int = 200, *, level: Level | None = None,
             area: str = "") -> list[Record]:
        """The most recent records, newest last, optionally filtered."""
        out: list[Record] = []
        if not self.json_path.exists():
            return out
        try:
            with self.json_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except ValueError:
                        continue  # a torn line from an interrupted write
                    try:
                        rec_level = Level(payload.get("level", "info"))
                    except ValueError:
                        rec_level = Level.INFO
                    if level is not None and rec_level.rank < level.rank:
                        continue
                    if area and payload.get("area") != area:
                        continue
                    out.append(Record(
                        at=payload.get("at", ""),
                        level=rec_level,
                        area=payload.get("area", ""),
                        message=payload.get("message", ""),
                        fields=payload.get("fields", {}) or {},
                        error_id=payload.get("error_id", ""),
                    ))
        except OSError:
            return out
        return out[-limit:]

    def errors(self, limit: int = 50) -> list[ErrorReport]:
        """Recent error reports, newest first."""
        if not self.errors_dir.is_dir():
            return []
        out: list[ErrorReport] = []
        try:
            paths = sorted(self.errors_dir.glob("*.json"), reverse=True)[:limit]
        except OSError:
            return []
        for path in paths:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            out.append(ErrorReport(
                error_id=raw.get("error_id", path.stem),
                at=raw.get("at", ""),
                area=raw.get("area", ""),
                message=raw.get("message", ""),
                exception_type=raw.get("exception_type", ""),
                exception_text=raw.get("exception_text", ""),
                traceback_text=raw.get("traceback", ""),
                context=raw.get("context", {}) or {},
                environment=raw.get("environment", {}) or {},
            ))
        return out

    def find_error(self, error_id: str) -> ErrorReport | None:
        for report in self.errors(limit=500):
            if report.error_id.upper() == error_id.upper():
                return report
        return None


# --------------------------------------------------------------------------
# The model transcript
# --------------------------------------------------------------------------

@dataclass
class Exchange:
    """One conversation turn with the model, and its consequences.

    The last three fields are what make this worth keeping. Anyone can log a
    prompt and a completion; what matters in a tool that acts on the answer is
    whether the answer was *used*. An exchange where the model proposed six
    actions and the guard refused five of them is the single most informative
    record this application produces, and it only exists if the outcome is
    written down beside the reply.
    """

    at: str = ""
    #: "plan" | "expert" | "explain" - which lane asked.
    purpose: str = "plan"
    model: str = ""
    system: str = ""
    prompt: str = ""
    reply: str = ""
    ok: bool = True
    error: str = ""
    tokens: int = 0
    seconds: float = 0.0
    #: What Lares understood the reply to mean.
    parsed: dict[str, Any] = field(default_factory=dict)
    #: What was accepted, and what was thrown away and why.
    accepted: list[str] = field(default_factory=list)
    rejected: dict[str, str] = field(default_factory=dict)
    cycle_id: str = ""
    exchange_id: str = ""

    @property
    def tps(self) -> float:
        return self.tokens / self.seconds if self.seconds > 0 else 0.0

    def headline(self) -> str:
        if not self.ok:
            return f"{self.purpose}: failed - {self.error}"
        bits = [f"{len(self.accepted)} accepted"]
        if self.rejected:
            bits.append(f"{len(self.rejected)} rejected")
        if self.tokens:
            bits.append(f"{self.tokens} tokens in {self.seconds:.1f}s")
        return f"{self.purpose}: " + ", ".join(bits)


class Transcript:
    """The append-only record of every exchange with the model.

    Kept separate from the narrative log because the two have completely
    different shapes and lifetimes: a narrative line is forty characters and you
    want thousands of them, an exchange is several kilobytes of prompt and you
    want the last few hundred.
    """

    def __init__(self, path: Path | None = None, *, enabled: bool = True,
                 keep_prompts: bool = True) -> None:
        self.path = path or (state_dir("logs") / "transcript.jsonl")
        _ensure_dir(self.path.parent)
        self.enabled = enabled
        #: When False, the prompt and reply bodies are replaced by their lengths.
        #: The metadata - timing, what was accepted, what was refused - is kept,
        #: because that is the part that matters for auditing behaviour.
        self.keep_prompts = keep_prompts
        self._lock = threading.Lock()

    def record(self, exchange: Exchange) -> Exchange:
        if not exchange.at:
            exchange.at = _stamp()
        if not exchange.exchange_id:
            exchange.exchange_id = "ex-" + uuid.uuid4().hex[:10]
        if not self.enabled:
            return exchange

        payload: dict[str, Any] = {
            "at": exchange.at,
            "exchange_id": exchange.exchange_id,
            "cycle_id": exchange.cycle_id,
            "purpose": exchange.purpose,
            "model": exchange.model,
            "ok": exchange.ok,
            "error": exchange.error,
            "tokens": exchange.tokens,
            "seconds": round(exchange.seconds, 3),
            "tokens_per_second": round(exchange.tps, 2),
            "parsed": _safe_fields(exchange.parsed),
            "accepted": exchange.accepted,
            "rejected": exchange.rejected,
        }
        if self.keep_prompts:
            payload["system"] = exchange.system
            payload["prompt"] = exchange.prompt
            payload["reply"] = exchange.reply
        else:
            payload["system_chars"] = len(exchange.system)
            payload["prompt_chars"] = len(exchange.prompt)
            payload["reply_chars"] = len(exchange.reply)

        with self._lock:
            try:
                _rotate(self.path, TRANSCRIPT_MAX_BYTES, 2)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
            except OSError as exc:
                print(f"lares: could not write transcript ({exc})", file=sys.stderr)
        return exchange

    # -- reading --------------------------------------------------------

    def __iter__(self) -> Iterator[Exchange]:
        if not self.path.exists():
            return iter(())
        return self._read()

    def _read(self) -> Iterator[Exchange]:
        try:
            handle = self.path.open("r", encoding="utf-8")
        except OSError:
            return
        with handle as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                yield Exchange(
                    at=raw.get("at", ""),
                    purpose=raw.get("purpose", "plan"),
                    model=raw.get("model", ""),
                    system=raw.get("system", ""),
                    prompt=raw.get("prompt", ""),
                    reply=raw.get("reply", ""),
                    ok=bool(raw.get("ok", True)),
                    error=raw.get("error", ""),
                    tokens=int(raw.get("tokens", 0) or 0),
                    seconds=float(raw.get("seconds", 0.0) or 0.0),
                    parsed=raw.get("parsed", {}) or {},
                    accepted=raw.get("accepted", []) or [],
                    rejected=raw.get("rejected", {}) or {},
                    cycle_id=raw.get("cycle_id", ""),
                    exchange_id=raw.get("exchange_id", ""),
                )

    def recent(self, limit: int = 25) -> list[Exchange]:
        return list(self)[-limit:][::-1]

    def find(self, exchange_id: str) -> Exchange | None:
        for exchange in self:
            if exchange.exchange_id == exchange_id:
                return exchange
        return None

    def as_markdown(self, limit: int = 20) -> str:
        """Render recent exchanges as a readable document.

        The JSON lines are for machines. This is what you send someone when you
        want them to see how the model is actually behaving on your hardware.
        """
        lines = ["# Lares model transcript", ""]
        entries = self.recent(limit)
        if not entries:
            lines.append("_No exchanges recorded yet._")
            return "\n".join(lines)

        for exchange in entries:
            lines.append(f"## {exchange.at} - {exchange.purpose}")
            lines.append("")
            lines.append(f"- Model: {exchange.model or 'unknown'}")
            lines.append(f"- Result: {exchange.headline()}")
            if exchange.cycle_id:
                lines.append(f"- Cycle: `{exchange.cycle_id}`")
            if exchange.rejected:
                lines.append("- Refused by the guard:")
                for cid, why in exchange.rejected.items():
                    lines.append(f"  - `{cid}` - {why}")
            lines.append("")
            if exchange.prompt:
                lines.append("**Asked**")
                lines.append("")
                lines.append("```text")
                lines.append(exchange.prompt.strip()[:4000])
                lines.append("```")
                lines.append("")
            if exchange.reply:
                lines.append("**Answered**")
                lines.append("")
                lines.append("```json")
                lines.append(exchange.reply.strip()[:4000])
                lines.append("```")
                lines.append("")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Shared instances
# --------------------------------------------------------------------------

_log: Log | None = None
_transcript: Transcript | None = None
_setup_lock = threading.Lock()


def get() -> Log:
    """The process-wide log."""
    global _log
    if _log is None:
        with _setup_lock:
            if _log is None:
                _log = Log()
    return _log


def transcript() -> Transcript:
    """The process-wide model transcript."""
    global _transcript
    if _transcript is None:
        with _setup_lock:
            if _transcript is None:
                _transcript = Transcript()
    return _transcript


def configure(*, level: Level = Level.INFO, echo: bool = False,
              directory: Path | None = None, keep_prompts: bool = True,
              transcript_enabled: bool = True) -> Log:
    """Set up logging for this process. Called once at start-up."""
    global _log, _transcript
    with _setup_lock:
        _log = Log(directory, level=level, echo=echo)
        _transcript = Transcript(
            (directory / "transcript.jsonl") if directory else None,
            enabled=transcript_enabled,
            keep_prompts=keep_prompts,
        )
    return _log


def record_startup(application: str) -> dict[str, str]:
    """Write a full description of this machine at the top of every run.

    When someone reports that Lares did something strange, the first six
    questions are always the same: which build, which Windows, which
    architecture, elevated or not, real hardware or a VM, and is the model
    actually loaded. Answering them from a log the user already has beats
    another round trip asking.

    This is deliberately more than :func:`_environment` collects for an error
    report - that one has to be cheap because it runs inside a failure path,
    whereas this runs once at start-up and can afford to shell out.
    """
    log = get()
    facts: dict[str, str] = dict(_environment())
    facts["application"] = application

    try:
        from .preflight import architecture, hypervisor
        arch = architecture()
        facts["architecture"] = arch.describe()
        facts["emulated"] = str(arch.emulated)
    except Exception:  # noqa: BLE001
        pass

    try:
        from .winsys import current_user, is_demo, is_elevated, os_caption
        facts["user"] = current_user()
        facts["elevated"] = str(is_elevated())
        facts["demo_mode"] = str(is_demo())
        facts["os"] = os_caption()
    except Exception:  # noqa: BLE001
        pass

    try:
        from .brain.models import measure
        hardware = measure()
        facts["hardware"] = hardware.describe()
    except Exception:  # noqa: BLE001
        pass

    try:
        from .brain import embedded
        facts["embedded_model"] = embedded.describe()
    except Exception:  # noqa: BLE001
        pass

    # The hypervisor probe shells out to PowerShell, so it is skipped unless we
    # are actually on Windows and not in demo mode - no point paying for it to
    # tell us nothing.
    try:
        from .winsys import IS_WINDOWS, is_demo as _demo
        if IS_WINDOWS and not _demo():
            name = hypervisor()
            if name:
                facts["virtual_machine"] = name
    except Exception:  # noqa: BLE001
        pass

    log.info("system", f"{application} starting", **facts)
    return facts


def install_excepthook() -> None:
    """Send otherwise-unhandled exceptions to the log before the process dies.

    Both applications call this. Without it, a crash in a Qt slot or a worker
    thread prints to a console nobody is looking at and leaves no trace on disk
    - which is exactly the situation this whole module exists to prevent.
    """
    previous = sys.excepthook

    def hook(kind, value, tb) -> None:
        try:
            get().error("system", f"Unhandled {kind.__name__}", exc=value)
        finally:
            previous(kind, value, tb)

    sys.excepthook = hook

    def thread_hook(args) -> None:
        if args.exc_value is not None:
            get().error(
                "system",
                f"Unhandled {args.exc_type.__name__} in thread {args.thread and args.thread.name}",
                exc=args.exc_value,
            )

    threading.excepthook = thread_hook


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _rotate(path: Path, max_bytes: int, keep: int) -> None:
    try:
        if not path.exists() or path.stat().st_size < max_bytes:
            return
    except OSError:
        return
    for index in range(keep - 1, 0, -1):
        older = path.with_name(f"{path.name}.{index}")
        newer = path.with_name(f"{path.name}.{index + 1}")
        if older.exists():
            try:
                older.replace(newer)
            except OSError:
                return
    try:
        path.replace(path.with_name(f"{path.name}.1"))
    except OSError:
        pass


def _prune(directory: Path, keep: int) -> None:
    """Keep the newest *keep* files in a directory, deleting the rest."""
    try:
        files = sorted(directory.glob("*.json"), reverse=True)
    except OSError:
        return
    for path in files[keep:]:
        try:
            path.unlink()
        except OSError:
            pass


def _safe_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Make arbitrary context safe to serialise.

    Log fields come from call sites all over the codebase and occasionally hold
    something that will not survive ``json.dumps``. Rendering those as their
    repr keeps the entry useful instead of losing it to a TypeError.
    """
    out: dict[str, Any] = {}
    for key, value in fields.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[str(key)] = value
        elif isinstance(value, (list, tuple)):
            out[str(key)] = [_scalar(v) for v in value][:50]
        elif isinstance(value, dict):
            out[str(key)] = {str(k): _scalar(v) for k, v in list(value.items())[:50]}
        else:
            out[str(key)] = _scalar(value)
    return out


def _scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    try:
        return str(value)[:500]
    except Exception:  # noqa: BLE001
        return "<unrepresentable>"


def _environment() -> dict[str, str]:
    """Platform detail worth having attached to every crash."""
    import platform

    from .version import VERSION

    try:
        return {
            "lares": VERSION,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "frozen": str(bool(getattr(sys, "frozen", False))),
            "pid": str(os.getpid()),
        }
    except Exception:  # noqa: BLE001
        return {}
