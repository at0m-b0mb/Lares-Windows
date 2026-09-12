"""The embedded language model.

llama.cpp through llama-cpp-python, running a quantised GGUF entirely on the CPU.
No network, no API key, no telemetry - the model is a file on disk and inference
happens in this process. That is a requirement rather than a preference: a
security tool that ships a machine's configuration to somebody else's server to
decide what to do about it is not a security tool.

The single most important property of this module is that **it is allowed to be
absent**. llama-cpp-python may not be installed, the model may not have been
downloaded yet, the machine may be too small to load it, or inference may simply
fail. In every one of those cases ``available`` is False and the caller falls
back to the built-in planner. Lares never stops working because the model is not
there; it just stops being able to explain itself as well.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .models import Choice, ModelSpec, choose

#: Generation caps. A planning answer is a few hundred tokens; anything longer
#: means the model has started rambling and the extra minutes are wasted.
PLAN_TOKENS = 1024
EXPERT_TOKENS = 1400

#: Low but non-zero. Zero makes small models repeat themselves when a plan has
#: several similar actions in it.
TEMPERATURE = 0.2


@dataclass
class Reply:
    text: str
    ok: bool = True
    error: str = ""
    tokens: int = 0
    seconds: float = 0.0

    @property
    def tps(self) -> float:
        return self.tokens / self.seconds if self.seconds > 0 else 0.0


@dataclass
class Watch:
    """Somewhere to send an exchange while it is still happening.

    Every exchange is already written to the transcript, but only once it is
    over, and on the hardware this targets "over" is two or three minutes
    later. For that whole time a spinner is indistinguishable from a hang, and
    someone who wants to see the application talk to the model is instead
    watching a dot move.

    Attaching one of these to the Engine changes nothing about the answer. The
    same text is produced; it is assembled here, a token at a time, instead of
    inside llama.cpp. Because the Engine is the single object the planner, the
    consultation and the agent all share, attaching it in one place makes every
    exchange visible without a flag threaded through five call sites.

    Every callback is display. None of them may change the outcome, and a
    callback that raises is discarded rather than allowed to lose a reply that
    took minutes to produce - a console that cannot encode a character is not
    a reason to throw away the answer.
    """

    #: The system prompt and the user message, before generation starts.
    on_prompt: Callable[[str, str], None] | None = None
    #: One fragment of the reply, as it is produced. Usually one token.
    on_token: Callable[[str], None] | None = None
    #: The finished Reply, successful or not.
    on_reply: Callable[["Reply"], None] | None = None


class _Shape(Exception):
    """The backend returned something this code does not understand."""


def _safely(call: Callable[..., Any], *args: Any) -> None:
    """Run a watcher callback, absorbing anything it does.

    Deliberately silent. The alternative - logging every failed write - turns
    one broken console into thousands of log lines, one per token.
    """
    try:
        call(*args)
    except Exception:  # noqa: BLE001 - display must never break generation
        pass


class Engine:
    """A lazily-loaded local model."""

    def __init__(self, spec: ModelSpec | None = None, threads: int = 0,
                 verbose: bool = False) -> None:
        self.spec = spec
        self.threads = threads
        self.verbose = verbose
        self._llama: Any = None
        self._lock = threading.Lock()
        self._load_error = ""
        #: Set to a Watch to have exchanges reported as they happen.
        self.watch: Watch | None = None

    # -- construction ---------------------------------------------------

    @classmethod
    def autoselect(cls, prefer: str = "", verbose: bool = False) -> tuple["Engine", Choice]:
        """Build an engine for whatever this machine can run."""
        decision = choose(prefer=prefer)
        engine = cls(decision.spec, threads=decision.hardware.threads, verbose=verbose)
        return engine, decision

    # -- state ----------------------------------------------------------

    @property
    def model_path(self) -> Path | None:
        return self.spec.path if self.spec else None

    @property
    def name(self) -> str:
        return self.spec.name if self.spec else "built-in planner"

    @property
    def available(self) -> bool:
        """True when a real model could serve a request right now."""
        if self.spec is None or not self.spec.path.exists():
            return False
        if self._llama is not None:
            return True
        return _backend_present()

    @property
    def status(self) -> str:
        if self.spec is None:
            return "no model selected; using the built-in planner"
        if not self.spec.path.exists():
            return f"{self.spec.name} is not downloaded yet"
        if not _backend_present():
            detail = backend_error()
            if getattr(sys, "frozen", False) and detail:
                # In a packaged build the library is supposed to be inside the
                # executable, so "not installed" is misleading - it is there and
                # it would not load. Say which.
                return f"the bundled model backend would not load ({detail})"
            return "llama-cpp-python is not installed; using the built-in planner"
        if self._load_error:
            return f"{self.spec.name} failed to load: {self._load_error}"
        if self._llama is None:
            return f"{self.spec.name} is ready to load"
        return f"{self.spec.name} is loaded"

    # -- loading --------------------------------------------------------

    def load(self) -> bool:
        """Load the model into memory. Safe to call repeatedly.

        Loading a 3B model from a spinning disk takes several seconds, so it
        happens once and is held. Callers that only want to know whether a model
        could work should read ``available`` instead of calling this.
        """
        if self._llama is not None:
            return True
        if self.spec is None or not self.spec.path.exists():
            return False

        with self._lock:
            if self._llama is not None:
                return True
            try:
                from llama_cpp import Llama
            except ImportError as exc:
                self._load_error = f"llama-cpp-python not installed ({exc})"
                return False
            try:
                self._llama = Llama(
                    model_path=str(self.spec.path),
                    n_ctx=self.spec.context,
                    n_threads=self.threads or None,
                    n_gpu_layers=0,      # CPU only, by design
                    use_mmap=True,       # lets the OS page the weights in
                    use_mlock=False,     # never pin; these machines are short on RAM
                    verbose=self.verbose,
                    logits_all=False,
                )
            except Exception as exc:  # noqa: BLE001 - any load failure is non-fatal
                self._load_error = str(exc)[:300]
                self._llama = None
                return False
        return True

    def unload(self) -> None:
        """Release the weights. The tray agent does this between cycles."""
        with self._lock:
            self._llama = None

    # -- inference ------------------------------------------------------

    def ask(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = PLAN_TOKENS,
        schema: dict[str, Any] | None = None,
        temperature: float = TEMPERATURE,
        _echoed: bool = False,
    ) -> Reply:
        """One chat completion.

        When *schema* is supplied, llama.cpp compiles it into a grammar and the
        sampler is constrained to tokens that keep the output valid against it.
        On a 1.5B model this is the difference between usable and useless: it
        removes the entire class of failure where the model writes a fine plan
        wrapped in prose, or forgets a closing brace four hundred tokens in.

        With a Watch attached the reply is streamed instead of awaited, and
        each fragment is handed over as it appears. The result is the same
        object either way, so nothing downstream can tell which path ran.

        *_echoed* is private: a schema the backend rejects is retried without
        one, and the prompt must not be reported to the watcher twice for what
        is one exchange from every other point of view.
        """
        if not self.load():
            return Reply("", ok=False, error=self.status)

        watch = self.watch
        if watch is not None and watch.on_prompt is not None and not _echoed:
            _safely(watch.on_prompt, system, user)

        kwargs: dict[str, Any] = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": 0.9,
            "repeat_penalty": 1.05,
        }
        if schema is not None:
            kwargs["response_format"] = {"type": "json_object", "schema": schema}

        live = watch is not None and watch.on_token is not None
        started = time.monotonic()
        try:
            if live:
                text, used = self._streamed(kwargs, watch.on_token)  # type: ignore[arg-type]
            else:
                text, used = self._whole(kwargs)
        except _Shape:
            return self._told(watch, Reply(
                "", ok=False, error="model returned an unexpected shape",
                seconds=time.monotonic() - started))
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            if schema is not None:
                # Older llama-cpp-python builds reject a schema in response_format.
                # Retrying unconstrained is much better than failing the cycle;
                # the parser downstream is written to cope with loose output.
                return self.ask(system, user, max_tokens=max_tokens, schema=None,
                                temperature=temperature, _echoed=True)
            return self._told(watch, Reply(
                "", ok=False, error=message[:300],
                seconds=time.monotonic() - started))

        return self._told(watch, Reply(
            text.strip(), ok=True, tokens=used,
            seconds=time.monotonic() - started))

    def _whole(self, kwargs: dict[str, Any]) -> tuple[str, int]:
        """Generate, and wait for all of it."""
        result = self._llama.create_chat_completion(**kwargs)
        try:
            text = result["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise _Shape() from exc

        used = 0
        usage = result.get("usage") if isinstance(result, dict) else None
        if isinstance(usage, dict):
            used = int(usage.get("completion_tokens", 0) or 0)
        return text, used

    def _streamed(self, kwargs: dict[str, Any],
                  on_token: Callable[[str], None]) -> tuple[str, int]:
        """Generate, handing over each fragment as it arrives.

        The token count is the number of content fragments rather than a usage
        figure, because llama.cpp reports no usage on a streamed completion.
        One fragment is one token, so the tokens-per-second this yields is the
        real rate and not an estimate presented as one.

        Chunks that carry no text - the opening role chunk, the closing finish
        chunk - are skipped rather than treated as a malformed response, which
        is why a shape that is merely uninteresting does not raise here.
        """
        parts: list[str] = []
        for chunk in self._llama.create_chat_completion(**dict(kwargs, stream=True)):
            try:
                delta = chunk["choices"][0]["delta"].get("content")
            except (KeyError, IndexError, TypeError, AttributeError):
                continue
            if not delta:
                continue
            parts.append(delta)
            _safely(on_token, delta)
        return "".join(parts), len(parts)

    @staticmethod
    def _told(watch: Watch | None, reply: Reply) -> Reply:
        """Report the finished exchange, then hand it back unchanged."""
        if watch is not None and watch.on_reply is not None:
            _safely(watch.on_reply, reply)
        return reply


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

#: Why the backend could not be imported, kept so it can be reported instead
#: of swallowed. Computed once: a failed import is not cheap and the answer
#: does not change within a process.
_BACKEND_ERROR: str | None = None
_BACKEND_CHECKED = False


def _prepare_frozen_library() -> None:
    """Point llama_cpp at its native library inside a PyInstaller bundle.

    llama_cpp finds its DLL relative to its own __file__, which works in a
    normal install and is fragile in a onefile build where the package is
    unpacked into a temporary directory. It honours an environment variable
    naming the directory, so when the bundled library is findable we set that
    before the import rather than hoping the relative path resolves.

    The variable has been spelled two ways across releases, so both are set.
    """
    base = getattr(sys, "_MEIPASS", "")
    if not base:
        return

    root = Path(base)
    for candidate in (root / "llama_cpp" / "lib", root / "llama_cpp", root):
        if not candidate.is_dir():
            continue
        if any(candidate.glob("*llama*.dll")) or any(candidate.glob("*llama*.so")):
            for name in ("LLAMA_CPP_LIB_PATH", "LLAMA_CPP_LIB"):
                os.environ.setdefault(name, str(candidate))
            return


def backend_error() -> str:
    """The reason the model backend is unusable, or an empty string."""
    _backend_present()
    return _BACKEND_ERROR or ""


def _backend_present() -> bool:
    """Whether llama_cpp can actually be imported - not merely located.

    This deliberately performs the real import. Checking that the module
    *exists* is a different question from whether it *loads*: the package is
    pure Python wrapping a native library, so a bundle that carries the Python
    half without the DLL passes any find_spec check and then fails here. That
    exact split had `doctor` reporting the backend as installed while the same
    executable's planner reported it missing.
    """
    global _BACKEND_ERROR, _BACKEND_CHECKED
    if _BACKEND_CHECKED:
        return _BACKEND_ERROR is None

    _BACKEND_CHECKED = True
    _prepare_frozen_library()
    try:
        import llama_cpp  # noqa: F401
    except Exception as exc:  # noqa: BLE001 - a broken install is the same as no install
        _BACKEND_ERROR = f"{type(exc).__name__}: {exc}"[:300]
        return False
    _BACKEND_ERROR = None
    return True


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> dict[str, Any] | None:
    """Pull a JSON object out of whatever the model actually said.

    With a schema-constrained grammar the text is already clean. Without one -
    an older llama-cpp-python, or the Expert lane - small models routinely wrap
    the answer in a markdown fence or add a sentence of preamble. Rather than
    failing the cycle over punctuation, we try progressively looser reads.
    """
    if not text:
        return None

    candidates: list[str] = [text.strip()]

    fenced = _FENCE.search(text)
    if fenced:
        candidates.insert(0, fenced.group(1).strip())

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start:end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed

    # Last resort: the reply may simply have run out of room. A small model
    # asked for several hundred tokens of JSON hits the cap mid-sentence often
    # enough that treating it as unusable throws away work that was finished.
    repaired = repair_json(text)
    if repaired is not None:
        try:
            parsed = json.loads(repaired)
        except ValueError:
            return None
        # An empty object is refused here even though it parses. A model that
        # genuinely meant "{}" would have produced valid JSON and been read
        # above; reaching this line means the reply was cut short, and a reply
        # cut short before anything completed must not come back as a
        # confident empty answer - which downstream reads as "nothing is
        # wrong with this machine".
        if isinstance(parsed, dict) and parsed:
            return parsed
    return None


def repair_json(text: str) -> str | None:
    """Close a JSON object that stopped in the middle, discarding the last bit.

    This exists because of what actually happens on the hardware this targets.
    A 1.5B model asked for a plan with several rationales in it reaches the
    token cap partway through a sentence, and the result is a document that is
    correct up to the cut and unparseable because of it. Refusing the whole
    reply loses four finished items to recover none.

    The repair is deliberately conservative: rather than guessing at how to
    finish the fragment, it rewinds to the last point where the document was
    structurally complete - the end of a finished value, or a separator after
    one - drops everything after that, and closes the containers that were
    still open there. Whatever the model had actually finished saying survives;
    the half-written item is gone rather than invented.

    Returns None when there is nothing recoverable.
    """
    start = text.find("{")
    if start == -1:
        return None
    body = text[start:]

    stack: list[str] = []
    in_string = False
    escaped = False
    #: Where to cut, and the closers owed at that point. Seeded empty so a
    #: reply that was truncated before anything completed yields nothing
    #: rather than "{}", which would read as a confident empty answer.
    cut: int | None = None
    owed: list[str] = []

    def mark(index: int) -> None:
        nonlocal cut, owed
        cut, owed = index, list(stack)

    for index, char in enumerate(body):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "{[":
            stack.append("}" if char == "{" else "]")
            mark(index + 1)          # an empty container is already valid
        elif char in "}]":
            if not stack:
                break                # more closers than openers: give up here
            stack.pop()
            mark(index + 1)
        elif char == ",":
            mark(index)              # everything before the comma is complete

    if cut is None:
        return None

    head = body[:cut].rstrip().rstrip(",")
    if not head:
        return None
    return head + "".join(reversed(owed))


def strip_fence(text: str) -> str:
    """Return the body of a fenced code block, or the text unchanged."""
    match = _FENCE.search(text)
    return match.group(1).strip() if match else text.strip()
