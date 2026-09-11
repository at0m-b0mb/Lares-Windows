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
from typing import Any

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
    ) -> Reply:
        """One chat completion.

        When *schema* is supplied, llama.cpp compiles it into a grammar and the
        sampler is constrained to tokens that keep the output valid against it.
        On a 1.5B model this is the difference between usable and useless: it
        removes the entire class of failure where the model writes a fine plan
        wrapped in prose, or forgets a closing brace four hundred tokens in.
        """
        if not self.load():
            return Reply("", ok=False, error=self.status)

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

        started = time.monotonic()
        try:
            result = self._llama.create_chat_completion(**kwargs)
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            if schema is not None:
                # Older llama-cpp-python builds reject a schema in response_format.
                # Retrying unconstrained is much better than failing the cycle;
                # the parser downstream is written to cope with loose output.
                return self.ask(system, user, max_tokens=max_tokens, schema=None,
                                temperature=temperature)
            return Reply("", ok=False, error=message[:300],
                         seconds=time.monotonic() - started)

        elapsed = time.monotonic() - started
        try:
            text = result["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return Reply("", ok=False, error="model returned an unexpected shape",
                         seconds=elapsed)

        used = 0
        usage = result.get("usage") if isinstance(result, dict) else None
        if isinstance(usage, dict):
            used = int(usage.get("completion_tokens", 0) or 0)

        return Reply(text.strip(), ok=True, tokens=used, seconds=elapsed)


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
    return None


def strip_fence(text: str) -> str:
    """Return the body of a fenced code block, or the text unchanged."""
    match = _FENCE.search(text)
    return match.group(1).strip() if match else text.strip()
