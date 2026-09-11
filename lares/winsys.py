"""The single place Lares talks to the operating system.

Everything that shells out goes through :func:`run` or :func:`powershell` so
that there is exactly one code path to audit, one timeout policy, and one
switch that makes the whole application safe to develop on a non-Windows box.

Design notes
------------
* **No shell.** Every invocation passes an argument list to ``subprocess`` with
  ``shell=False``. Nothing here interpolates user or model text into a command
  line; PowerShell bodies are handed over as encoded commands or script files,
  never spliced into a string that a shell will re-parse.
* **Everything times out.** A hung ``Get-WmiObject`` on a sick machine must not
  wedge an autonomous loop that is supposed to run unattended for months.
* **Demo mode is automatic off Windows** so the GUI, the reports and the
  planner can all be exercised on macOS or Linux during development.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

IS_WINDOWS = platform.system() == "Windows"

#: Default ceiling for any single external command.
DEFAULT_TIMEOUT = 45

_DEMO_OVERRIDE: bool | None = None


# --------------------------------------------------------------------------
# Mode
# --------------------------------------------------------------------------

def set_demo(enabled: bool | None) -> None:
    """Force demo mode on or off. ``None`` restores automatic detection."""
    global _DEMO_OVERRIDE
    _DEMO_OVERRIDE = enabled


def is_demo() -> bool:
    """True when Lares must synthesise data instead of reading the machine.

    Demo mode is on when explicitly requested, when ``LARES_DEMO`` is set, or
    automatically whenever we are not on Windows — there is no live data to
    read on a Mac, and silently returning empty results would make every
    report look like a clean bill of health.
    """
    if _DEMO_OVERRIDE is not None:
        return _DEMO_OVERRIDE
    if os.environ.get("LARES_DEMO", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return not IS_WINDOWS


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Result:
    """Outcome of one external command."""

    ok: bool
    stdout: str
    stderr: str
    code: int
    #: Set when the command never completed (timeout, missing binary).
    error: str = ""

    @property
    def text(self) -> str:
        return self.stdout.strip()

    def json(self, default=None):
        """Parse stdout as JSON, tolerating PowerShell's single-object output.

        ``ConvertTo-Json`` emits a bare object for one item and an array for
        many, so callers that expect a list get one either way.
        """
        raw = self.stdout.strip()
        if not raw:
            return default
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return default

    def json_list(self) -> list:
        data = self.json(default=None)
        if data is None:
            return []
        if isinstance(data, list):
            return data
        return [data]


FAILED = Result(ok=False, stdout="", stderr="", code=-1, error="not executed")


# --------------------------------------------------------------------------
# Running things
# --------------------------------------------------------------------------

def run(args: list[str], timeout: int = DEFAULT_TIMEOUT, cwd: str | None = None) -> Result:
    """Run an argument vector with no shell, capturing output.

    Never raises. A missing binary, a timeout and a non-zero exit all come
    back as a :class:`Result` with ``ok=False`` so that one sick collector can
    never take down a scan.
    """
    if not args:
        return Result(False, "", "", -1, "empty command")
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            shell=False,
            encoding="utf-8",
            errors="replace",
            creationflags=_no_window_flags(),
        )
    except FileNotFoundError:
        return Result(False, "", "", -1, f"{args[0]} not found")
    except subprocess.TimeoutExpired:
        return Result(False, "", "", -1, f"timed out after {timeout}s")
    except OSError as exc:  # pragma: no cover - platform dependent
        return Result(False, "", "", -1, str(exc))
    return Result(
        ok=proc.returncode == 0,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        code=proc.returncode,
    )


def _no_window_flags() -> int:
    """Keep console windows from flashing when the GUI shells out."""
    if IS_WINDOWS:
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return 0


def powershell_exe() -> str:
    """Prefer Windows PowerShell 5.1; fall back to pwsh 7+ if that is all there is.

    5.1 is the one guaranteed to exist on every supported Windows build and it
    carries the full set of management modules Lares depends on. pwsh is only
    used when 5.1 is genuinely absent.
    """
    if IS_WINDOWS:
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        candidate = system32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if candidate.exists():
            return str(candidate)
    found = shutil.which("powershell") or shutil.which("pwsh")
    return found or "powershell.exe"


def powershell(script: str, timeout: int = DEFAULT_TIMEOUT) -> Result:
    """Execute a PowerShell body and return its output.

    The script is passed as a base64 ``-EncodedCommand``, which sidesteps every
    quoting and escaping problem that comes from building a command line by
    string concatenation. ``-NoProfile`` keeps a user's profile from changing
    behaviour, and the execution policy is bypassed for this process only —
    it does not touch the machine's policy.
    """
    if is_demo():
        return Result(False, "", "", -1, "demo mode: powershell not executed")

    body = (
        "$ProgressPreference='SilentlyContinue';"
        "$ErrorActionPreference='Stop';"
        "$WarningPreference='SilentlyContinue';\n" + script
    )
    encoded = base64.b64encode(body.encode("utf-16-le")).decode("ascii")
    return run(
        [
            powershell_exe(),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-OutputFormat", "Text",
            "-EncodedCommand", encoded,
        ],
        timeout=timeout,
    )


def powershell_json(script: str, timeout: int = DEFAULT_TIMEOUT):
    """Run a script whose last statement pipes to ``ConvertTo-Json``.

    ``-Depth 5`` is appended only when the caller has not already piped, so a
    probe can control its own serialisation when it needs to.
    """
    body = script if "ConvertTo-Json" in script else f"{script} | ConvertTo-Json -Depth 5 -Compress"
    return powershell(body, timeout=timeout).json(default=None)


def script_file(script: str, suffix: str = ".ps1") -> Path:
    """Write a script to a private temp file and return its path.

    Used for remediation bodies, which are long enough that an encoded command
    becomes unwieldy and which we want to keep on disk for the journal.
    """
    fd, name = tempfile.mkstemp(suffix=suffix, prefix="lares-")
    with os.fdopen(fd, "w", encoding="utf-8-sig") as fh:
        fh.write(script)
    path = Path(name)
    if not IS_WINDOWS:
        path.chmod(0o600)
    return path


# --------------------------------------------------------------------------
# Privilege
# --------------------------------------------------------------------------

def is_elevated() -> bool:
    """True when this process holds an elevated (admin) token.

    Lares reports this rather than demanding it: a non-elevated run is a fully
    valid read-only mode, and saying so plainly is better than failing every
    remediation with an opaque access-denied.
    """
    if is_demo():
        return True
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover
        return False


def current_user() -> str:
    if is_demo():
        return "DESKTOP-KP7724\\kailash"
    domain = os.environ.get("USERDOMAIN", "")
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    return f"{domain}\\{user}" if domain else user


def relaunch_elevated(argv: list[str] | None = None) -> bool:
    """Ask Windows to restart this process with an elevated token.

    Returns True when the UAC request was handed off (the caller should then
    exit). Returns False on non-Windows, when already elevated, or when the
    user dismissed the prompt.
    """
    if not IS_WINDOWS or is_elevated():
        return False
    argv = argv if argv is not None else sys.argv[1:]
    params = " ".join(f'"{a}"' for a in [sys.argv[0], *argv])
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", sys.executable, params, None, 1
        )
    except Exception:
        return False
    return int(rc) > 32


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

def data_dir() -> Path:
    """Per-user directory for models, journal and configuration."""
    if IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        path = base / "Lares"
    else:
        path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "lares"
    path.mkdir(parents=True, exist_ok=True)
    return path


def state_dir(name: str) -> Path:
    path = data_dir() / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json_atomic(path: Path, payload: Any) -> bool:
    """Write JSON so that a crash can never leave a half-written state file.

    ``write_text`` truncates the file and then writes into it, so a process
    killed in between leaves valid-looking JSON that is actually a fragment -
    and every loader here falls back to defaults when parsing fails. For the
    circuit breaker that is the worst possible failure: a corrupt breaker.json
    reads as "not tripped", which silently re-arms autonomy on a machine that
    had just halted itself.

    So: write a sibling temporary file, flush it to the platter, then rename.
    ``os.replace`` is atomic on POSIX and on Windows, so a reader sees either
    the old file or the new one and never a fragment.
    """
    tmp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        return True
    except (OSError, TypeError, ValueError):
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def read_json(path: Path, default: Any = None) -> Any:
    """Read a JSON state file, returning *default* if it is missing or broken."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def os_caption() -> str:
    if is_demo():
        return "Microsoft Windows 11 Pro"
    r = powershell("(Get-CimInstance Win32_OperatingSystem).Caption")
    return r.text or platform.platform()
