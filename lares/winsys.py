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
import re
import shutil
import subprocess
import sys
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
        stderr=clean_clixml(proc.stderr or ""),
        code=proc.returncode,
    )


_CLIXML_PREFIX = "#< CLIXML"
_CLIXML_STRING = re.compile(r"<S[^>]*>(.*?)</S>", re.DOTALL)


def clean_clixml(text: str) -> str:
    """Turn PowerShell's serialised error stream back into readable text.

    When PowerShell's stderr is captured rather than shown, it does not write
    plain messages - it writes the error records as CLIXML, so a failure that
    reads perfectly well in a console arrives here as

        #< CLIXML <Objs Version="1.1.0.1" xmlns="http://schemas...

    and the useful sentence is buried in an <S> element several hundred
    characters in. Reporting that verbatim to somebody whose remediation just
    failed is no better than reporting nothing.
    """
    if _CLIXML_PREFIX not in text:
        return text

    body = text.split(_CLIXML_PREFIX, 1)[1]
    pieces = []
    for raw in _CLIXML_STRING.findall(body):
        # CLIXML escapes newlines and tabs as _x000D__x000A_ and friends.
        piece = re.sub(r"_x([0-9A-Fa-f]{4})_",
                       lambda m: chr(int(m.group(1), 16)), raw)
        pieces.append(piece)

    message = " ".join(" ".join(pieces).split())
    if not message:
        # Nothing extractable. Say so rather than handing back the raw XML.
        return "PowerShell reported an error but its detail could not be read"
    return _unescape(message)


def _unescape(text: str) -> str:
    for entity, char in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'),
                         ("&apos;", "'"), ("&amp;", "&")):
        text = text.replace(entity, char)
    return text


def _no_window_flags() -> int:
    """Keep console windows from flashing when the GUI shells out."""
    if IS_WINDOWS:
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return 0


def _system_root() -> str:
    """The real Windows directory, asked of the OS rather than the environment.

    Falls back to the environment variable only when the call is unavailable,
    which is every non-Windows platform and nothing else.
    """
    if IS_WINDOWS:
        try:
            buffer = ctypes.create_unicode_buffer(260)
            length = ctypes.windll.kernel32.GetSystemDirectoryW(  # type: ignore[attr-defined]
                buffer, len(buffer))
            if 0 < length < len(buffer):
                # GetSystemDirectory returns ...\System32; the callers here
                # want the Windows directory above it.
                return str(Path(buffer.value).parent)
        except Exception:  # noqa: BLE001 - fall through to the environment
            pass
    return os.environ.get("SystemRoot", r"C:\Windows")


def powershell_exe() -> str:
    """Prefer Windows PowerShell 5.1; fall back to pwsh 7+ if that is all there is.

    5.1 is the one guaranteed to exist on every supported Windows build and it
    carries the full set of management modules Lares depends on. pwsh is only
    used when 5.1 is genuinely absent.

    Every candidate is an absolute path under a directory only an administrator
    can write to, and a relative answer is refused outright. That is not
    fussiness. ``shutil.which`` on Windows searches the **current directory
    first** - CPython inserts ``os.curdir`` ahead of PATH - so an earlier
    version of this function would, if System32 could not be read, run
    whatever ``powershell.exe`` happened to sit beside the file someone had
    just double-clicked. Lares runs as administrator. A tool that hardens a
    machine must not be the thing that hands a writable download folder a
    SYSTEM shell.
    """
    if IS_WINDOWS:
        # GetSystemDirectoryW, not %SystemRoot%. The environment variable is
        # inherited and any process can set it for the one it launches, so
        # building "absolute, administrator-only" paths out of it left the
        # whole set attacker-chosen - a bypass of the fix that replaced the
        # PATH search. The Win32 call reads the value the kernel holds and
        # cannot be influenced by the environment.
        root = Path(_system_root())
        candidates = [
            root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
            # A 32-bit process on 64-bit Windows is redirected away from the
            # real System32; SysNative is the door back to it.
            root / "SysNative" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
            root / "SysWOW64" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        ]
        for program_files in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            base = os.environ.get(program_files)
            if base:
                candidates.append(Path(base) / "PowerShell" / "7" / "pwsh.exe")
        for candidate in candidates:
            try:
                if candidate.is_file():
                    return str(candidate)
            except OSError:
                continue
        # Nothing was found where it is supposed to be. Say so rather than
        # searching a path an attacker may be standing in; run() reports a
        # missing binary cleanly, and a scan that cannot find PowerShell is a
        # far better outcome than one that finds the wrong one.
        return str(candidates[0])

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


# script_file() lived here: it wrote a script to a temp file and handed back the
# path. Nothing called it. Its docstring described a design that was not the one
# that shipped - every script goes through powershell() as a base64
# -EncodedCommand, which never touches the filesystem at all.
#
# It is deleted rather than kept for later because of what it was. A privileged
# process that writes a script to a shared temp directory and then runs it by
# path has a window between the two where another user can replace the file,
# and on Windows an elevated process inherits a TEMP that is not always its
# own. Leaving that primitive lying around for a future caller to reach for is
# how that bug gets written. If a script ever genuinely needs to be on disk, it
# belongs in a directory this process creates with an explicit DACL, and that
# decision should be made deliberately rather than inherited from dead code.


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
