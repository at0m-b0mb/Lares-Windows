"""A model carried inside the executable itself.

The goal is one file. Someone downloads ``lares.exe``, runs it on a machine with
no Python, no pip, no compiler and no internet, and it works - model included.

The obvious way to do that is to hand the .gguf to PyInstaller as bundled data,
and it is a trap. A onefile build unpacks its entire payload into a temporary
directory *every time it starts*. With a gigabyte of model weights in there,
every launch would copy a gigabyte to disk before printing anything, on exactly
the slow spinning-disk machines this tool is meant for.

So the model is not bundled. It is **appended to the finished executable** as an
overlay, after a footer that says where it starts and what it should hash to:

    [ PyInstaller executable ][ model bytes ][ name ][ 64-byte footer ]

At startup Lares reads the last 64 bytes of its own file. If the footer is
there, the model is streamed out to the cache directory once, verified against
the recorded SHA-256, and thereafter memory-mapped from that path like any other
model - which is also the only way llama.cpp can use it, since it mmaps the file
rather than reading it through Python.

The result is a single file that starts instantly on every run but the first,
and which can be checked for tampering: the hash in the footer must match the
bytes that come out of it.

Appending data to an executable does not disturb it. The PE loader reads the
section table for its extents and ignores trailing bytes, which is the same
mechanism self-extracting archives have used for thirty years. It does break an
Authenticode signature, so signing has to happen after the model is appended,
not before.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .. import logs
from ..winsys import state_dir

#: Bracketing magic. Two of them, at both ends of the footer, so a file that
#: merely happens to end in the right eight bytes is not mistaken for a payload.
MAGIC_HEAD = b"LARESMDL"
MAGIC_TAIL = b"LARESEND"

FOOTER_FORMAT = "<8sIQH2x32s8s"
FOOTER_SIZE = struct.calcsize(FOOTER_FORMAT)   # 64 bytes
FORMAT_VERSION = 1

#: Copy in chunks rather than reading a gigabyte into memory on a 4GB machine.
CHUNK = 4 * 1024 * 1024


@dataclass(frozen=True)
class Payload:
    """A model found inside this executable."""

    name: str
    size: int
    sha256: str
    offset: int

    @property
    def size_mb(self) -> int:
        return self.size // (1024 * 1024)


Progress = Callable[[int, int], None]


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

def host_path() -> Path | None:
    """The file that might carry a payload: this executable, when frozen."""
    if not getattr(sys, "frozen", False):
        return None
    try:
        return Path(sys.executable).resolve()
    except OSError:
        return None


def read_footer(path: Path) -> Payload | None:
    """Return the payload description at the end of *path*, if there is one."""
    try:
        size = path.stat().st_size
        if size < FOOTER_SIZE:
            return None
        with path.open("rb") as fh:
            fh.seek(-FOOTER_SIZE, os.SEEK_END)
            raw = fh.read(FOOTER_SIZE)
            if len(raw) != FOOTER_SIZE:
                return None
            head, version, length, name_len, digest, tail = struct.unpack(FOOTER_FORMAT, raw)
            if head != MAGIC_HEAD or tail != MAGIC_TAIL:
                return None
            if version != FORMAT_VERSION:
                logs.get().warn(
                    "model", "This executable carries a payload in a newer format",
                    found=version, understood=FORMAT_VERSION)
                return None

            name_offset = size - FOOTER_SIZE - name_len
            payload_offset = name_offset - length
            if payload_offset < 0 or name_len > 512:
                return None

            fh.seek(name_offset)
            name = fh.read(name_len).decode("utf-8", errors="replace")

        if not safe_filename(name):
            # The name decides where the payload is written, so it is the one
            # field in this footer that can reach outside the cache directory.
            # Refusing the whole payload is the right answer rather than
            # sanitising the name: a footer asking to be written to
            # System32 is not a filename problem to be cleaned up, it is a
            # hostile executable, and Lares then runs without an embedded
            # model rather than writing what it was told to.
            logs.get().error(
                "model", "This executable's payload asked to be written "
                         "outside the model cache; refusing it",
                exc=ValueError(f"unsafe payload name {name[:120]!r}"))
            return None

        return Payload(name=name, size=length, sha256=digest.hex(), offset=payload_offset)
    except (OSError, struct.error, ValueError):
        return None


def present() -> Payload | None:
    """The payload in this executable, or None when running from source."""
    path = host_path()
    if path is None:
        return None
    return read_footer(path)


# --------------------------------------------------------------------------
# Unpacking
# --------------------------------------------------------------------------

def cache_dir() -> Path:
    return state_dir("models")


#: Windows treats these as devices wherever they appear as a filename stem, so
#: a payload called "CON.gguf" would not be a file at all.
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{n}" for n in range(1, 10)),
    *(f"LPT{n}" for n in range(1, 10)),
}

#: Deliberately narrow. This names a GGUF file that upstream publishes, not an
#: arbitrary path, so anything outside this set is a reason to stop rather
#: than a case to handle.
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}")


def safe_filename(name: str) -> bool:
    """Whether *name* is a bare filename that cannot escape a directory.

    The payload name arrives from data appended to the executable, which is
    exactly the kind of input this file already treats as hostile everywhere
    else - the offsets and the length are bounds-checked a few lines above.
    The name was not, and it is the field that decides where a gigabyte gets
    written by a process running as administrator.

    ``Path("C:/cache") / "C:/Windows/System32/x.dll"`` is
    ``C:/Windows/System32/x.dll``: an absolute component discards everything
    to its left. So a crafted footer could write its payload anywhere the
    process can reach, and the integrity check is no defence at all, because
    whoever wrote the name also wrote the hash it is checked against.
    """
    if not name or name != name.strip():
        return False
    if not _SAFE_NAME.fullmatch(name):
        return False
    if name in (".", ".."):
        return False
    # Path treats both separators on Windows, so both are refused everywhere.
    if "/" in name or "\\" in name or ":" in name:
        return False
    if name.split(".")[0].upper() in _RESERVED:
        return False
    return True


def cached_path(payload: Payload) -> Path:
    """Where this payload is unpacked to.

    The name is re-checked here rather than trusted from read_footer. This is
    the function whose return value gets opened for writing, and a second
    check costs nothing next to being wrong about which of two callers
    validated first.
    """
    if not safe_filename(payload.name):
        raise ValueError(f"unsafe payload name: {payload.name[:120]!r}")
    return cache_dir() / payload.name


def is_unpacked(payload: Payload) -> bool:
    """True when the model is already on disk at the right size.

    Size is checked rather than hash, because hashing a gigabyte on every start
    would cost more than it saves. The hash is verified when the file is written
    - the expensive check happens once, at the moment it could actually catch
    something.
    """
    path = cached_path(payload)
    try:
        return path.is_file() and path.stat().st_size == payload.size
    except OSError:
        return False


def unpack(payload: Payload, *, progress: Progress | None = None) -> Path | None:
    """Write the embedded model out to the cache, verifying it. Idempotent.

    Returns the path to the model, or None if it could not be written - in which
    case Lares carries on with the built-in planner rather than failing.
    """
    log = logs.get()
    destination = cached_path(payload)

    if is_unpacked(payload):
        return destination

    host = host_path()
    if host is None:
        return None

    # Written under a temporary name and renamed at the end, so an interrupted
    # unpack - a power cut, a full disk - cannot leave a half-written model that
    # looks complete on the next run.
    temporary = destination.with_suffix(destination.suffix + ".part")
    digest = hashlib.sha256()
    written = 0

    log.info("model", f"Unpacking the embedded model ({payload.size_mb} MB)",
             name=payload.name, destination=str(destination))

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with host.open("rb") as source, temporary.open("wb") as out:
            source.seek(payload.offset)
            remaining = payload.size
            while remaining > 0:
                block = source.read(min(CHUNK, remaining))
                if not block:
                    break
                out.write(block)
                digest.update(block)
                written += len(block)
                remaining -= len(block)
                if progress:
                    progress(written, payload.size)
    except OSError as exc:
        log.error("model", "Could not unpack the embedded model", exc=exc,
                  destination=str(destination), written=written)
        _remove(temporary)
        return None

    if written != payload.size:
        log.error("model", "The embedded model is truncated",
                  exc=ValueError(f"expected {payload.size} bytes, read {written}"))
        _remove(temporary)
        return None

    if digest.hexdigest() != payload.sha256:
        # Either the download was corrupted or the executable was modified. In
        # both cases the right move is to refuse it: this file is about to be
        # given decision-making authority over a machine's security settings.
        log.error(
            "model", "The embedded model failed its integrity check",
            exc=ValueError(f"expected {payload.sha256[:16]}, got {digest.hexdigest()[:16]}"),
            name=payload.name,
        )
        _remove(temporary)
        return None

    try:
        temporary.replace(destination)
    except OSError as exc:
        log.error("model", "Could not put the unpacked model in place", exc=exc)
        _remove(temporary)
        return None

    log.info("model", "Embedded model unpacked and verified",
             name=payload.name, size_mb=payload.size_mb)
    return destination


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def ensure(*, progress: Progress | None = None) -> Path | None:
    """The one call the rest of the application makes.

    Returns a usable path to the embedded model, unpacking it on first run, or
    None when this build does not carry one.
    """
    payload = present()
    if payload is None:
        return None
    return unpack(payload, progress=progress)


def describe() -> str:
    """A line for the Model page and ``lares doctor``."""
    payload = present()
    if payload is None:
        if getattr(sys, "frozen", False):
            return "this build does not carry a model; one will be downloaded when needed"
        return "not a packaged build"
    state = "unpacked" if is_unpacked(payload) else "not yet unpacked"
    return f"{payload.name} ({payload.size_mb} MB, {state}) is embedded in this executable"
