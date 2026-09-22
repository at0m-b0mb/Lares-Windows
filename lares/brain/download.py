"""Fetching a model, once, and knowing it has not changed since.

The weights are not in the repository - they are gigabytes and they are not ours
to redistribute. They come from Hugging Face over HTTPS, straight to disk, with
no dependency beyond the standard library so that a machine with a bare Python
install can still get one.

On integrity: the first fetch is trust-on-first-use, because no hash is shipped
for a file this project does not host and inventing one would be worse than
admitting that. What Lares does instead is compute the hash it received, print
it so it can be checked against the model card, and pin it. ``verify`` then
checks the file against that pin whenever it is called - on every fetch, and
whenever ``lares model`` is run.

It is not checked on every start. Re-reading a gigabyte before the first token
is not a cost the hardware this targets can pay, so a model already in place is
taken on its size. What this catches is a truncated download, a disk that
rotted, and a file replaced by something of a different length. What it cannot
catch is the account it runs as: the cache is in that user's own profile,
beside an executable the same user can replace. Filling in ``sha256`` on a
registry entry makes even the first fetch strict.
"""

from __future__ import annotations

import hashlib
import shutil
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import ModelSpec, expected_digest, save_pin

#: Read size. Large enough to keep the hash cheap, small enough that progress
#: moves visibly on a slow connection.
CHUNK = 1024 * 256

USER_AGENT = "Lares/0.1 (+https://github.com/at0m-b0mb/Lares-Windows)"

Progress = Callable[[int, int], None]


@dataclass
class Result:
    ok: bool
    path: Path | None = None
    digest: str = ""
    message: str = ""
    #: True when the file was already present and verified.
    cached: bool = False


def sha256_of(path: Path, progress: Progress | None = None) -> str:
    total = path.stat().st_size
    done = 0
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            hasher.update(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)
    return hasher.hexdigest()


def verify(spec: ModelSpec, progress: Progress | None = None) -> Result:
    """Check an already-downloaded model against its pin."""
    if not spec.path.exists():
        return Result(False, message=f"{spec.filename} is not downloaded")

    expected = expected_digest(spec)
    if not expected:
        digest = sha256_of(spec.path, progress)
        save_pin(spec.filename, digest)
        return Result(True, spec.path, digest, cached=True,
                      message=f"pinned sha256 {digest}")

    digest = sha256_of(spec.path, progress)
    if digest != expected:
        return Result(
            False, spec.path, digest,
            message=(
                f"{spec.filename} does not match its pinned checksum.\n"
                f"  expected {expected}\n  found    {digest}\n"
                "The file has changed since it was first downloaded. Delete it and "
                "fetch it again, or investigate why it changed."
            ),
        )
    return Result(True, spec.path, digest, cached=True, message="checksum matches")


def fetch(spec: ModelSpec, progress: Progress | None = None,
          force: bool = False) -> Result:
    """Download a model to disk, resuming nothing and verifying afterwards.

    The download goes to a ``.part`` file and is only moved into place once the
    hash has been computed, so an interrupted fetch can never leave something
    that looks like a usable model.
    """
    if spec.path.exists() and not force:
        return verify(spec, progress)

    if not spec.repo:
        # The embedded spec has no upstream - it came out of the executable.
        # Without this the URL would be built with an empty path segment and
        # the failure would look like a network problem rather than a bug.
        return Result(False, message=(
            f"{spec.name} has no download source; it is carried inside this "
            "executable rather than fetched"
        ))

    if not spec.url.lower().startswith("https://"):
        return Result(False, message=f"refusing a non-HTTPS model URL: {spec.url}")

    target = spec.path
    partial = target.with_suffix(target.suffix + ".part")
    target.parent.mkdir(parents=True, exist_ok=True)

    free = shutil.disk_usage(target.parent).free
    needed = spec.size_mb * 1024 * 1024
    if free < needed * 1.1:
        return Result(False, message=(
            f"not enough disk space: {spec.name} needs about {spec.size_mb} MB "
            f"and only {free // 2**20} MB is free"
        ))

    request = urllib.request.Request(spec.url, headers={"User-Agent": USER_AGENT})
    hasher = hashlib.sha256()
    done = 0

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            # Hugging Face redirects large files to a CDN, and urllib follows
            # redirects without caring whether the scheme survives. A redirect
            # that lands on http:// would put the weights on the wire in clear,
            # so the scheme is checked after the hops rather than before.
            final = getattr(response, "url", "") or spec.url
            if not final.lower().startswith("https://"):
                partial.unlink(missing_ok=True)
                return Result(False, message=(
                    f"the download was redirected to a non-HTTPS address ({final}) "
                    "and was abandoned"
                ))
            total = int(response.headers.get("Content-Length", 0) or needed)
            with partial.open("wb") as fh:
                while chunk := response.read(CHUNK):
                    fh.write(chunk)
                    hasher.update(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
    except urllib.error.HTTPError as exc:
        partial.unlink(missing_ok=True)
        return Result(False, message=f"download failed: HTTP {exc.code} for {spec.url}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        partial.unlink(missing_ok=True)
        return Result(False, message=f"download failed: {exc}")

    digest = hasher.hexdigest()
    expected = spec.sha256  # only a shipped pin makes the first fetch strict
    if expected and digest != expected:
        partial.unlink(missing_ok=True)
        return Result(False, digest=digest, message=(
            f"{spec.filename} did not match the expected checksum and was discarded.\n"
            f"  expected {expected}\n  received {digest}"
        ))

    partial.replace(target)
    save_pin(spec.filename, digest)
    return Result(True, target, digest, message=(
        f"downloaded {done // 2**20} MB and pinned sha256 {digest}. "
        "Compare it against the file's checksum on its Hugging Face model card."
    ))


def remove(spec: ModelSpec) -> bool:
    try:
        spec.path.unlink()
        return True
    except OSError:
        return False
