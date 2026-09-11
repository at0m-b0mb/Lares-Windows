"""Append a GGUF model to a built executable.

Run after PyInstaller, before signing:

    python winbuild/embed_model.py dist/lares.exe models/qwen2.5-coder-1.5b.gguf
    python winbuild/embed_model.py --check dist/lares.exe

The layout written here is the one ``lares/brain/embedded.py`` reads:

    [ executable ][ model bytes ][ model filename ][ 64-byte footer ]

Trailing bytes do not disturb a PE executable - the loader uses the section
table for its extents - which is how self-extracting archives have always
worked. It does invalidate an Authenticode signature, so sign afterwards.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lares.brain.embedded import (  # noqa: E402
    CHUNK,
    FOOTER_FORMAT,
    FORMAT_VERSION,
    MAGIC_HEAD,
    MAGIC_TAIL,
    read_footer,
)


def digest_of(path: Path) -> tuple[str, int]:
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while block := fh.read(CHUNK):
            sha.update(block)
            size += len(block)
    return sha.hexdigest(), size


def embed(executable: Path, model: Path, *, output: Path | None = None) -> Path:
    if not executable.is_file():
        raise SystemExit(f"no such executable: {executable}")
    if not model.is_file():
        raise SystemExit(f"no such model: {model}")

    if read_footer(executable) is not None:
        raise SystemExit(
            f"{executable.name} already carries a model. Rebuild it rather than "
            "appending twice - the second payload would be unreachable."
        )

    target = output or executable
    if target != executable:
        shutil.copy2(executable, target)

    sha, size = digest_of(model)
    name = model.name.encode("utf-8")
    if len(name) > 512:
        raise SystemExit("model filename is too long to record")

    print(f"  executable : {executable.name} ({executable.stat().st_size / 1e6:.1f} MB)")
    print(f"  model      : {model.name} ({size / 1e6:.1f} MB)")
    print(f"  sha256     : {sha}")

    with target.open("ab") as out, model.open("rb") as src:
        copied = 0
        while block := src.read(CHUNK):
            out.write(block)
            copied += len(block)
            done = copied * 100 // size
            print(f"\r  appending  : {done:3d}%", end="", flush=True)
        print()

        out.write(name)
        out.write(struct.pack(
            FOOTER_FORMAT,
            MAGIC_HEAD, FORMAT_VERSION, size, len(name),
            bytes.fromhex(sha), MAGIC_TAIL,
        ))

    # Read it back the way the application will, so a packaging mistake fails
    # here rather than on a user's machine.
    payload = read_footer(target)
    if payload is None:
        raise SystemExit("wrote the payload but could not read it back - aborting")
    if payload.sha256 != sha or payload.size != size or payload.name != model.name:
        raise SystemExit("the footer read back does not match what was written")

    print(f"  result     : {target} ({target.stat().st_size / 1e6:.1f} MB)")
    print(f"  verified   : {payload.name}, {payload.size_mb} MB at offset {payload.offset}")
    return target


def check(executable: Path) -> int:
    payload = read_footer(executable)
    if payload is None:
        print(f"{executable.name}: no embedded model")
        return 1
    print(f"{executable.name}: {payload.name}")
    print(f"  size   {payload.size_mb} MB")
    print(f"  sha256 {payload.sha256}")
    print(f"  offset {payload.offset}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("executable", type=Path)
    parser.add_argument("model", type=Path, nargs="?")
    parser.add_argument("--output", type=Path, help="write a copy instead of appending in place")
    parser.add_argument("--check", action="store_true", help="report what is already embedded")
    args = parser.parse_args(argv)

    if args.check:
        return check(args.executable)
    if args.model is None:
        parser.error("a model path is required unless --check is given")

    embed(args.executable, args.model, output=args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
