"""Tests for the model-in-the-executable mechanism.

These matter more than most, because this code decides whether to hand a file
to llama.cpp and give it authority over a machine's security settings. The
properties worth proving are that a payload survives the round trip byte for
byte, that a corrupted one is refused rather than used, and that a build with no
payload at all behaves like a normal program instead of crashing.

The "executable" here is an ordinary file. Nothing in the reader cares what the
prefix bytes are - that is the point of appending after the end.
"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
from pathlib import Path

import pytest

from lares import logs
from lares.brain import embedded


def _load_embed_tool():
    """Import winbuild/embed_model.py by path.

    It is a build script rather than part of the package, so it is not
    importable by name - but it writes the format this module reads, and the
    two agreeing is exactly what these tests are for.
    """
    path = Path(__file__).resolve().parent.parent / "winbuild" / "embed_model.py"
    spec = importlib.util.spec_from_file_location("lares_embed_tool", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


embed_model = _load_embed_tool().embed


@pytest.fixture(autouse=True)
def _quiet_logs(tmp_path, monkeypatch):
    logs.configure(directory=tmp_path / "logs")
    monkeypatch.setattr(embedded, "cache_dir", lambda: tmp_path / "models")
    (tmp_path / "models").mkdir(parents=True, exist_ok=True)


@pytest.fixture()
def fake_exe(tmp_path):
    path = tmp_path / "lares.exe"
    path.write_bytes(b"MZ" + b"\x00" * 4096)      # enough to look like a program
    return path


@pytest.fixture()
def model(tmp_path):
    path = tmp_path / "qwen-tiny.gguf"
    path.write_bytes(b"GGUF" + bytes(range(256)) * 400)
    return path


# --------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------

def test_a_payload_survives_the_round_trip(fake_exe, model, monkeypatch):
    original = model.read_bytes()
    embed_model(fake_exe, model)

    payload = embedded.read_footer(fake_exe)
    assert payload is not None
    assert payload.name == "qwen-tiny.gguf"
    assert payload.size == len(original)
    assert payload.sha256 == hashlib.sha256(original).hexdigest()

    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    out = embedded.unpack(payload)
    assert out is not None
    assert out.read_bytes() == original


def test_the_executable_prefix_is_left_untouched(fake_exe, model):
    before = fake_exe.read_bytes()
    embed_model(fake_exe, model)
    assert fake_exe.read_bytes()[: len(before)] == before


def test_unpacking_is_idempotent_and_skips_the_second_time(fake_exe, model, monkeypatch):
    embed_model(fake_exe, model)
    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    payload = embedded.read_footer(fake_exe)

    first = embedded.unpack(payload)
    assert first is not None
    assert embedded.is_unpacked(payload)

    stamp = first.stat().st_mtime_ns
    second = embedded.unpack(payload)
    assert second == first
    assert second.stat().st_mtime_ns == stamp, "should not have rewritten the file"


# --------------------------------------------------------------------------
# Refusing bad payloads
# --------------------------------------------------------------------------

def test_a_corrupted_payload_is_refused_rather_than_used(fake_exe, model, monkeypatch):
    embed_model(fake_exe, model)
    payload = embedded.read_footer(fake_exe)

    # Flip a byte in the middle of the model, leaving the footer intact - the
    # shape a real corruption or a tamper would take.
    blob = bytearray(fake_exe.read_bytes())
    blob[payload.offset + 100] ^= 0xFF
    fake_exe.write_bytes(bytes(blob))

    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    assert embedded.unpack(payload) is None
    assert not embedded.cached_path(payload).exists()
    assert not embedded.cached_path(payload).with_suffix(".gguf.part").exists()


def test_a_refused_payload_is_reported_as_an_error_with_an_id(fake_exe, model, monkeypatch):
    embed_model(fake_exe, model)
    payload = embedded.read_footer(fake_exe)
    blob = bytearray(fake_exe.read_bytes())
    blob[payload.offset + 5] ^= 0xFF
    fake_exe.write_bytes(bytes(blob))

    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    embedded.unpack(payload)

    reports = logs.get().errors()
    assert any("integrity" in r.message for r in reports)


def test_a_truncated_payload_is_refused(fake_exe, model, monkeypatch):
    embed_model(fake_exe, model)
    payload = embedded.read_footer(fake_exe)

    blob = fake_exe.read_bytes()
    fake_exe.write_bytes(blob[: payload.offset + payload.size // 2] + blob[-64:])

    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    assert embedded.unpack(payload) is None


# --------------------------------------------------------------------------
# No payload
# --------------------------------------------------------------------------

def test_a_plain_executable_reports_no_payload(fake_exe):
    assert embedded.read_footer(fake_exe) is None


def test_a_file_ending_in_the_magic_by_chance_is_not_a_payload(tmp_path):
    decoy = tmp_path / "decoy.exe"
    decoy.write_bytes(b"\x00" * 200 + embedded.MAGIC_HEAD)
    assert embedded.read_footer(decoy) is None


def test_a_file_shorter_than_the_footer_is_handled(tmp_path):
    tiny = tmp_path / "tiny.exe"
    tiny.write_bytes(b"MZ")
    assert embedded.read_footer(tiny) is None


def test_a_future_format_version_is_declined_rather_than_misread(fake_exe, model):
    embed_model(fake_exe, model)
    blob = bytearray(fake_exe.read_bytes())
    # Rewrite the version field inside the footer.
    footer_at = len(blob) - embedded.FOOTER_SIZE
    head, _version, length, name_len, digest, tail = struct.unpack(
        embedded.FOOTER_FORMAT, bytes(blob[footer_at:]))
    blob[footer_at:] = struct.pack(
        embedded.FOOTER_FORMAT, head, 99, length, name_len, digest, tail)
    fake_exe.write_bytes(bytes(blob))

    assert embedded.read_footer(fake_exe) is None


def test_ensure_returns_none_when_not_frozen(monkeypatch):
    monkeypatch.setattr(embedded, "host_path", lambda: None)
    assert embedded.ensure() is None


def test_describe_is_readable_in_every_state(fake_exe, model, monkeypatch):
    monkeypatch.setattr(embedded, "host_path", lambda: None)
    assert "not a packaged build" in embedded.describe()

    embed_model(fake_exe, model)
    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    assert "embedded in this executable" in embedded.describe()
    assert "not yet unpacked" in embedded.describe()

    embedded.unpack(embedded.read_footer(fake_exe))
    assert "unpacked" in embedded.describe()


# --------------------------------------------------------------------------
# The packaging tool's own guards
# --------------------------------------------------------------------------

def test_embedding_twice_is_refused(fake_exe, model):
    embed_model(fake_exe, model)
    with pytest.raises(SystemExit):
        embed_model(fake_exe, model)


def test_progress_is_reported_while_unpacking(fake_exe, model, monkeypatch):
    embed_model(fake_exe, model)
    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    monkeypatch.setattr(embedded, "CHUNK", 1024)

    seen: list[tuple[int, int]] = []
    embedded.unpack(embedded.read_footer(fake_exe), progress=lambda d, t: seen.append((d, t)))

    assert seen, "expected progress callbacks"
    assert seen[-1][0] == seen[-1][1], "final callback should report completion"


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------

def test_a_packaged_build_selects_the_model_it_carries(fake_exe, model, monkeypatch):
    """The single-file build must use what it is carrying, not go downloading.

    This also constructs the fallback ModelSpec, which is the only place that
    happens - a missing required field there would otherwise surface for the
    first time on a user's machine.
    """
    from lares.brain import models as models_mod

    embed_model(fake_exe, model)
    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)
    monkeypatch.setattr(models_mod, "models_dir", embedded.cache_dir)

    decision = models_mod.choose()

    assert decision.spec is not None
    assert decision.spec.filename == "qwen-tiny.gguf"
    assert decision.present
    assert "embedded in this executable" in decision.reason
    assert decision.spec.path.is_file(), "spec.path must point at the unpacked file"


def test_an_explicit_tier_still_overrides_the_embedded_model(fake_exe, model, monkeypatch):
    from lares.brain import models as models_mod

    embed_model(fake_exe, model)
    monkeypatch.setattr(embedded, "host_path", lambda: fake_exe)

    decision = models_mod.choose(prefer="1.5b")
    assert decision.spec is not None
    assert decision.spec.key == "1.5b"
