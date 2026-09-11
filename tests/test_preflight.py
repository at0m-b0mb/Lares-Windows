"""What the doctor reports, including the paths that only run inside an .exe.

Frozen-only branches are the ones most likely to be wrong, because they cannot
run during ordinary development and every test passes without them. Two real
bugs in this project were exactly that shape - a missing import on a line that
only executes inside a PyInstaller build - so the frozen paths are exercised
here explicitly by faking sys.frozen.
"""

from __future__ import annotations

import sys

import pytest

from lares import preflight
from lares.preflight import State


@pytest.fixture
def frozen(tmp_path, monkeypatch):
    """Pretend to be a packaged executable living in tmp_path."""
    exe = tmp_path / "lares.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    return tmp_path


# --------------------------------------------------------------------------
# The desktop check
# --------------------------------------------------------------------------

def test_a_packaged_build_looks_for_the_desktop_exe_not_the_module(frozen):
    """The console build excludes Qt on purpose, so a missing PyQt6 module says
    nothing at all about whether the desktop application is available."""
    (frozen / "lares-desktop.exe").write_bytes(b"MZ")

    check = preflight.check_gui()

    assert check.state is State.OK
    assert "lares-desktop.exe" in check.detail


def test_a_packaged_build_without_the_desktop_exe_says_how_to_get_it(frozen):
    check = preflight.check_gui()

    assert check.state is State.WARN
    # Telling someone with no Python and no pip to run pip would be useless.
    assert "pip install" not in check.remedy
    assert "-Desktop" in check.remedy or "releases" in check.remedy


def test_from_source_the_module_is_what_matters(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    check = preflight.check_gui()
    assert "PyQt6" in check.detail


# --------------------------------------------------------------------------
# Architecture
# --------------------------------------------------------------------------

def test_architecture_describes_itself_without_raising():
    arch = preflight.architecture()
    assert arch.process and arch.native
    assert arch.describe()


def test_emulation_is_reported_as_its_own_thing():
    arch = preflight.Architecture(process="x64", native="ARM64", emulated=True)
    assert arch.is_arm
    assert "emulation" in arch.describe()


# --------------------------------------------------------------------------
# The whole report
# --------------------------------------------------------------------------

def test_every_check_returns_a_usable_result():
    checks = preflight.run()
    assert checks
    for check in checks:
        assert check.name
        assert check.detail
        assert isinstance(check.state, State)
        # Anything not OK has to say what to do about it.
        if check.state is not State.OK:
            assert check.remedy, f"{check.name} is {check.state.value} with no remedy"


def test_the_verdict_matches_the_worst_check():
    ok = [preflight.Check("a", State.OK, "fine")]
    warn = ok + [preflight.Check("b", State.WARN, "hmm", "do this")]
    fail = warn + [preflight.Check("c", State.FAIL, "no", "fix this")]

    assert preflight.worst(ok) is State.OK
    assert preflight.worst(warn) is State.WARN
    assert preflight.worst(fail) is State.FAIL
    assert "cannot run" in preflight.verdict(fail)
    assert "limitations" in preflight.verdict(warn)


def test_a_packaged_build_reports_every_check_without_raising(frozen):
    for check in preflight.run():
        assert check.name and check.detail
