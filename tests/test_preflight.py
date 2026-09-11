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


def test_a_missing_desktop_companion_is_not_a_limitation(frozen):
    """The terminal application is complete on its own, so grading its absence
    as a warning made a healthy machine report that it would run "with the
    limitations noted above" - contradicting this check's own remedy text."""
    check = preflight.check_gui()

    assert check.state is State.OK
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


# --------------------------------------------------------------------------
# The backend check must ask the same question the engine asks
# --------------------------------------------------------------------------

def test_doctor_and_the_engine_never_disagree(monkeypatch):
    """Reported from a real machine: doctor said the backend was installed and
    the planner in the same executable said it was not.

    The cause was doctor checking whether the *module* existed while the engine
    performed the real *import*. llama_cpp is pure Python wrapping a native
    library, so a bundle carrying the Python half without the DLL satisfies the
    first and fails the second.
    """
    from lares.brain import engine as engine_mod

    for present, error in ((True, None), (False, "OSError: cannot load library")):
        monkeypatch.setattr(engine_mod, "_BACKEND_CHECKED", True, raising=False)
        monkeypatch.setattr(engine_mod, "_BACKEND_ERROR", error, raising=False)

        check = preflight.check_model_backend()
        assert (check.state is State.OK) == present, (
            "doctor must report exactly what the engine would find")


def test_a_packaged_build_blames_itself_rather_than_the_machine(frozen, monkeypatch):
    from lares.brain import engine as engine_mod
    monkeypatch.setattr(engine_mod, "_BACKEND_CHECKED", True, raising=False)
    monkeypatch.setattr(engine_mod, "_BACKEND_ERROR",
                        "OSError: [WinError 193] not a valid Win32 application",
                        raising=False)

    check = preflight.check_model_backend()

    assert check.state is State.WARN
    assert "would not load" in check.detail
    assert "WinError 193" in check.detail
    assert "packaging fault" in check.remedy


def test_the_reason_an_import_failed_is_kept_not_swallowed(monkeypatch):
    """A backend that will not load must say why. Returning a bare False left
    nothing on screen or on disk to act on."""
    from lares.brain import engine as engine_mod
    monkeypatch.setattr(engine_mod, "_BACKEND_CHECKED", False, raising=False)
    monkeypatch.setattr(engine_mod, "_BACKEND_ERROR", None, raising=False)

    import builtins
    real_import = builtins.__import__

    def fail(name, *args, **kwargs):
        if name == "llama_cpp":
            raise OSError("[WinError 126] The specified module could not be found")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail)

    assert engine_mod._backend_present() is False
    assert "WinError 126" in engine_mod.backend_error()
