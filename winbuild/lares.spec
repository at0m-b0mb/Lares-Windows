# PyInstaller spec for all three Lares executables.
#
# Builds three programs from one spec so they cannot drift apart:
#
#   lares.exe           the terminal application, console subsystem
#   lares-desktop.exe   the desktop application, windowed subsystem
#   lares-freehand.exe  the lane with no catalogue, console subsystem
#
# Both are onefile. That is the whole point of shipping a binary here - the
# person running it should not have to think about Python, pip, a virtual
# environment, or which of three Pythons on their machine is on PATH.
#
# Build it with:
#
#   pyinstaller winbuild/lares.spec --noconfirm
#
# and note that this must run on Windows. PyInstaller is a bundler, not a
# cross-compiler: it wraps the interpreter and the extension modules of the
# machine it runs on, so a Windows binary has to be produced on Windows and an
# ARM64 binary on an ARM64 Windows machine. The repository builds both in CI
# for exactly that reason.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve().parent

# The catalogue is data, not code, and the executor can only ever run what is
# in it - so if these files do not make it into the bundle, the program starts
# and then refuses to do anything. Worth being explicit about.
CATALOGUE = [(str(ROOT / "lares" / "catalog" / "controls"), "lares/catalog/controls")]
datas = CATALOGUE + [
    (str(ROOT / "assets" / "lares.ico"), "assets"),
]

# llama_cpp ships a native library beside its Python package and loads it by
# path at import time, so it needs collecting wholesale rather than by module
# name. It is genuinely optional: on ARM64 there is no wheel for it, and Lares
# falls back to the built-in planner. Missing here is not an error.
hiddenimports = ["yaml"]
binaries = []
try:
    import llama_cpp  # noqa: F401
except ImportError:
    _HAS_BACKEND = False
    print("[lares.spec] llama-cpp-python not present; "
          "building without the model backend (the built-in planner still works)")
else:
    _HAS_BACKEND = True
    from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

    hiddenimports += collect_submodules("llama_cpp")
    datas += collect_data_files("llama_cpp")

    # collect_dynamic_libs is not enough on its own here. llama_cpp finds its
    # native library by walking from its own __file__ into lib/, and a onefile
    # build unpacks into a temporary directory where that relative walk is
    # fragile - which showed up as doctor reporting the backend present while
    # the planner in the same executable could not import it. Placing the
    # libraries explicitly under llama_cpp/lib puts them where the package
    # actually looks; lares/brain/engine.py also sets the environment variable
    # that names the directory, so both routes lead to the same place.
    collected = collect_dynamic_libs("llama_cpp")
    binaries += collected
    package_dir = Path(llama_cpp.__file__).resolve().parent
    for candidate in sorted((package_dir / "lib").glob("*")):
        if candidate.suffix.lower() in (".dll", ".so", ".dylib"):
            binaries.append((str(candidate), "llama_cpp/lib"))

    # llama_cpp imports numpy at module scope, so it has to come along.
    hiddenimports += ["numpy"]

    print(f"[lares.spec] bundling llama-cpp-python "
          f"({len(binaries)} native libraries) and numpy")

# Trimming what is provably unused keeps the download reasonable on the slow
# machines this targets.
#
# numpy is the cautionary tale and is deliberately not in this list when the
# backend is bundled. It was, on the reasoning that Lares itself never imports
# it - which is true, and irrelevant, because llama_cpp does. The result was a
# 1.1 GB executable that carried the model and the backend and then failed to
# load it with ModuleNotFoundError, falling back to the built-in planner while
# reporting the backend as present. Excluding a package your dependency needs
# does not fail loudly at build time; it fails quietly on a user's machine.
excludes = [
    "tkinter", "matplotlib", "scipy", "pandas", "PIL",
    "pytest", "setuptools", "pip", "unittest", "pydoc", "doctest",
    "IPython", "notebook", "sphinx",
]

if not _HAS_BACKEND:
    # Nothing else here needs numpy, so it only earns its place alongside
    # llama_cpp.
    excludes.append("numpy")

block_cipher = None


def analysis(entry: str, extra_excludes=(), extra_datas=None) -> Analysis:
    return Analysis(
        [str(ROOT / entry)],
        pathex=[str(ROOT)],
        binaries=binaries,
        datas=datas if extra_datas is None else extra_datas,
        hiddenimports=hiddenimports,
        hookspath=[],
        runtime_hooks=[],
        excludes=excludes + list(extra_excludes),
        win_no_prefer_redirects=False,
        win_private_assemblies=False,
        cipher=block_cipher,
        noarchive=False,
    )


# -- the terminal application ---------------------------------------------
# Qt is excluded here deliberately. Without it the console build is a fraction
# of the size, and the terminal application has no business importing a GUI
# toolkit.
console_a = analysis("lares.py", extra_excludes=["PyQt6", "PyQt5", "PySide6"])
console_pyz = PYZ(console_a.pure, console_a.zipped_data, cipher=block_cipher)
console_exe = EXE(
    console_pyz,
    console_a.scripts,
    console_a.binaries,
    console_a.zipfiles,
    console_a.datas,
    [],
    name="lares",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    icon=str(ROOT / "assets" / "lares.ico"),
    version=str(ROOT / "winbuild" / "version_info.txt"),
)

# -- the freehand application ---------------------------------------------
# Built without the catalogue, on purpose. This program's whole claim is that
# nothing it runs was written in advance, and the cheapest way to keep that
# claim true is for the pre-written remediations not to be in the file at all.
# Nothing in its import graph reads them - the loader is imported, which costs
# nothing, and load() is never called - so leaving them out is a property of
# the binary rather than a promise about it.
freehand_a = analysis(
    "lares-freehand.py",
    extra_excludes=["PyQt6", "PyQt5", "PySide6"],
    # Everything the other builds carry except the catalogue. Written as a
    # subtraction rather than a fresh list on purpose: llama_cpp's data files
    # are appended to datas above, and a hand-written list here would have
    # quietly shipped a freehand binary whose model backend could not load -
    # which is the one thing this program cannot do without.
    extra_datas=[item for item in datas if item not in CATALOGUE],
)
freehand_pyz = PYZ(freehand_a.pure, freehand_a.zipped_data, cipher=block_cipher)
freehand_exe = EXE(
    freehand_pyz,
    freehand_a.scripts,
    freehand_a.binaries,
    freehand_a.zipfiles,
    freehand_a.datas,
    [],
    name="lares-freehand",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    icon=str(ROOT / "assets" / "lares.ico"),
    version=str(ROOT / "winbuild" / "version_info.txt"),
)

# -- the desktop application ----------------------------------------------
desktop_a = analysis("lares-gui.py")
desktop_pyz = PYZ(desktop_a.pure, desktop_a.zipped_data, cipher=block_cipher)
desktop_exe = EXE(
    desktop_pyz,
    desktop_a.scripts,
    desktop_a.binaries,
    desktop_a.zipfiles,
    desktop_a.datas,
    [],
    name="lares-desktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    icon=str(ROOT / "assets" / "lares.ico"),
    version=str(ROOT / "winbuild" / "version_info.txt"),
)
