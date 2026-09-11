"""What this machine can and cannot run, checked rather than assumed.

Lares targets two Windows architectures and they are not equally well served:

* **x64 (AMD64)** - everything works. Native Python, PyQt6 wheels, and prebuilt
  llama-cpp-python CPU wheels, so the embedded model runs without a compiler.

* **ARM64** - Windows 11 on ARM, which is what VMware Fusion runs on Apple
  Silicon, and what a Surface Pro X or a Snapdragon laptop is. Python and PyQt6
  both ship native ARM64 builds, so the scanner, the catalogue, the executor and
  the desktop application all run natively and at full speed. What is *not*
  published for ARM64 is a prebuilt ``llama-cpp-python`` wheel, so the embedded
  model either needs a compiler or is simply left out.

That last point is why the built-in planner was never allowed to be a stub. On
ARM64 without a compiler, Lares still scans, still decides, still fixes, still
verifies and still rolls back. It just does that with the deterministic planner
instead of the model, and this module is what says so out loud rather than
failing later with an import error.

There is one more wrinkle worth naming: Windows on ARM will happily run x64
Python under emulation, and an emulated interpreter reports ``AMD64`` for its
own architecture while the machine underneath is ARM64. That combination pulls
in x64 wheels that work but run slowly, so it is detected and reported
separately rather than being mistaken for a real x64 machine.
"""

from __future__ import annotations

import ctypes
import importlib.util
import platform
import shutil
import sys
from dataclasses import dataclass
from enum import Enum

from .winsys import IS_WINDOWS, data_dir, is_demo, is_elevated, powershell

#: IMAGE_FILE_MACHINE constants used by IsWow64Process2.
_MACHINE_NAMES = {
    0x0000: "unknown",
    0x014C: "x86",
    0x01C4: "ARM32",
    0x8664: "x64",
    0xAA64: "ARM64",
}


class State(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Check:
    name: str
    state: State
    detail: str
    #: What to do about it, when there is something to do.
    remedy: str = ""

    @property
    def mark(self) -> str:
        return {State.OK: "ok", State.WARN: "warn", State.FAIL: "FAIL"}[self.state]


# --------------------------------------------------------------------------
# Architecture
# --------------------------------------------------------------------------

@dataclass
class Architecture:
    """What the process is, and what the machine underneath it is."""

    process: str          # "x64" | "ARM64" | "x86" | platform.machine()
    native: str           # the machine's own architecture
    emulated: bool        # process architecture differs from native

    @property
    def is_arm(self) -> bool:
        return self.native == "ARM64"

    def describe(self) -> str:
        if self.emulated:
            return (
                f"{self.process} Python running under emulation on a {self.native} machine"
            )
        return f"{self.process} on {self.native}"


def architecture() -> Architecture:
    """Detect process and native architecture.

    On Windows this uses ``IsWow64Process2``, which is the only reliable way to
    tell a genuine x64 machine from an x64 process being emulated on ARM64 -
    every environment variable and ``platform`` value reports the emulated view.
    """
    machine = (platform.machine() or "").upper()
    process = {"AMD64": "x64", "X86_64": "x64", "ARM64": "ARM64",
               "AARCH64": "ARM64", "X86": "x86", "I386": "x86"}.get(machine, machine or "unknown")

    if not IS_WINDOWS:
        return Architecture(process=process, native=process, emulated=False)

    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        process_machine = ctypes.c_uint16(0)
        native_machine = ctypes.c_uint16(0)
        ok = kernel32.IsWow64Process2(
            kernel32.GetCurrentProcess(),
            ctypes.byref(process_machine),
            ctypes.byref(native_machine),
        )
        if ok:
            native = _MACHINE_NAMES.get(native_machine.value, "unknown")
            # A process machine of 0 means "not running under emulation", in
            # which case the process architecture is the native one.
            if process_machine.value == 0:
                return Architecture(process=native, native=native, emulated=False)
            proc = _MACHINE_NAMES.get(process_machine.value, process)
            return Architecture(process=proc, native=native, emulated=proc != native)
    except (AttributeError, OSError):
        pass  # pre-1511 Windows, or a stub; fall back to the reported values

    return Architecture(process=process, native=process, emulated=False)


# --------------------------------------------------------------------------
# Virtual machine
# --------------------------------------------------------------------------

def hypervisor() -> str:
    """Name the virtual machine this is running in, or an empty string.

    Worth knowing because a VM changes what several findings mean: a snapshot is
    cheap, a locked-out remote session is recoverable from the host, and some
    hardware-backed controls simply are not available to a guest.
    """
    if is_demo() or not IS_WINDOWS:
        return ""
    result = powershell(
        "$c = Get-CimInstance Win32_ComputerSystem; "
        "Write-Output \"$($c.Manufacturer)|$($c.Model)\""
    )
    if not result.ok:
        return ""
    blob = result.text.lower()
    for needle, name in (
        ("vmware", "VMware"),
        ("parallels", "Parallels"),
        ("virtualbox", "VirtualBox"),
        ("qemu", "QEMU/KVM"),
        ("xen", "Xen"),
        ("microsoft corporation|virtual machine", "Hyper-V"),
    ):
        if all(part in blob for part in needle.split("|")):
            return name
    return ""


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def _module_present(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def check_python() -> Check:
    version = sys.version.split()[0]
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 10):
        return Check(
            "Python", State.FAIL, f"{version} is too old",
            "Lares needs Python 3.10 or newer. Install it from python.org, "
            "choosing the build that matches this machine's architecture.",
        )
    return Check("Python", State.OK, f"{version} ({sys.executable})")


def check_architecture() -> Check:
    arch = architecture()
    if arch.emulated:
        return Check(
            "Architecture", State.WARN, arch.describe(),
            "This is an emulated x64 Python on an ARM64 machine. Everything "
            "works, but slowly. Installing native ARM64 Python instead will "
            "make the scan noticeably faster; the trade is that the embedded "
            "model has no prebuilt ARM64 wheel and would need a compiler.",
        )
    return Check("Architecture", State.OK, arch.describe())


def check_platform() -> Check:
    if IS_WINDOWS:
        return Check("Operating system", State.OK, platform.platform())
    return Check(
        "Operating system", State.WARN,
        f"{platform.system()} - Lares runs in demo mode here",
        "The catalogue targets Windows. On this machine every probe returns "
        "synthetic data and nothing will be changed, which is how the interface "
        "is developed and screenshotted.",
    )


def check_elevation() -> Check:
    if is_demo():
        return Check("Privileges", State.OK, "demo mode; elevation is not required")
    if is_elevated():
        return Check("Privileges", State.OK, "running elevated; remediation is available")
    return Check(
        "Privileges", State.WARN, "not elevated; this is a read-only session",
        "Scanning and reporting work fine. Applying fixes needs administrator "
        "rights - start Lares from an elevated prompt, or let the installed "
        "scheduled task run it.",
    )


def check_powershell() -> Check:
    if not IS_WINDOWS:
        return Check("PowerShell", State.WARN, "not applicable off Windows")
    found = shutil.which("powershell") or shutil.which("pwsh")
    if not found:
        return Check(
            "PowerShell", State.FAIL, "no PowerShell interpreter found",
            "Every probe and every remediation is PowerShell. Windows ships "
            "5.1 at System32\\WindowsPowerShell\\v1.0; if it is missing, the "
            "machine needs repairing before Lares can do anything useful.",
        )
    result = powershell("$PSVersionTable.PSVersion.ToString()")
    version = result.text or "unknown version"
    return Check("PowerShell", State.OK, f"{version} at {found}")


def check_gui() -> Check:
    if _module_present("PyQt6"):
        return Check("Desktop application", State.OK, "PyQt6 is installed")
    arch = architecture()
    return Check(
        "Desktop application", State.WARN, "PyQt6 is not installed",
        "The terminal application works without it. For the desktop one, run "
        f"'pip install PyQt6' - wheels are published for {arch.native or 'this'} "
        "architecture, including ARM64.",
    )


def check_model_backend() -> Check:
    """The one check whose answer genuinely differs between x64 and ARM64."""
    if _module_present("llama_cpp"):
        return Check("Model backend", State.OK, "llama-cpp-python is installed")

    arch = architecture()
    if arch.native == "ARM64" and not arch.emulated:
        return Check(
            "Model backend", State.WARN,
            "llama-cpp-python is not installed, and no ARM64 wheel is published",
            "Lares runs fully without it using the built-in planner - it will "
            "scan, decide, fix, verify and roll back exactly the same, it just "
            "will not narrate its reasoning. To get the model as well, build the "
            "backend from source: install Visual Studio Build Tools with the "
            "ARM64 C++ workload and CMake, then 'pip install llama-cpp-python'.",
        )
    return Check(
        "Model backend", State.WARN, "llama-cpp-python is not installed",
        "Lares runs fully without it using the built-in planner. To add the "
        "model, install the prebuilt CPU wheel:\n"
        "  pip install llama-cpp-python "
        "--extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu",
    )


def check_catalog() -> Check:
    try:
        from .catalog import loader
        catalog = loader.load()
    except Exception as exc:  # noqa: BLE001
        return Check(
            "Control catalogue", State.FAIL, f"failed to load: {exc}",
            "The catalogue is the only thing Lares is allowed to execute. If it "
            "will not load, nothing runs. This is almost always a broken YAML "
            "edit; the message above names the file and the control.",
        )
    return Check(
        "Control catalogue", State.OK,
        f"{len(catalog)} controls across {len(catalog.domains)} domains "
        f"(digest {catalog.digest[:12]})",
    )


def check_storage() -> Check:
    try:
        path = data_dir()
        probe = path / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return Check(
            "Storage", State.FAIL, f"cannot write to the data directory: {exc}",
            "Lares keeps its settings, journal, logs and model here. Without "
            "write access it cannot record what it did, which means it must not "
            "be allowed to change anything.",
        )
    return Check("Storage", State.OK, str(path))


def check_virtualisation() -> Check:
    name = hypervisor()
    if not name:
        return Check("Virtual machine", State.OK, "running on hardware, or not detected")
    return Check(
        "Virtual machine", State.OK, f"{name} guest",
        "Take a snapshot before the first run with changes enabled. It is the "
        "cheapest possible undo and it covers the cases the rollback journal "
        "cannot, such as a change that needs a restart to reveal its effect.",
    )


def run() -> list[Check]:
    """Every check, in the order a person would want to read them."""
    return [
        check_platform(),
        check_architecture(),
        check_python(),
        check_powershell(),
        check_elevation(),
        check_storage(),
        check_catalog(),
        check_gui(),
        check_model_backend(),
        check_virtualisation(),
    ]


def worst(checks: list[Check]) -> State:
    if any(c.state is State.FAIL for c in checks):
        return State.FAIL
    if any(c.state is State.WARN for c in checks):
        return State.WARN
    return State.OK


def verdict(checks: list[Check]) -> str:
    state = worst(checks)
    if state is State.FAIL:
        return "Lares cannot run correctly on this machine yet."
    if state is State.WARN:
        return "Lares will run, with the limitations noted above."
    return "Everything Lares needs is present."
