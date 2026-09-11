"""Which model this machine can actually run, and where to get it.

Lares is meant to work on the tired four-year-old laptop that most needs
hardening, not on a workstation with a GPU. So there is no single model: there
is a ladder, and the machine is measured before one is picked.

Why Qwen2.5-Coder across the whole ladder
-----------------------------------------
The job the model does here is not recalling security trivia - the security
facts come from the catalogue through retrieval, which is far more reliable than
anything a 1.5B model remembers. The job is reading a scan, choosing controls,
filling in parameters, and emitting strictly-shaped JSON without drifting. That
is a code-shaped task, and Qwen2.5-Coder is the strongest open family at that
size. It also has real PowerShell in its training mix, which matters for the
Expert lane where it writes script rather than selecting it.

Everything is GGUF at Q4_K_M, which is the quantisation where quality loss is
still small and a 3B model fits in about two gigabytes of RAM.

Checksums
---------
No hash is shipped for a file this repository does not host. On first download
Lares records the hash it received, prints it so it can be compared against the
model card, and pins it locally. Every later load verifies against that pin, so
a file swapped afterwards is caught even though the first fetch is trust-on-
first-use. Set ``sha256`` in a registry entry to make the first fetch strict too.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..winsys import IS_WINDOWS, data_dir, powershell, write_json_atomic


@dataclass(frozen=True)
class ModelSpec:
    """One rung on the ladder."""

    key: str
    name: str
    #: Hugging Face repository and filename.
    repo: str
    filename: str
    #: Approximate on-disk size, for the download prompt and the disk check.
    size_mb: int
    #: Total system memory, in GB, below which this rung is not offered.
    min_ram_gb: float
    #: Physical cores below which this rung is not offered.
    min_cores: int
    #: Context window to open. Smaller is dramatically faster on weak CPUs.
    context: int
    #: Rough tokens per second on a 4-core laptop CPU, for expectation setting.
    expect_tps: str
    #: Pin a known-good hash here to make even the first download strict.
    sha256: str = ""
    note: str = ""

    @property
    def url(self) -> str:
        return f"https://huggingface.co/{self.repo}/resolve/main/{self.filename}"

    @property
    def path(self) -> Path:
        return models_dir() / self.filename


#: Ordered strongest first. Selection walks down until one fits.
LADDER: tuple[ModelSpec, ...] = (
    ModelSpec(
        key="7b",
        name="Qwen2.5-Coder 7B Instruct (Q4_K_M)",
        repo="Qwen/Qwen2.5-Coder-7B-Instruct-GGUF",
        filename="qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        size_mb=4700,
        min_ram_gb=15.0,
        min_cores=6,
        context=8192,
        expect_tps="3-6 tokens/s",
        note="Noticeably better at reasoning about which fix to apply first.",
    ),
    ModelSpec(
        key="3b",
        name="Qwen2.5-Coder 3B Instruct (Q4_K_M)",
        repo="Qwen/Qwen2.5-Coder-3B-Instruct-GGUF",
        filename="qwen2.5-coder-3b-instruct-q4_k_m.gguf",
        size_mb=2000,
        min_ram_gb=7.0,
        min_cores=4,
        context=4096,
        expect_tps="6-12 tokens/s",
        note="The default. Best balance of judgement and speed on ordinary laptops.",
    ),
    ModelSpec(
        key="1.5b",
        name="Qwen2.5-Coder 1.5B Instruct (Q4_K_M)",
        repo="Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF",
        filename="qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
        size_mb=1100,
        min_ram_gb=3.5,
        min_cores=2,
        context=4096,
        expect_tps="10-20 tokens/s",
        note="For old hardware. Still reliable at selecting controls; weaker at ordering them.",
    ),
    ModelSpec(
        key="0.5b",
        name="Qwen2.5-Coder 0.5B Instruct (Q4_K_M)",
        repo="Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF",
        filename="qwen2.5-coder-0.5b-instruct-q4_k_m.gguf",
        size_mb=400,
        min_ram_gb=1.5,
        min_cores=1,
        context=2048,
        expect_tps="20-40 tokens/s",
        note="Last resort. Use the built-in planner instead unless memory is very tight.",
    ),
)

BY_KEY = {spec.key: spec for spec in LADDER}
DEFAULT_KEY = "3b"


def models_dir() -> Path:
    path = data_dir() / "models"
    path.mkdir(parents=True, exist_ok=True)
    return path


# --------------------------------------------------------------------------
# Measuring the machine
# --------------------------------------------------------------------------

@dataclass
class Hardware:
    ram_gb: float = 0.0
    physical_cores: int = 0
    logical_cores: int = 0
    free_disk_gb: float = 0.0
    arch: str = ""
    notes: list[str] = field(default_factory=list)

    def describe(self) -> str:
        return (
            f"{self.ram_gb:.1f} GB RAM, {self.physical_cores} physical cores "
            f"({self.logical_cores} logical), {self.free_disk_gb:.0f} GB free"
        )

    @property
    def threads(self) -> int:
        """Threads to give llama.cpp.

        Beyond the physical core count llama.cpp gets slower, not faster, because
        the hyperthread siblings contend for the same vector units. One core is
        also left for the rest of the system so an unattended scan does not make
        the machine unusable for whoever is sitting at it.
        """
        cores = self.physical_cores or self.logical_cores or 2
        return max(1, min(cores - 1, 8)) if cores > 2 else max(1, cores)


def measure() -> Hardware:
    """Read memory, cores and free disk. Works on any platform."""
    hardware = Hardware(arch=platform.machine())
    hardware.logical_cores = os.cpu_count() or 2

    if IS_WINDOWS:
        data = powershell(
            "$cs = Get-CimInstance Win32_ComputerSystem;"
            "$cpu = @(Get-CimInstance Win32_Processor)[0];"
            "[pscustomobject]@{"
            " ram = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2);"
            " cores = $cpu.NumberOfCores;"
            " logical = $cpu.NumberOfLogicalProcessors"
            "} | ConvertTo-Json -Compress",
            timeout=45,
        ).json(default=None)
        if isinstance(data, dict):
            hardware.ram_gb = float(data.get("ram", 0) or 0)
            hardware.physical_cores = int(data.get("cores", 0) or 0)
            hardware.logical_cores = int(data.get("logical", 0) or hardware.logical_cores)

    if not hardware.ram_gb:
        hardware.ram_gb = _ram_fallback()
    if not hardware.physical_cores:
        # Assume hyperthreading rather than pretending every logical core is real;
        # over-estimating cores here makes the machine pick a model it will crawl on.
        hardware.physical_cores = max(1, hardware.logical_cores // 2)
        hardware.notes.append("physical core count estimated from logical cores")

    try:
        hardware.free_disk_gb = shutil.disk_usage(models_dir()).free / 2**30
    except OSError:
        hardware.free_disk_gb = 0.0

    return hardware


def _ram_fallback() -> float:
    """Total RAM without Windows-specific calls, for development hosts."""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        size = os.sysconf("SC_PAGE_SIZE")
        return (pages * size) / 2**30
    except (ValueError, OSError, AttributeError):
        pass
    try:  # macOS
        import subprocess
        out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True,
                             text=True, timeout=5)
        if out.returncode == 0:
            return int(out.stdout.strip()) / 2**30
    except Exception:  # noqa: BLE001
        pass
    return 0.0


# --------------------------------------------------------------------------
# Choosing
# --------------------------------------------------------------------------

@dataclass
class Choice:
    spec: ModelSpec | None
    hardware: Hardware
    reason: str
    #: True when the file is already on disk.
    present: bool = False

    @property
    def ok(self) -> bool:
        return self.spec is not None


def _embedded_spec() -> ModelSpec | None:
    """A spec for the model inside this executable, unpacking it if needed.

    Returns None when this is not a packaged build, when the build carries no
    model, or when unpacking failed - all three of which mean "carry on with
    whatever else is available", never "stop".
    """
    from . import embedded

    payload = embedded.present()
    if payload is None:
        return None

    path = embedded.ensure()
    if path is None:
        return None

    # Prefer the ladder entry with the same filename, so the embedded model
    # inherits its real context length and thread advice rather than a guess.
    for spec in LADDER:
        if spec.filename == payload.name:
            return spec

    return ModelSpec(
        key="embedded",
        name=payload.name.replace(".gguf", ""),
        repo="",
        filename=payload.name,
        size_mb=payload.size_mb,
        min_ram_gb=2,
        min_cores=2,
        context=4096,
        expect_tps="unknown for this build",
        sha256=payload.sha256,
        note="Shipped inside this executable.",
    )


def choose(hardware: Hardware | None = None, prefer: str = "") -> Choice:
    """Pick the best rung this machine can carry.

    An explicit *prefer* key wins even if the hardware is marginal - someone who
    asks for the 7B on an 8 GB laptop is allowed to, they will just wait. The
    automatic path is deliberately conservative, because a model that swaps to
    disk mid-scan is worse than no model at all.
    """
    hardware = hardware or measure()

    # A build that carries its own model uses it, unless a tier was named
    # explicitly. This is the whole point of the single-file executable: it has
    # a model, it does not need to ask the internet for one, and it should not
    # quietly ignore what it is carrying in order to go and download something.
    if not prefer:
        carried = _embedded_spec()
        if carried is not None:
            return Choice(
                carried, hardware,
                f"{carried.name} is embedded in this executable",
                present=True,
            )

    if prefer:
        spec = BY_KEY.get(prefer.lower())
        if spec is None:
            return Choice(None, hardware, f"no such model tier {prefer!r}; "
                                          f"choose from {sorted(BY_KEY)}")
        return Choice(spec, hardware, f"{spec.name} was requested explicitly",
                      present=spec.path.exists())

    for spec in LADDER:
        if hardware.ram_gb and hardware.ram_gb < spec.min_ram_gb:
            continue
        if hardware.physical_cores and hardware.physical_cores < spec.min_cores:
            continue
        present = spec.path.exists()
        if not present and hardware.free_disk_gb and \
                hardware.free_disk_gb * 1024 < spec.size_mb * 1.5:
            continue
        return Choice(
            spec, hardware,
            f"{hardware.describe()} comfortably runs {spec.name}",
            present=present,
        )

    return Choice(
        None, hardware,
        f"{hardware.describe()} is below the smallest model on the ladder. "
        "Lares will use its built-in planner, which needs no model at all.",
    )


def installed() -> list[ModelSpec]:
    return [spec for spec in LADDER if spec.path.exists()]


# --------------------------------------------------------------------------
# Checksum pinning
# --------------------------------------------------------------------------

def _pins_path() -> Path:
    return models_dir() / "pins.json"


def load_pins() -> dict[str, str]:
    try:
        return json.loads(_pins_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_pin(filename: str, digest: str) -> None:
    """Record a model's checksum, atomically.

    A torn pins file parses as empty, which silently downgrades every model on
    the machine from "verified against a known hash" back to trust-on-first-use.
    """
    pins = load_pins()
    pins[filename] = digest
    write_json_atomic(_pins_path(), pins)


def expected_digest(spec: ModelSpec) -> str:
    """The hash this file must have: the shipped pin, else the local one."""
    return spec.sha256 or load_pins().get(spec.filename, "")
