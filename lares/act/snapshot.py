"""Capturing enough state to undo a change even if the rollback script fails.

Every control carries a rollback script, and that is the primary way a change
gets undone. This module is the second line: a literal copy of the state the
remediation is about to touch, taken before it runs.

Why both? A rollback script encodes what we *believe* the change did. A snapshot
records what was actually there. When a remediation half-succeeds - the registry
value written but the service edit failed - the script's assumption is wrong and
the export is the only accurate record.

What gets captured is derived from the remediation body itself: the registry
paths it mentions are exported with reg.exe, and if it touches firewall or
service configuration those are dumped too. A System Restore point is attempted
once per cycle as a coarse backstop, but it is best-effort - restore points are
disabled on a large fraction of real machines and rate-limited on the rest.

Two things this module does **not** do, said here because the paragraph above
used to imply both. Nothing restores a snapshot automatically: the .reg files
are evidence and a manual recovery path, and the rollback script is what runs.
And a snapshot that captured some of what it went looking for is still a
partial snapshot - ``Snapshot.complete`` is the field that says which, and the
executor records it rather than treating "we got one key out of three" as a
success.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..winsys import IS_WINDOWS, is_demo, powershell, run, state_dir

#: Registry roots as they appear in PowerShell paths, mapped to reg.exe names.
_HIVES = {
    "HKLM": "HKLM", "HKEY_LOCAL_MACHINE": "HKLM",
    "HKCU": "HKCU", "HKEY_CURRENT_USER": "HKCU",
    "HKCR": "HKCR", "HKEY_CLASSES_ROOT": "HKCR",
    "HKU": "HKU", "HKEY_USERS": "HKU",
}

_REG_PATH = re.compile(
    r"\b(HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)"
    r":?\\([^\s'\"`,)\]}]+)",
    re.IGNORECASE,
)

_FIREWALL = re.compile(r"\b(Set-NetFirewall|New-NetFirewall|Remove-NetFirewall|netsh\s+advfirewall)", re.I)
_SERVICE = re.compile(r"\b(Set-Service|Stop-Service|Start-Service|sc\.exe|CurrentControlSet\\Services)", re.I)
_DEFENDER = re.compile(r"\b(Set-MpPreference|Add-MpPreference|Remove-MpPreference)", re.I)

#: Keep this many snapshot directories before pruning the oldest.
KEEP = 60


@dataclass
class Snapshot:
    """A directory of captured state, plus what we managed to capture."""

    snapshot_id: str
    directory: Path
    captured: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    restore_point: bool = False

    @property
    def ok(self) -> bool:
        """True when something usable was captured, or there was nothing to capture."""
        return bool(self.captured) or not self.failures

    @property
    def complete(self) -> bool:
        """True when everything it went looking for was captured.

        Distinct from ``ok`` on purpose. A snapshot that got one registry key
        out of three is usable - better than nothing, and the change should
        still go ahead - but it is not the record the operator would assume
        from a line that says the state was captured. Proceeding is right;
        saying so as though it were complete is not.
        """
        return not self.failures

    def summary(self) -> str:
        if not self.captured and not self.failures:
            return "nothing needed capturing"
        parts = [f"captured {', '.join(self.captured)}"] if self.captured else []
        if self.failures:
            parts.append(f"could not capture {', '.join(self.failures)}")
        return "; ".join(parts)


def registry_paths(script: str) -> list[str]:
    """Registry keys a script mentions, as reg.exe-style paths.

    Deliberately over-captures: a path that appears in a comment or in a
    conditional branch that will not execute still gets exported. Exporting a
    key we did not need costs a few kilobytes; missing one costs the rollback.
    """
    found: list[str] = []
    for hive, rest in _REG_PATH.findall(script):
        root = _HIVES.get(hive.upper())
        if not root:
            continue
        key = rest.rstrip("\\").strip()
        if not key:
            continue
        path = f"{root}\\{key}"
        if path not in found:
            found.append(path)
    return found


def _safe_name(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", path)[:120]


#: Distinguishes snapshots taken inside the same second.
_sequence = 0


def take(script: str, label: str = "") -> Snapshot:
    """Capture whatever state *script* is about to modify.

    Never raises. A snapshot that cannot be written is reported as a failure so
    the executor refuses that one action; letting an OSError out of here would
    end the whole cycle and trip the breaker over a full disk.

    The id carries a counter as well as a timestamp because two changes to the
    same control inside one second would otherwise share a directory and the
    second would overwrite the first's captured state.
    """
    global _sequence
    _sequence += 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    suffix = _safe_name(label) if label else "change"
    snapshot_id = f"{stamp}-{_sequence:03d}-{suffix}"
    directory = state_dir("snapshots") / snapshot_id

    try:
        directory.mkdir(parents=True, exist_ok=True)
        snap = Snapshot(snapshot_id=snapshot_id, directory=directory)
        (directory / "script.ps1").write_text(script, encoding="utf-8")
    except OSError as exc:
        snap = Snapshot(snapshot_id=snapshot_id, directory=directory)
        snap.failures.append(f"could not write the snapshot directory: {exc}")
        return snap

    if is_demo():
        snap.captured.append("demo (nothing real to capture)")
        return snap

    for path in registry_paths(script):
        target = directory / f"reg_{_safe_name(path)}.reg"
        result = run(["reg.exe", "export", path, str(target), "/y"], timeout=30)
        if result.ok and target.exists():
            snap.captured.append(f"registry {path}")
        elif "unable to find" in (result.stderr + result.stdout).lower():
            # The key does not exist yet. That is itself the state to restore
            # to, and the rollback scripts handle it via their -1 sentinel.
            (directory / f"absent_{_safe_name(path)}.txt").write_text(path, encoding="utf-8")
            snap.captured.append(f"registry {path} (absent)")
        else:
            snap.failures.append(f"registry {path}")

    if _FIREWALL.search(script):
        _capture(snap, "firewall", "Get-NetFirewallProfile | ConvertTo-Json -Depth 4",
                 "firewall_profiles.json")
        _capture(snap, "firewall rules",
                 "Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile "
                 "| ConvertTo-Json -Depth 4 -Compress", "firewall_rules.json")

    if _SERVICE.search(script):
        _capture(snap, "services",
                 "Get-CimInstance Win32_Service | Select-Object Name,StartMode,State,PathName "
                 "| ConvertTo-Json -Depth 4 -Compress", "services.json")

    if _DEFENDER.search(script):
        _capture(snap, "defender preferences",
                 "Get-MpPreference | ConvertTo-Json -Depth 4 -Compress", "defender.json")

    try:
        _prune()
    except OSError:
        pass          # housekeeping failing is not a reason to refuse a change
    return snap


def _capture(snap: Snapshot, label: str, script: str, filename: str) -> None:
    result = powershell(script, timeout=60)
    if result.ok and result.stdout.strip():
        (snap.directory / filename).write_text(result.stdout, encoding="utf-8")
        snap.captured.append(label)
    else:
        snap.failures.append(label)


def protection_enabled() -> bool:
    """Whether System Protection is on for the system drive.

    Asked first because it is off by default on most consumer installs, and
    Checkpoint-Computer on a machine where it is off spends its whole timeout
    finding that out. One cheap question saves up to three minutes per cycle
    in what is, on this hardware, the common case.
    """
    if is_demo() or not IS_WINDOWS:
        return False
    result = powershell(
        "(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | "
        "Measure-Object).Count -ge 0 -and "
        "((Get-CimInstance -Namespace root/default -ClassName SystemRestore "
        "-ErrorAction Stop | Measure-Object).Count -ge 0)",
        timeout=30,
    )
    return result.ok


def restore_point(description: str = "Lares hardening") -> bool:
    """Attempt a System Restore point. Best effort; never blocks a cycle.

    System Protection is off by default on many consumer installs and Windows
    rate-limits checkpoints to one per 24 hours, so failure here is the normal
    case rather than an exception. The per-key registry exports are what the
    rollback actually relies on.
    """
    if is_demo() or not IS_WINDOWS:
        return False
    if not protection_enabled():
        return False
    result = powershell(
        "Checkpoint-Computer -Description '" + description.replace("'", "") + "' "
        "-RestorePointType 'MODIFY_SETTINGS'",
        timeout=180,
    )
    return result.ok


def _prune() -> None:
    root = state_dir("snapshots")
    try:
        directories = sorted(
            (d for d in root.iterdir() if d.is_dir()),
            key=lambda d: d.name,
        )
    except OSError:
        return
    for stale in directories[:-KEEP]:
        shutil.rmtree(stale, ignore_errors=True)
