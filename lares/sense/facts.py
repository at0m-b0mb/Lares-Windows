"""What kind of machine is this?

Facts are context, not findings. Nothing here is graded. Their job is to let the
model reason about whether a control is even relevant - a laptop that travels is
a different risk picture from a desktop that never leaves a locked office, and
Home edition simply does not have some of the settings Pro does.

They also decide which language model tier the machine can run, which is why
memory and core count are collected even though no control looks at them.

One PowerShell round trip gathers everything. Thirty separate invocations on a
four-core laptop with a spinning disk is most of a minute, and this runs at the
start of every cycle.
"""

from __future__ import annotations

import os
import platform
import shutil

from ..core import Fact
from ..winsys import current_user, is_elevated, powershell

_GATHER = r"""
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$cpu  = @(Get-CimInstance Win32_Processor)[0]
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"

$secureBoot = 'unknown'
try { $secureBoot = if (Confirm-SecureBootUEFI) { 'Enabled' } else { 'Disabled' } } catch { $secureBoot = 'not supported' }

$tpm = 'not present'
try {
  $t = Get-Tpm -ErrorAction Stop
  if ($t.TpmPresent) { $tpm = "$($t.TpmVersion), $(if ($t.TpmReady) { 'ready' } else { 'not ready' })" }
} catch { }

$net = $null
try { $net = Get-NetConnectionProfile -ErrorAction Stop | Select-Object -First 1 } catch { }

$listen = @()
try { $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch { }
$anyIface = @($listen | Where-Object { $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' })

$admins = @()
try { $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { ("$($_.Name)" -split '\\')[-1] }) } catch { }

$users = @()
try { $users = @(Get-LocalUser -ErrorAction Stop) } catch { }

$hotfix = $null
try { $hotfix = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 } catch { }

$apps = 0
try {
  $apps = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
            -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }).Count
} catch { }

$av = 'unknown'
try { if ((Get-MpComputerStatus -ErrorAction Stop).AMServiceEnabled) { $av = 'Microsoft Defender' } } catch { }

[pscustomobject]@{
  hostname    = $env:COMPUTERNAME
  caption     = $os.Caption
  version     = "$($os.Version) ($((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion))"
  arch        = $os.OSArchitecture
  installed   = if ($os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd') } else { 'unknown' }
  lastBoot    = if ($os.LastBootUpTime) { [int]((Get-Date) - $os.LastBootUpTime).TotalDays } else { -1 }
  domain      = if ($cs.PartOfDomain) { "Yes ($($cs.Domain))" } else { "No (workgroup $($cs.Workgroup))" }
  chassis     = "$($cs.Manufacturer) $($cs.Model)"
  cpuName     = $cpu.Name
  cores       = $cpu.NumberOfCores
  threads     = $cpu.NumberOfLogicalProcessors
  memoryGB    = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
  diskGB      = [math]::Round($disk.Size / 1GB, 0)
  freeGB      = [math]::Round($disk.FreeSpace / 1GB, 0)
  secureBoot  = $secureBoot
  tpm         = $tpm
  netName     = if ($net) { "$($net.InterfaceAlias), profile $($net.NetworkCategory)" } else { 'no active connection' }
  listening   = $listen.Count
  anyIface    = $anyIface.Count
  adminCount  = $admins.Count
  adminNames  = ($admins -join ', ')
  userTotal   = $users.Count
  userEnabled = @($users | Where-Object { $_.Enabled }).Count
  lastPatch   = if ($hotfix) { "$($hotfix.HotFixID), $([int]((Get-Date) - $hotfix.InstalledOn).TotalDays) days ago" } else { 'unknown' }
  appCount    = $apps
  antivirus   = $av
} | ConvertTo-Json -Depth 4 -Compress
"""


def gather(timeout: int = 90) -> list[Fact]:
    """Collect system context from the live machine.

    Falls back to what Python itself can see if the PowerShell pass fails, so a
    scan still carries some context rather than none.
    """
    data = powershell(_GATHER, timeout=timeout).json(default=None)
    if not isinstance(data, dict):
        return _fallback()

    def text(key: str, default: str = "unknown") -> str:
        value = data.get(key)
        if value is None or value == "":
            return default
        return str(value)

    boot_days = data.get("lastBoot", -1)
    boot = f"{boot_days} days ago" if isinstance(boot_days, int) and boot_days >= 0 else "unknown"

    facts = [
        Fact("Host name", text("hostname"), "system", True),
        Fact("Operating system", text("caption"), "system"),
        Fact("Version", text("version"), "system"),
        Fact("Architecture", text("arch"), "system"),
        Fact("Installed", text("installed"), "system"),
        Fact("Last restart", boot, "system"),
        Fact("Domain joined", text("domain"), "system"),

        Fact("Signed in as", current_user(), "identity", True),
        Fact("Running elevated", "Yes" if is_elevated() else "No", "identity"),
        Fact("Local administrators",
             f"{text('adminCount', '?')} ({text('adminNames', 'unreadable')})", "identity"),
        Fact("Local accounts",
             f"{text('userTotal', '?')} total, {text('userEnabled', '?')} enabled", "identity"),

        Fact("Model", text("chassis"), "hardware", True),
        Fact("Processor",
             f"{text('cpuName')}, {text('cores', '?')} cores / {text('threads', '?')} threads",
             "hardware"),
        Fact("Memory", f"{text('memoryGB', '?')} GB", "hardware"),
        Fact("System drive",
             f"{text('diskGB', '?')} GB, {text('freeGB', '?')} GB free", "hardware"),
        Fact("Secure Boot", text("secureBoot"), "hardware"),
        Fact("TPM", text("tpm"), "hardware"),

        Fact("Active network", text("netName"), "network"),
        Fact("Listening TCP ports",
             f"{text('listening', '?')} ({text('anyIface', '?')} on all interfaces)", "network"),

        Fact("Installed software", f"{text('appCount', '?')} packages", "software"),
        Fact("Last update installed", text("lastPatch"), "software"),
        Fact("Antivirus", text("antivirus"), "defence"),
    ]
    return facts


def _fallback() -> list[Fact]:
    """Context from Python alone, when the PowerShell pass did not work."""
    try:
        usage = shutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\")
        disk = f"{usage.total // 2**30} GB, {usage.free // 2**30} GB free"
    except OSError:
        disk = "unknown"
    return [
        Fact("Host name", platform.node(), "system", True),
        Fact("Operating system", platform.platform(), "system"),
        Fact("Architecture", platform.machine(), "system"),
        Fact("Signed in as", current_user(), "identity", True),
        Fact("Running elevated", "Yes" if is_elevated() else "No", "identity"),
        Fact("Processor", platform.processor() or "unknown", "hardware"),
        Fact("Logical processors", str(os.cpu_count() or "unknown"), "hardware"),
        Fact("System drive", disk, "hardware"),
        Fact("Context collection", "PowerShell pass failed; limited context", "system"),
    ]
