"""What an attacker can see: software, versions, ports, services, accounts.

The catalogue lane answers "is this machine compliant with thirty checks a
person wrote". This answers a different and broader question - "what is on this
machine, and what of it is reachable" - and it answers it without deciding
anything. Nothing here has an opinion about what is wrong. It reads, and what
it read is handed to the model, which is the thing that decides.

That split is the whole point of this module. It exists so the freehand lane
can be honest when it says nothing is hardcoded: the fixed part of that lane is
six read-only scripts that list what is installed and what is listening, and
every judgement made about what they return comes from the model.

Six views, each independent, each allowed to fail on its own:

    system      what this machine is - edition, build, patch level
    software    every installed product and its version
    ports       every listening TCP and UDP socket, and who owns it
    services    every running service, its account and its image path
    accounts    local users, who is an administrator, which are enabled
    exposure    the reachable-from-elsewhere settings: RDP, WinRM, SMB, firewall

A collector that cannot read its view records why and the others carry on. A
survey missing one section is worth far more than no survey, and the model is
told which sections are missing rather than being left to infer it from
silence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import logs
from ..core import utcnow
from ..winsys import IS_WINDOWS, clean_clixml, is_demo, powershell

#: Per-collector ceiling. A machine with four hundred installed products is a
#: real thing, and neither a 4k context window nor a person reading a terminal
#: benefits from all four hundred.
DEFAULT_ROWS = 60

#: One collector must not be able to hang a survey.
TIMEOUT = 90

Progress = Callable[[str], None]


@dataclass
class Section:
    """One view of the machine, and whether reading it worked."""

    key: str
    title: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    #: Set when the collector could not read this view at all.
    error: str = ""
    #: Set when it read it, but something about the reading is worth saying.
    note: str = ""
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class Surface:
    """Everything read off the machine in one pass."""

    sections: list[Section] = field(default_factory=list)
    at: str = field(default_factory=utcnow)
    demo: bool = False
    duration_ms: int = 0

    def get(self, key: str) -> Section | None:
        for section in self.sections:
            if section.key == key:
                return section
        return None

    def rows(self, key: str) -> list[dict[str, Any]]:
        section = self.get(key)
        return section.rows if section else []

    @property
    def failures(self) -> list[Section]:
        return [s for s in self.sections if s.error]

    def render(self, *, limit: int = DEFAULT_ROWS, budget: int = 0,
               only: list[str] | None = None) -> str:
        """The survey as text for the model.

        *budget* is a character ceiling for the whole thing. Sections are
        trimmed from the bottom of each list rather than dropped entirely,
        because a model told "42 listening ports" and shown three of them can
        still reason about the three; a model shown nothing cannot reason at
        all, and a model shown no heading does not know it is missing anything.

        *only* narrows it to named sections. Asking for the code that fixes one
        service does not need the installed software list, and on a 4k window
        the space that list takes is space the fix has to be written in.
        """
        cap = limit
        while True:
            text = self._render_at(cap, only)
            if not budget or len(text) <= budget or cap <= 5:
                return text
            cap = max(5, cap // 2)

    def _render_at(self, limit: int, only: list[str] | None = None) -> str:
        wanted = {k.strip().lower() for k in only} if only else None
        blocks: list[str] = []
        for section in self.sections:
            if wanted is not None and section.key not in wanted:
                continue
            head = f"== {section.title} =="
            if section.error:
                blocks.append(f"{head}\n  (could not be read: {section.error})")
                continue
            if not section.rows:
                blocks.append(f"{head}\n  (nothing found)")
                continue
            lines = [_line(section.key, row) for row in section.rows[:limit]]
            if len(section.rows) > limit:
                lines.append(f"  ... and {len(section.rows) - limit} more")
            if section.note:
                lines.append(f"  note: {section.note}")
            blocks.append(head + "\n" + "\n".join(lines))
        return "\n\n".join(blocks)

    def headline(self) -> str:
        """One line per section, for a person watching it run."""
        parts = []
        for section in self.sections:
            if section.error:
                parts.append(f"{section.key}: unavailable")
            else:
                parts.append(f"{section.key}: {len(section.rows)}")
        return ", ".join(parts)


def _line(key: str, row: dict[str, Any]) -> str:
    """One row, as a line the model can read without a schema."""
    if key == "software":
        version = row.get("version") or "unknown version"
        publisher = row.get("publisher") or ""
        tail = f"  [{publisher}]" if publisher else ""
        return f"  {row.get('name', '?')}  {version}{tail}"
    if key == "ports":
        reach = "REACHABLE FROM THE NETWORK" if row.get("exposed") else "localhost only"
        owner = row.get("process") or f"pid {row.get('pid', '?')}"
        return (f"  {row.get('proto', '?')}/{row.get('port', '?')} "
                f"on {row.get('address', '?')} - {owner} - {reach}")
    if key == "services":
        flag = "  UNQUOTED PATH" if row.get("unquoted") else ""
        return (f"  {row.get('name', '?')} ({row.get('start', '?')}) as "
                f"{row.get('account', '?')} - {row.get('path', '')}{flag}")
    if key == "accounts":
        bits = [row.get("name", "?")]
        bits.append("enabled" if row.get("enabled") else "disabled")
        if row.get("admin"):
            bits.append("ADMINISTRATOR")
        if row.get("never_expires"):
            bits.append("password never expires")
        if row.get("last_logon"):
            bits.append(f"last logon {row['last_logon']}")
        return "  " + " - ".join(str(b) for b in bits)
    pairs = ", ".join(f"{k}={v}" for k, v in row.items() if v not in ("", None))
    return f"  {pairs}"


# --------------------------------------------------------------------------
# The collectors. Read-only, every one of them.
# --------------------------------------------------------------------------

SYSTEM_PS = r"""
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR
$rows = @()
$rows += [pscustomobject]@{ item = 'edition';   value = $os.Caption }
$rows += [pscustomobject]@{ item = 'version';   value = "$($os.Version).$ubr" }
$rows += [pscustomobject]@{ item = 'installed'; value = $os.InstallDate }
$rows += [pscustomobject]@{ item = 'booted';    value = $os.LastBootUpTime }
$rows += [pscustomobject]@{ item = 'domain';    value = $cs.Domain }
$rows += [pscustomobject]@{ item = 'joined';    value = $cs.PartOfDomain }
$rows += [pscustomobject]@{ item = 'model';     value = "$($cs.Manufacturer) $($cs.Model)" }
$rows += [pscustomobject]@{ item = 'memory_gb'; value = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) }
$rows | ConvertTo-Json -Depth 3 -Compress
"""

SOFTWARE_PS = r"""
$keys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$found = @()
foreach ($key in $keys) {
  $found += Get-ItemProperty $key -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and -not $_.SystemComponent }
}
$found |
  Select-Object @{n='name';e={$_.DisplayName}},
                @{n='version';e={$_.DisplayVersion}},
                @{n='publisher';e={$_.Publisher}} |
  Sort-Object name -Unique |
  ConvertTo-Json -Depth 3 -Compress
"""

PORTS_PS = r"""
$rows = @()
try {
  foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
    $name = ''
    try { $name = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch { }
    $rows += [pscustomobject]@{
      proto = 'TCP'; port = $c.LocalPort; address = $c.LocalAddress
      process = $name; pid = $c.OwningProcess
    }
  }
  foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
    $name = ''
    try { $name = (Get-Process -Id $u.OwningProcess -ErrorAction Stop).ProcessName } catch { }
    $rows += [pscustomobject]@{
      proto = 'UDP'; port = $u.LocalPort; address = $u.LocalAddress
      process = $name; pid = $u.OwningProcess
    }
  }
} catch {
  # Get-NetTCPConnection is missing on a few stripped-down builds. netstat has
  # been on every Windows since NT and says the same thing in worse prose.
  foreach ($line in (netstat -ano)) {
    if ($line -match '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+\S+\s+(LISTENING\s+)?(\d+)\s*$') {
      $rows += [pscustomobject]@{
        proto = $matches[1]; port = [int]$matches[3]; address = $matches[2]
        process = ''; pid = [int]$matches[5]
      }
    }
  }
}
$rows | Sort-Object proto, port -Unique | ConvertTo-Json -Depth 3 -Compress
"""

SERVICES_PS = r"""
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Running' } |
  Select-Object @{n='name';e={$_.Name}},
                @{n='display';e={$_.DisplayName}},
                @{n='start';e={$_.StartMode}},
                @{n='account';e={$_.StartName}},
                @{n='path';e={$_.PathName}} |
  Sort-Object name |
  ConvertTo-Json -Depth 3 -Compress
"""

ACCOUNTS_PS = r"""
$admins = @()
try {
  $admins = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
             ForEach-Object { ($_.Name -split '\\')[-1] })
} catch { }
$rows = @()
try {
  foreach ($u in (Get-LocalUser -ErrorAction Stop)) {
    $rows += [pscustomobject]@{
      name = $u.Name
      enabled = [bool]$u.Enabled
      admin = [bool]($admins -contains $u.Name)
      never_expires = [bool]$u.PasswordNeverExpires
      last_logon = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd') } else { '' }
    }
  }
} catch {
  foreach ($u in (Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) {
    $rows += [pscustomobject]@{
      name = $u.Name; enabled = (-not $u.Disabled)
      admin = [bool]($admins -contains $u.Name)
      never_expires = [bool]$u.PasswordExpires -eq $false; last_logon = ''
    }
  }
}
$rows | ConvertTo-Json -Depth 3 -Compress
"""

EXPOSURE_PS = r"""
function Reg($path, $name) {
  try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { return $null }
}
$rows = @()
$deny = Reg 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$rows += [pscustomobject]@{ setting = 'remote desktop'; value = $(if ($deny -eq 0) { 'ENABLED' } else { 'disabled' }) }
$nla = Reg 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
$rows += [pscustomobject]@{ setting = 'rdp network level auth'; value = $(if ($nla -eq 1) { 'required' } else { 'NOT REQUIRED' }) }
$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
$rows += [pscustomobject]@{ setting = 'winrm service'; value = $(if ($winrm) { $winrm.Status } else { 'absent' }) }
try {
  $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
  $rows += [pscustomobject]@{ setting = 'smbv1'; value = $(if ($smb1) { 'ENABLED' } else { 'disabled' }) }
  $signing = (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature
  $rows += [pscustomobject]@{ setting = 'smb signing required'; value = "$signing" }
} catch { }
try {
  foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
    $rows += [pscustomobject]@{ setting = "firewall $($p.Name.ToLower())"; value = $(if ($p.Enabled) { 'on' } else { 'OFF' }) }
  }
} catch { }
$uac = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
$rows += [pscustomobject]@{ setting = 'uac'; value = $(if ($uac -eq 1) { 'on' } else { 'OFF' }) }
$auto = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
$rows += [pscustomobject]@{ setting = 'automatic logon'; value = $(if ("$auto" -eq '1') { 'ON' } else { 'off' }) }
$llmnr = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
$rows += [pscustomobject]@{ setting = 'llmnr'; value = $(if ($llmnr -eq 0) { 'off' } else { 'ON' }) }
try {
  $av = Get-MpComputerStatus -ErrorAction Stop
  $rows += [pscustomobject]@{ setting = 'defender real-time'; value = "$($av.RealTimeProtectionEnabled)" }
  $rows += [pscustomobject]@{ setting = 'defender signatures'; value = "$($av.AntivirusSignatureAge) days old" }
} catch { }
try {
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $rows += [pscustomobject]@{ setting = 'system drive encryption'; value = "$($bl.ProtectionStatus)" }
} catch { }
$rows | ConvertTo-Json -Depth 3 -Compress
"""

#: (key, title, script). Order is the order a person reads them in, and the
#: order the model is shown them: what the machine is, then what is on it,
#: then what of that is reachable.
COLLECTORS: tuple[tuple[str, str, str], ...] = (
    ("system", "What this machine is", SYSTEM_PS),
    ("software", "Installed software and versions", SOFTWARE_PS),
    ("ports", "Listening ports", PORTS_PS),
    ("services", "Running services", SERVICES_PS),
    ("accounts", "Local accounts", ACCOUNTS_PS),
    ("exposure", "Reachable settings", EXPOSURE_PS),
)


def survey(*, progress: Progress | None = None,
           only: list[str] | None = None) -> Surface:
    """Read every view of the machine. Changes nothing."""
    import time

    started = time.monotonic()
    result = Surface(demo=is_demo())
    wanted = {k.strip().lower() for k in only} if only else None

    for key, title, script in COLLECTORS:
        if wanted is not None and key not in wanted:
            continue
        if progress:
            progress(f"reading {title.lower()}")
        result.sections.append(_collect(key, title, script))

    result.duration_ms = int((time.monotonic() - started) * 1000)
    logs.get().info("scan", "Attack surface surveyed", detail=result.headline())
    return result


def _collect(key: str, title: str, script: str) -> Section:
    """Run one collector and shape what it returned."""
    import time

    started = time.monotonic()
    section = Section(key=key, title=title)

    if is_demo() or not IS_WINDOWS:
        section.rows = [dict(row) for row in DEMO_ROWS.get(key, [])]
        section.note = "synthetic: this is demonstration data, not this machine"
        _enrich(section)
        return section

    result = powershell(script, timeout=TIMEOUT)
    section.seconds = time.monotonic() - started

    if not result.ok and not result.stdout.strip():
        section.error = clean_clixml(result.error or result.stderr)[:200] or "no output"
        logs.get().warn("scan", f"Surface collector {key} failed",
                        detail=section.error)
        return section

    payload = result.json(default=None)
    if payload is None:
        section.error = "the reading was not usable JSON"
        return section
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        section.error = f"unexpected shape: {type(payload).__name__}"
        return section

    section.rows = [row for row in payload if isinstance(row, dict)]
    _enrich(section)
    return section


def _note(section: Section, text: str) -> None:
    """Add a note without losing one already there.

    The synthetic-data warning is set before enrichment runs, and a derived
    note that replaced it would take a demonstration survey and quietly stop
    saying it was a demonstration.
    """
    section.note = f"{section.note}; {text}" if section.note else text


#: A path an attacker can hijack: an unquoted service image path with a space
#: in it, where Windows will try C:\Program.exe before C:\Program Files\...
_UNQUOTED = re.compile(r'^[^"]*\s[^"]*\.exe', re.IGNORECASE)


def _enrich(section: Section) -> None:
    """Add the derived fields the model should not have to work out itself.

    This is the line worth being careful about, because it is the one place in
    this module that could turn into a hardcoded opinion. It does not decide
    anything is wrong. "This socket is bound to 0.0.0.0" and "this path has a
    space and no quotes" are facts about the reading, no different from the
    port number - the model is still the only thing that says whether either
    matters here.
    """
    if section.key == "ports":
        for row in section.rows:
            address = str(row.get("address", ""))
            row["exposed"] = address in ("0.0.0.0", "::", "*") or address.startswith("0.0.0.0")
        exposed = sum(1 for r in section.rows if r.get("exposed"))
        _note(section, f"{exposed} of {len(section.rows)} are bound to every interface")

    elif section.key == "services":
        for row in section.rows:
            path = str(row.get("path", "")).strip()
            row["unquoted"] = bool(path) and not path.startswith('"') and bool(_UNQUOTED.match(path))

    elif section.key == "accounts":
        admins = sum(1 for r in section.rows if r.get("admin"))
        _note(section, f"{admins} of {len(section.rows)} are administrators")


# --------------------------------------------------------------------------
# What the survey looks like where there is no Windows to survey
# --------------------------------------------------------------------------

#: Used in demo mode and on any non-Windows machine, so the lane can be
#: developed, tested and demonstrated off a Windows box. It is plainly labelled
#: as synthetic everywhere it appears - a tool that shows invented findings
#: without saying so is worse than one that shows nothing.
DEMO_ROWS: dict[str, list[dict[str, Any]]] = {
    "system": [
        {"item": "edition", "value": "Microsoft Windows 11 Pro"},
        {"item": "version", "value": "10.0.22631.3737"},
        {"item": "installed", "value": "2024-11-02"},
        {"item": "domain", "value": "WORKGROUP"},
        {"item": "joined", "value": "False"},
        {"item": "memory_gb", "value": "8"},
    ],
    "software": [
        {"name": "7-Zip 19.00", "version": "19.00", "publisher": "Igor Pavlov"},
        {"name": "Google Chrome", "version": "109.0.5414.120", "publisher": "Google LLC"},
        {"name": "Mozilla Firefox", "version": "115.3.1", "publisher": "Mozilla"},
        {"name": "Notepad++", "version": "8.4.7", "publisher": "Notepad++ Team"},
        {"name": "OpenSSH for Windows", "version": "8.1.0.1", "publisher": "OpenSSH"},
        {"name": "Python 3.9.7", "version": "3.9.7150.0", "publisher": "Python Software Foundation"},
        {"name": "VMware Tools", "version": "12.3.5", "publisher": "VMware, Inc."},
    ],
    "ports": [
        {"proto": "TCP", "port": 135, "address": "0.0.0.0", "process": "svchost", "pid": 968},
        {"proto": "TCP", "port": 139, "address": "0.0.0.0", "process": "System", "pid": 4},
        {"proto": "TCP", "port": 445, "address": "0.0.0.0", "process": "System", "pid": 4},
        {"proto": "TCP", "port": 3389, "address": "0.0.0.0", "process": "svchost", "pid": 1284},
        {"proto": "TCP", "port": 5985, "address": "0.0.0.0", "process": "System", "pid": 4},
        {"proto": "TCP", "port": 22, "address": "0.0.0.0", "process": "sshd", "pid": 3312},
        {"proto": "TCP", "port": 49664, "address": "0.0.0.0", "process": "lsass", "pid": 720},
        {"proto": "UDP", "port": 5353, "address": "0.0.0.0", "process": "svchost", "pid": 1600},
        {"proto": "UDP", "port": 5355, "address": "0.0.0.0", "process": "svchost", "pid": 1600},
        {"proto": "TCP", "port": 8080, "address": "127.0.0.1", "process": "node", "pid": 7712},
    ],
    "services": [
        {"name": "Spooler", "display": "Print Spooler", "start": "Auto",
         "account": "LocalSystem", "path": "C:\\Windows\\System32\\spoolsv.exe"},
        {"name": "TermService", "display": "Remote Desktop Services", "start": "Manual",
         "account": "NT Authority\\NetworkService",
         "path": "C:\\Windows\\System32\\svchost.exe -k NetworkService"},
        {"name": "VulnAgent", "display": "Vendor Update Agent", "start": "Auto",
         "account": "LocalSystem", "path": "C:\\Program Files\\Vendor Agent\\agent.exe -run"},
        {"name": "sshd", "display": "OpenSSH SSH Server", "start": "Auto",
         "account": "LocalSystem", "path": "C:\\Windows\\System32\\OpenSSH\\sshd.exe"},
    ],
    "accounts": [
        {"name": "Administrator", "enabled": False, "admin": True,
         "never_expires": True, "last_logon": ""},
        {"name": "Guest", "enabled": True, "admin": False,
         "never_expires": True, "last_logon": ""},
        {"name": "kai", "enabled": True, "admin": True,
         "never_expires": True, "last_logon": "2026-09-09"},
        {"name": "svc-backup", "enabled": True, "admin": True,
         "never_expires": True, "last_logon": "2025-02-14"},
    ],
    "exposure": [
        {"setting": "remote desktop", "value": "ENABLED"},
        {"setting": "rdp network level auth", "value": "NOT REQUIRED"},
        {"setting": "winrm service", "value": "Running"},
        {"setting": "smbv1", "value": "ENABLED"},
        {"setting": "smb signing required", "value": "False"},
        {"setting": "firewall public", "value": "OFF"},
        {"setting": "uac", "value": "on"},
        {"setting": "automatic logon", "value": "off"},
        {"setting": "llmnr", "value": "ON"},
        {"setting": "defender real-time", "value": "True"},
        {"setting": "system drive encryption", "value": "Off"},
    ],
}
