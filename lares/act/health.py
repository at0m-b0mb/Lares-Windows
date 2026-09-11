"""Is the machine still working?

This is the check that makes unattended remediation survivable. Lares captures a
small set of signals before it changes anything, and compares them afterwards.
If something that was working has stopped working, the change is undone
immediately - without asking anyone, because there is nobody to ask.

The comparison is deliberately **baseline-anchored**: a signal that was already
failing before the change is not a regression, and reporting it as one would
make every cycle on an offline laptop look like a disaster. Only a transition
from working to broken counts.

The signals are chosen for one property: each is a way an automated change could
plausibly cut a person off from their own machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..winsys import is_demo, powershell


@dataclass(frozen=True)
class Signal:
    key: str
    label: str
    #: What it means when this goes from working to broken.
    consequence: str


SIGNALS: tuple[Signal, ...] = (
    Signal("dns", "Name resolution",
           "the machine can no longer resolve host names"),
    Signal("gateway", "Default gateway reachable",
           "the machine has lost its network path"),
    Signal("admins", "An administrator account exists and is enabled",
           "nobody can administer this machine any more"),
    Signal("rdp", "Remote Desktop still listening",
           "a remote operator has just been locked out"),
    Signal("winrm", "Remote management still listening",
           "remote management has just been cut off"),
    Signal("defender", "Antivirus service running",
           "the machine has lost its malware protection"),
    Signal("profile", "User profile directory readable",
           "the running user's profile is no longer accessible"),
)

SIGNAL_BY_KEY = {s.key: s for s in SIGNALS}


#: One PowerShell round trip captures every signal; running seven separate
#: probes after every single change would dominate the cost of a cycle.
_PROBE = r"""
$dns = $false
try { $null = [System.Net.Dns]::GetHostEntry('localhost'); $dns = $true } catch { }
try {
  $r = Resolve-DnsName -Name 'microsoft.com' -QuickTimeout -ErrorAction Stop
  if ($r) { $dns = $true }
} catch { }

$gw = $false
try {
  $g = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric | Select-Object -First 1).NextHop
  if ($g -and $g -ne '0.0.0.0') {
    $gw = Test-Connection -ComputerName $g -Count 1 -Quiet -ErrorAction SilentlyContinue
  } else { $gw = $true }   # no gateway configured is not a regression we caused
} catch { $gw = $true }

$admins = $false
try {
  $m = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
  foreach ($x in $m) {
    if ("$($x.ObjectClass)" -eq 'User') {
      $n = ("$($x.Name)" -split '\\')[-1]
      $u = Get-LocalUser -Name $n -ErrorAction SilentlyContinue
      if ($null -eq $u -or $u.Enabled) { $admins = $true }
    } else { $admins = $true }
  }
} catch { $admins = $true }

function Test-Listening([int]$p) {
  try { return [bool](Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction Stop) }
  catch { return $false }
}

$def = $false
try { $def = [bool](Get-MpComputerStatus -ErrorAction Stop).AMServiceEnabled } catch { }

$prof = $false
try { $prof = Test-Path -LiteralPath $env:USERPROFILE -ErrorAction Stop } catch { }

[pscustomobject]@{
  dns      = $dns
  gateway  = $gw
  admins   = $admins
  rdp      = (Test-Listening 3389)
  winrm    = (Test-Listening 5985)
  defender = $def
  profile  = $prof
} | ConvertTo-Json -Compress
"""


@dataclass
class Health:
    """A reading of every signal at one moment."""

    values: dict[str, bool] = field(default_factory=dict)
    #: True when the probe itself could not be run.
    unavailable: bool = False

    def get(self, key: str) -> bool:
        return bool(self.values.get(key, False))

    def as_dict(self) -> dict[str, Any]:
        return dict(self.values)

    def summary(self) -> str:
        if self.unavailable:
            return "health probe unavailable"
        working = [k for k, v in self.values.items() if v]
        return f"{len(working)}/{len(self.values)} signals working"


@dataclass(frozen=True)
class Regression:
    signal: Signal

    def __str__(self) -> str:
        return f"{self.signal.label}: {self.signal.consequence}"


def capture(timeout: int = 30) -> Health:
    """Read every health signal once."""
    if is_demo():
        return Health({s.key: True for s in SIGNALS})

    result = powershell(_PROBE, timeout=timeout)
    data = result.json(default=None)
    if not isinstance(data, dict):
        # A machine that cannot answer the health probe is one we should not be
        # making unattended changes to. The caller treats this as "do not act".
        return Health(unavailable=True)
    return Health({s.key: bool(data.get(s.key, False)) for s in SIGNALS})


def compare(before: Health, after: Health) -> list[Regression]:
    """Signals that were working before and are not working now.

    Anything already broken beforehand is ignored. If either reading is
    unavailable we return no regressions, because a missing measurement is not
    evidence of damage - the caller decides separately whether to act at all
    without a working health probe.
    """
    if before.unavailable or after.unavailable:
        return []
    return [
        Regression(SIGNAL_BY_KEY[key])
        for key in SIGNAL_BY_KEY
        if before.get(key) and not after.get(key)
    ]


def describe(regressions: list[Regression]) -> str:
    if not regressions:
        return "no health regression"
    return "; ".join(str(r) for r in regressions)
