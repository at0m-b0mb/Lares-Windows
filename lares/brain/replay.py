"""An Engine-shaped object that answers from a script instead of a model.

The freehand lane is nothing without a model - it has no catalogue to fall back
on, and refusing to run without one is the correct behaviour rather than a
limitation. That leaves a real problem: anyone who wants to understand what the
lane does before committing to a gigabyte download has no way to look at it.

This is the way to look at it. It presents the same surface as Engine, so
``Freehand`` cannot tell the difference and no second arrangement of the lane
exists for demonstration purposes - the code that runs against a replay is the
identical code that runs against a model, which is the only way a walkthrough
can honestly claim to show what the real thing does.

The answers are labelled everywhere they appear. They are written by hand to
show the shape of a reply, not captured from a model run, and nothing in this
file pretends otherwise.
"""

from __future__ import annotations

import time
from typing import Any

from .engine import Reply, Watch


class Replay:
    """Answers in order, streaming them the way a model would."""

    #: Named so that every place that prints the model's name - the header,
    #: the transcript, the journal entry for a change - says what it was.
    name = "recorded answers (no model is running)"
    status = "replaying written-out answers; no model is involved"
    available = True
    spec = None

    def __init__(self, answers: list[str], *, pace: float = 0.012) -> None:
        self.answers = list(answers)
        self.asked: list[tuple[str, str]] = []
        self.pace = pace
        self.watch: Watch | None = None

    def ask(self, system: str, user: str, *, max_tokens: int = 0,
            schema: dict[str, Any] | None = None,
            temperature: float = 0.0) -> Reply:
        self.asked.append((system, user))
        watch = self.watch
        if watch is not None and watch.on_prompt is not None:
            watch.on_prompt(system, user)

        if not self.answers:
            reply = Reply("", ok=False, error="no recorded answer for this question")
            return self._told(watch, reply)

        text = self.answers.pop(0)
        started = time.monotonic()
        if watch is not None and watch.on_token is not None:
            for fragment in _fragments(text):
                watch.on_token(fragment)
                if self.pace:
                    time.sleep(self.pace)

        return self._told(watch, Reply(
            text, ok=True, tokens=len(text.split()),
            seconds=max(time.monotonic() - started, 0.01)))

    @staticmethod
    def _told(watch: Watch | None, reply: Reply) -> Reply:
        if watch is not None and watch.on_reply is not None:
            watch.on_reply(reply)
        return reply

    # Engine offers these; Freehand never calls them, but something else might.
    def load(self) -> bool:
        return True

    def unload(self) -> None:
        return None


def _fragments(text: str) -> list[str]:
    """Split the way a tokeniser roughly would, so playback looks like output."""
    out: list[str] = []
    current = ""
    for char in text:
        current += char
        if char in " \n{}[],:" and current.strip():
            out.append(current)
            current = ""
        elif len(current) >= 6:
            out.append(current)
            current = ""
    if current:
        out.append(current)
    return out


# --------------------------------------------------------------------------
# The written-out answers
# --------------------------------------------------------------------------

#: Replies in the shape the model returns, for the freehand lane's --recorded.
#:
#: These are NOT a capture of a model run, and nothing here pretends they are.
#: They exist so the flow - assess, write, screen, check, apply, verify - can be
#: followed by someone deciding whether to download a gigabyte first, and they
#: are played through the identical code the live path uses.
#:
#: The second remedy deliberately reaches for a reboot, which the screen
#: refuses. A walkthrough where every script is accepted teaches nothing about
#: the one judgement this program keeps for itself, and a model that never
#: writes anything objectionable is not a model anyone has met.
FREEHAND_ANSWERS: list[str] = [
    r"""{
  "summary": "This machine is reachable on six ports and three of them are the ones worth having: SMB on 445, RDP on 3389 without network level authentication, and WinRM on 5985. SMBv1 is still enabled, which is the protocol every worm since 2017 has reached for. There is also a service running as LocalSystem from an unquoted path with a space in it, and a Guest account that is switched on.",
  "issues": [
    {"title": "SMBv1 is enabled", "area": "exposure", "severity": "critical",
     "why": "SMBv1 is the protocol WannaCry and NotPetya spread over. Nothing on a current Windows network needs it, and leaving it on hands an attacker already on this network a well-travelled way in.",
     "evidence": "smbv1 = ENABLED"},
    {"title": "RDP accepts connections without network level authentication", "area": "exposure", "severity": "high",
     "why": "Without NLA an attacker reaches the logon screen before authenticating, which exposes the service itself to anyone who can route to port 3389.",
     "evidence": "rdp network level auth = NOT REQUIRED"},
    {"title": "The Guest account is enabled", "area": "accounts", "severity": "high",
     "why": "Guest is an account with no password. Enabled, it is a foothold that needs no credential at all.",
     "evidence": "Guest - enabled"},
    {"title": "A service runs as LocalSystem from an unquoted path", "area": "services", "severity": "high",
     "why": "Windows tries C:\\Program.exe before C:\\Program Files\\Vendor Agent\\agent.exe. Any user who can write to the root of C: becomes SYSTEM at the next restart.",
     "evidence": "VulnAgent (Auto) as LocalSystem - C:\\Program Files\\Vendor Agent\\agent.exe -run  UNQUOTED PATH"},
    {"title": "The public firewall profile is off", "area": "exposure", "severity": "high",
     "why": "On an untrusted network every one of the listening ports above is reachable with no filtering at all.",
     "evidence": "firewall public = OFF"}
  ]
}""",
    r"""{
  "explain": "Turns off the SMBv1 server protocol. This is a server-side setting and needs no restart on Windows 10 or 11. Clients that speak only SMBv1 will stop being able to connect, which is the intent.",
  "check": "if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { 'NOTFIXED' } else { 'FIXED' }",
  "fix": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
  "undo": "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force"
}""",
    r"""{
  "explain": "Requires network level authentication for Remote Desktop, so a connection has to authenticate before a session is created. I am restarting the machine afterwards so the terminal service picks the change up.",
  "check": "$v = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication; if ($v -eq 1) { 'FIXED' } else { 'NOTFIXED' }",
  "fix": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1\nRestart-Computer -Force",
  "undo": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 0"
}""",
    r"""{
  "explain": "Disables the built-in Guest account. It keeps its name and its profile; it simply cannot be used to log on.",
  "check": "if ((Get-LocalUser -Name 'Guest').Enabled) { 'NOTFIXED' } else { 'FIXED' }",
  "fix": "Disable-LocalUser -Name 'Guest'",
  "undo": "Enable-LocalUser -Name 'Guest'"
}""",
    r"""{
  "explain": "Puts quotes around the service image path so Windows resolves it as one path instead of trying every space-separated prefix first. The argument stays outside the quotes.",
  "check": "$p = (Get-CimInstance Win32_Service -Filter \"Name='VulnAgent'\").PathName; if ($p.StartsWith('\"')) { 'FIXED' } else { 'NOTFIXED' }",
  "fix": "$key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VulnAgent'\nSet-ItemProperty -Path $key -Name ImagePath -Value '\"C:\\Program Files\\Vendor Agent\\agent.exe\" -run'",
  "undo": "$key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VulnAgent'\nSet-ItemProperty -Path $key -Name ImagePath -Value 'C:\\Program Files\\Vendor Agent\\agent.exe -run'"
}""",
    r"""{
  "explain": "Switches the public firewall profile back on and leaves its rules alone, so existing allowances survive and everything else is filtered again.",
  "check": "if ((Get-NetFirewallProfile -Name Public).Enabled) { 'FIXED' } else { 'NOTFIXED' }",
  "fix": "Set-NetFirewallProfile -Name Public -Enabled True",
  "undo": "Set-NetFirewallProfile -Name Public -Enabled False"
}""",
]
