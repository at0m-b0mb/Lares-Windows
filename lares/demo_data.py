"""A believable Windows machine, for development and for demonstrations.

Lares is a Windows tool, but it is written and tested on macOS and Linux and it
has to be showable without handing someone a deliberately broken PC. Demo mode
supplies the answers the probes would have given on a real, moderately neglected
Windows 11 laptop - the kind of machine this application actually exists for.

The host is DESKTOP-KP7724, matching the other tools in this catalogue so that
screenshots across projects look like the same machine.

Every entry here is shaped exactly like the JSON a real probe returns, so demo
mode exercises the same parsing, planning and grading code as a live run. The
only thing that is faked is the PowerShell round trip.
"""

from __future__ import annotations

from typing import Any

HOSTNAME = "DESKTOP-KP7724"
USERNAME = f"{HOSTNAME}\\kailash"

#: System context, as (key, value, domain, sensitive) tuples.
FACTS: list[tuple[str, str, str, bool]] = [
    ("Host name", HOSTNAME, "system", True),
    ("Operating system", "Microsoft Windows 11 Pro", "system", False),
    ("Version", "10.0.26100 (24H2)", "system", False),
    ("Architecture", "64-bit (x64)", "system", False),
    ("Installed", "2024-03-11", "system", False),
    ("Last restart", "6 days ago", "system", False),
    ("Domain joined", "No (workgroup WORKGROUP)", "system", False),

    ("Signed in as", USERNAME, "identity", True),
    ("Running elevated", "Yes", "identity", False),
    ("Local administrators", "3 (Administrator, kailash, svc_backup)", "identity", False),
    ("Local accounts", "5 total, 4 enabled", "identity", False),

    ("Processor", "Intel Core i5-8250U, 4 cores / 8 threads", "hardware", False),
    ("Memory", "8.0 GB", "hardware", False),
    ("System drive", "237 GB SSD, 41 GB free", "hardware", False),
    ("Secure Boot", "Enabled", "hardware", False),
    ("TPM", "2.0, present and ready", "hardware", False),

    ("Active network", "Wi-Fi, profile Private", "network", False),
    ("IPv4 address", "192.168.1.42", "network", True),
    ("Default gateway", "192.168.1.1", "network", True),
    ("Listening TCP ports", "14 (3 on all interfaces)", "network", False),

    ("Installed software", "94 packages", "software", False),
    ("Last update installed", "KB5062553, 71 days ago", "software", False),
    ("Antivirus", "Microsoft Defender", "defence", False),
]


def _probe(
    compliant: bool,
    observed: str,
    evidence: str = "",
    params: dict[str, Any] | None = None,
    instances: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"compliant": compliant, "observed": observed}
    if evidence:
        out["evidence"] = evidence
    if params:
        out["params"] = params
    if instances is not None:
        out["instances"] = instances
    return out


#: control id -> the object that control's detect probe would print.
PROBES: dict[str, dict[str, Any]] = {

    # -- network -------------------------------------------------------
    "NET-001": _probe(
        False,
        "Firewall is off for profile(s): Public",
        "Domain=True; Private=True; Public=False",
        instances=[{
            "params": {"profile": "Public"},
            "observed": "The Public firewall profile is disabled",
        }],
    ),
    "NET-002": _probe(
        True,
        "Every profile blocks unmatched inbound traffic by default",
        "Domain=Block; Private=Block; Public=Block",
    ),
    "NET-003": _probe(
        False,
        "3 service(s) listening on all interfaces: 3389/svchost, 5040/svchost, 8080/node",
        "3389 svchost C:\\Windows\\System32\\svchost.exe\n"
        "5040 svchost C:\\Windows\\System32\\svchost.exe\n"
        "8080 node C:\\Program Files\\nodejs\\node.exe",
        instances=[
            {
                "params": {"port": 3389, "profile": "Public"},
                "observed": "TCP 3389 is open to all interfaces, held by svchost",
                "evidence": "C:\\Windows\\System32\\svchost.exe (Remote Desktop)",
            },
            {
                "params": {"port": 5040, "profile": "Public"},
                "observed": "TCP 5040 is open to all interfaces, held by svchost",
                "evidence": "C:\\Windows\\System32\\svchost.exe (Connected Devices Platform)",
            },
            {
                "params": {"port": 8080, "profile": "Public"},
                "observed": "TCP 8080 is open to all interfaces, held by node",
                "evidence": "C:\\Program Files\\nodejs\\node.exe",
            },
        ],
    ),
    "NET-004": _probe(
        False,
        "The SMBv1 server protocol is enabled",
        "EnableSMB1Protocol=True; EnableSMB2Protocol=True",
    ),
    "NET-005": _probe(
        False,
        "LLMNR is enabled - the machine will answer and trust multicast name requests",
        "EnableMulticast=<not set>",
    ),
    "NET-006": _probe(
        True,
        "Remote Registry is stopped and disabled",
        "Status=Stopped; StartMode=Disabled",
    ),

    # -- identity ------------------------------------------------------
    "IDN-001": _probe(
        True,
        "User Account Control is enabled",
        "EnableLUA=1",
        params={"previous": 1},
    ),
    "IDN-002": _probe(
        False,
        "Administrators are elevated silently, with no consent prompt",
        "ConsentPromptBehaviorAdmin=0",
        params={"previous": 0},
    ),
    "IDN-003": _probe(
        False,
        "The built-in Guest account is enabled",
        "Guest.Enabled=True; LastLogon=",
    ),
    "IDN-004": _probe(
        True,
        "No clear-text logon password is stored in the registry",
        "AutoAdminLogon=0; DefaultUserName=kailash; DefaultPassword=<absent>",
    ),
    "IDN-005": _probe(
        False,
        "WDigest is keeping clear-text passwords in memory",
        "UseLogonCredential=1",
        params={"previous": 1},
    ),
    "IDN-006": _probe(
        False,
        "LSASS runs unprotected - its memory can be read by any administrator",
        "RunAsPPL=<not set>",
        params={"previous": -1},
    ),
    "IDN-007": _probe(
        False,
        "Anonymous connections can enumerate local accounts or shares",
        "RestrictAnonymousSAM=1; RestrictAnonymous=-1 (-1 means not set)",
        params={"previous_sam": 1, "previous_all": -1},
    ),
    "IDN-008": _probe(
        False,
        "3 account(s) hold local administrator rights: Administrator, kailash, svc_backup",
        "Administrator [User] Local\nkailash [User] Local\nsvc_backup [User] Local",
    ),

    # -- defence -------------------------------------------------------
    "DEF-001": _probe(
        True,
        "Defender real-time protection is active",
        "RealTimeProtectionEnabled=True; DisableRealtimeMonitoring=False; AMServiceEnabled=True",
    ),
    "DEF-002": _probe(
        False,
        "Defender definitions are 9 day(s) old",
        "AntivirusSignatureVersion=1.421.1288.0; AntivirusSignatureLastUpdated=9 days ago",
    ),
    "DEF-003": _probe(
        False,
        "Tamper Protection is off - Defender can be disabled by any elevated process",
        "IsTamperProtected=False",
    ),
    "DEF-004": _probe(
        False,
        "The LSASS credential-theft rule is not configured",
        "rule=9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2; state=not configured; configured_rules=0",
    ),
    "DEF-005": _probe(
        False,
        "SmartScreen is not checking apps and downloads",
        "SmartScreenEnabled=Off",
        params={"previous": "Off"},
    ),
    "DEF-006": _probe(
        False,
        "Dropped packets are not logged on: Domain, Private, Public",
        "Domain LogBlocked=False; Private LogBlocked=False; Public LogBlocked=False",
        instances=[
            {"params": {"profile": "Domain"},
             "observed": "The Domain profile does not log dropped packets"},
            {"params": {"profile": "Private"},
             "observed": "The Private profile does not log dropped packets"},
            {"params": {"profile": "Public"},
             "observed": "The Public profile does not log dropped packets"},
        ],
    ),
    "DEF-007": _probe(
        False,
        "The system drive is not protected by BitLocker (FullyDecrypted)",
        "ProtectionStatus=Off; VolumeStatus=FullyDecrypted; EncryptionPercentage=0",
    ),

    # -- services ------------------------------------------------------
    "SVC-001": _probe(
        False,
        "1 service(s) run from an unquoted path: BackupAgentSvc",
        "BackupAgentSvc: C:\\Tools\\Backup Agent\\agentsvc.exe -service",
        instances=[{
            "params": {"service": "BackupAgentSvc"},
            "observed": "Service BackupAgentSvc starts from unquoted "
                        "C:\\Tools\\Backup Agent\\agentsvc.exe -service",
            "evidence": "Backup Agent Service",
        }],
    ),
    "SVC-002": _probe(
        False,
        "1 service(s) run from a user-writable folder: BackupAgentSvc",
        "BackupAgentSvc: C:\\Tools\\Backup Agent grants Modify to BUILTIN\\Users",
    ),
    "SVC-003": _probe(
        False,
        "Any user can make the spooler install a printer driver as SYSTEM",
        "RestrictDriverInstallationToAdministrators=<not set>; Spooler=Running",
        params={"previous": -1},
    ),
    "SVC-004": _probe(
        True,
        "No privileged scheduled task runs from a user-writable folder",
    ),

    # -- system --------------------------------------------------------
    "SYS-001": _probe(
        False,
        "The PowerShell 2.0 engine is installed and can be used to bypass script logging",
        "MicrosoftWindowsPowerShellV2Root.State=Enabled",
    ),
    "SYS-002": _probe(
        False,
        "PowerShell runs without recording what it executes",
        "EnableScriptBlockLogging=<not set>",
        params={"previous": -1},
    ),
    "SYS-003": _probe(
        False,
        "Process creation is not being audited at all",
        "ProcessCreationIncludeCmdLine_Enabled=<not set>; auditpol_success=False",
        params={"previous": -1},
    ),
    "SYS-004": _probe(
        False,
        "AutoRun is still active for some drive types, including removable media",
        "NoDriveTypeAutoRun=<not set> (255 disables all)",
        params={"previous": -1},
    ),
    "SYS-005": _probe(
        False,
        "The most recent update was installed 71 day(s) ago (KB5062553)",
        "HotFixID=KB5062553; InstalledOn=71 days ago; Description=Security Update",
    ),
}


def probe_for(control_id: str) -> dict[str, Any]:
    """The demo answer for a control, defaulting to compliant if unlisted.

    Defaulting to compliant keeps a newly added control from appearing as a
    fake problem in demo screenshots before anyone has written its demo data.
    """
    return PROBES.get(
        control_id,
        _probe(True, "no demo data for this control; treated as compliant"),
    )


#: State after Lares has fixed what it can, so the GUI can show a second pass.
def probe_after_remediation(control_id: str, fixed: set[str]) -> dict[str, Any]:
    base = probe_for(control_id)
    if control_id not in fixed:
        return base
    return _probe(True, f"resolved by Lares: {base.get('observed', '')}")
