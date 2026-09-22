"""The gate between what the model wants and what the machine will do.

Everything in this module is pure Python with no Windows dependency, which is
deliberate: this is the code that decides whether a privileged script runs, so
it has to be exercisable by tests on any machine, thousands of times, including
against inputs a model would never produce but an attacker might.

Three independent checks, in order, each able to refuse on its own:

1. :func:`validate_params` - the model's parameters must match the shapes the
   control declared. Types, ranges, enum membership, regex, and a hard refusal
   of shell metacharacters regardless of what the control's own pattern allows.
2. :func:`screen_script` - the rendered script is read for operations that are
   catastrophic and irreversible. The catalogue is written by hand and should
   never trip this; the Expert lane, where the model authors PowerShell freely,
   is exactly why it exists.
3. :func:`check_policy` - situational rules. Is the process elevated? Is this
   control above the autonomy ceiling? Does it apply to this Windows edition?

A refusal is a normal outcome, not an error. It gets journalled with a reason
and the loop carries on to the next action.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..core import Control, ParamSpec, RiskTier


class Refused(Exception):
    """Raised when an action must not proceed. Carries an operator-readable reason."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------
# 1. Parameter validation
# --------------------------------------------------------------------------

#: Characters that let a string stop being data and start being code. Refused
#: in every string and path parameter no matter how permissive the control's
#: own pattern is, so that a sloppy regex in one YAML file cannot become an
#: injection. The backtick is PowerShell's escape character and ``$`` opens
#: both variable expansion and ``$( )`` subexpressions, so those two are what
#: actually matter; the rest are refused because nothing legitimate needs them.
_ALWAYS_REFUSED = set("`$;|&<>\"'\r\n\t\x00")

#: Additionally refused in ``string`` parameters. Paths are exempt because
#: ``C:\Program Files (x86)`` and GUID-named folders are ordinary, and without
#: ``$`` or a backtick these brackets cannot start a subexpression.
_STRUCTURAL = set("(){}[]")


def _forbidden_chars(spec: ParamSpec) -> set[str]:
    if spec.type == "path":
        return _ALWAYS_REFUSED
    return _ALWAYS_REFUSED | _STRUCTURAL

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}


def _validate_int(spec: ParamSpec, value: Any) -> int:
    if isinstance(value, bool):
        raise Refused(f"parameter '{spec.name}' must be a number, got a boolean")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"-?\d{1,10}", value.strip()):
        number = int(value.strip())
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    else:
        raise Refused(f"parameter '{spec.name}' must be a whole number, got {value!r}")

    if spec.minimum is not None and number < spec.minimum:
        raise Refused(f"parameter '{spec.name}' is {number}, below the minimum {spec.minimum}")
    if spec.maximum is not None and number > spec.maximum:
        raise Refused(f"parameter '{spec.name}' is {number}, above the maximum {spec.maximum}")
    return number


def _validate_bool(spec: ParamSpec, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
    raise Refused(f"parameter '{spec.name}' must be true or false, got {value!r}")


def _validate_enum(spec: ParamSpec, value: Any) -> str:
    if not isinstance(value, str):
        raise Refused(f"parameter '{spec.name}' must be one of {list(spec.choices)}")
    candidate = value.strip()
    for choice in spec.choices:
        if candidate.lower() == choice.lower():
            # Return the catalogue's own spelling, never the model's.
            return choice
    raise Refused(
        f"parameter '{spec.name}' must be one of {list(spec.choices)}, got {value!r}"
    )


def _validate_text(spec: ParamSpec, value: Any) -> str:
    if not isinstance(value, str):
        raise Refused(f"parameter '{spec.name}' must be text, got {type(value).__name__}")
    text = value.strip()
    if not text:
        raise Refused(f"parameter '{spec.name}' is empty")
    if len(text) > 320:
        raise Refused(f"parameter '{spec.name}' is {len(text)} characters, over the 320 limit")
    if _CONTROL_CHARS.search(text):
        raise Refused(f"parameter '{spec.name}' contains control characters")

    bad = sorted(set(text) & _forbidden_chars(spec))
    if bad:
        raise Refused(
            f"parameter '{spec.name}' contains shell metacharacter(s) {''.join(bad)!r}",
            detail=text,
        )
    if spec.type == "path":
        if ".." in text:
            raise Refused(f"parameter '{spec.name}' contains a parent-directory traversal")
        if text.startswith("\\\\"):
            raise Refused(f"parameter '{spec.name}' is a UNC path, which is not accepted here")
    if spec.pattern and not re.fullmatch(spec.pattern, text):
        raise Refused(
            f"parameter '{spec.name}' does not match the shape this control accepts",
            detail=f"{text!r} vs /{spec.pattern}/",
        )
    return text


_VALIDATORS = {
    "int": _validate_int,
    "bool": _validate_bool,
    "enum": _validate_enum,
    "string": _validate_text,
    "path": _validate_text,
}


def validate_params(control: Control, params: dict[str, Any] | None) -> dict[str, Any]:
    """Return a clean parameter dict, or raise :class:`Refused`.

    The returned dict contains only parameters the control declared, with
    values of the declared type. Anything the model supplied that the control
    did not ask for is a refusal rather than something quietly dropped, because
    an unexpected key means the model is working from a different idea of this
    control than the catalogue has.
    """
    supplied = dict(params or {})
    declared = {spec.name for spec in control.params}

    extra = set(supplied) - declared
    if extra:
        raise Refused(
            f"{control.id} does not take parameter(s) {sorted(extra)}",
            detail=f"accepts {sorted(declared)}",
        )

    clean: dict[str, Any] = {}
    for spec in control.params:
        if spec.name not in supplied or supplied[spec.name] is None:
            if spec.required:
                raise Refused(f"{control.id} requires parameter '{spec.name}'")
            continue
        validator = _VALIDATORS.get(spec.type)
        if validator is None:  # pragma: no cover - loader rejects unknown types
            raise Refused(f"{control.id}.{spec.name} has unsupported type {spec.type!r}")
        clean[spec.name] = validator(spec, supplied[spec.name])
    return clean


# --------------------------------------------------------------------------
# 2. Script screening
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    why: str
    #: Rules below this line are so destructive that even a rollback script,
    #: which is otherwise trusted as the inverse of a vetted remediation, is
    #: refused if it contains them.
    absolute: bool = False
    #: Set when the rule asks what is *absent* rather than what is present.
    #:
    #: Those are read only against the normalised text, and the difference is
    #: not a nicety. "New-NetFirewallRule that does not say -Action Block" is a
    #: negative lookahead bounded by [^\n]*, so on raw source it cannot see an
    #: -Action Block that sits after a line continuation - and NET-003, a real
    #: control that blocks a port, formats exactly that way. Screening both
    #: forms adds matches for a positive rule and false positives for this
    #: kind, so this kind reads one form only.
    normalised_only: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


#: A PowerShell parameter, matching both the space form and the colon form.
#: ``-Enabled False`` and ``-Enabled:$false`` are the same instruction, and an
#: audit found that every rule here only knew the first one.
def _flag(name: str, value: str) -> str:
    return rf"-{name}\s*[:\s]\s*\$?(?:{value})\b"


#: Line continuation: a backtick, optional trailing spaces, then a newline.
#: PowerShell joins these into one logical line, so a rule written with
#: ``[^\n]*`` - which is nearly all of them - stops matching the moment an
#: attacker breaks the statement across two lines.
_CONTINUATION = re.compile(r"`[ \t]*\r?\n[ \t]*")


def normalise(script: str) -> str:
    """Undo the cheap obfuscations, so the rules below see one shape.

    Screening raw text means every rule has to anticipate every spelling of
    the thing it forbids, and it will not. An audit walked through this list
    and defeated eight of the rules without writing anything clever: a
    backtick before a newline, a backtick in the middle of an identifier
    (``I`EX`` runs), a parenthesis where a space was expected, ``net.exe``
    instead of ``net``.

    Undoing those here means each rule describes an *operation* rather than a
    spelling. It does not make this a PowerShell parser and it does not close
    the class - obfuscated PowerShell is undecidable in the general case, and
    anyone who wants past a blocklist gets past a blocklist. It closes the
    cheap half, which is the half a hallucinating model and a casual attacker
    both live in.

    The normalised text is screened *in addition to* the original, never
    instead of it, so this can only ever add matches.
    """
    joined = _CONTINUATION.sub(" ", script)
    # A backtick inside a word is an escape PowerShell discards, so "I`EX" is
    # "IEX". Removing them all can merge tokens that were separated by `n or
    # `t, which only ever creates more matches, never fewer.
    plain = joined.replace("`", "")
    return re.sub(r"[ \t]+", " ", plain)


#: Operations Lares will not perform, in the catalogue or in the Expert lane.
#:
#: This is not a general-purpose malicious-PowerShell detector and does not try
#: to be - obfuscated PowerShell is undecidable in the general case. It is a
#: list of the specific catastrophes that a hardening tool has no business
#: performing, so that a hallucinated "fix" cannot destroy the machine.
DANGEROUS_RULES: tuple[Rule, ...] = (
    Rule("format-volume", _rx(r"\bFormat-Volume\b"),
         "formats a disk volume", absolute=True),
    Rule("clear-disk", _rx(r"\bClear-Disk\b"),
         "erases a whole disk", absolute=True),
    Rule("remove-partition", _rx(r"\bRemove-Partition\b"),
         "deletes a disk partition", absolute=True),
    Rule("delete-shadows",
         _rx(r"\bvssadmin(\.exe)?\b[^\n]*\bdelete\b|"
             r"\bwmic(\.exe)?\b[^\n]*\bshadowcopy\b[^\n]*\bdelete\b|"
             r"\bWin32_ShadowCopy\b[^\n]*\bDelete\b"),
         "deletes volume shadow copies, which is how ransomware removes your ability to recover",
         absolute=True),
    Rule("wipe-free-space", _rx(r"\bcipher(\.exe)?\b[^\n]*\s/w"),
         "overwrites free disk space, destroying recoverable data", absolute=True),
    Rule("bcdedit", _rx(r"\bbcdedit(\.exe)?\b"),
         "edits the boot configuration, which can leave the machine unbootable",
         absolute=True),
    Rule("recursive-force-delete",
         _rx(r"\bRemove-Item\b(?=[^\n]*-Recurse)(?=[^\n]*-Force)"),
         "force-deletes a directory tree", absolute=True),
    Rule("format-command", _rx(r"\bformat(\.com|\.exe)?\s+[a-z]:"),
         "formats a drive", absolute=True),
    Rule("rd-deltree", _rx(r"\b(rd|rmdir)(\.exe)?\b[^\n]*\s/s\b"),
         "recursively removes a directory tree", absolute=True),

    Rule("disable-adapter", _rx(r"\bDisable-NetAdapter\b"),
         "switches off a network adapter, which can cut off all remote access"),
    Rule("disable-defender",
         # Every -Disable* switch on Set-MpPreference, in both the space and
         # the colon form, plus turning reporting off entirely. An audit got
         # past the old rule with "-DisableRealtimeMonitoring:$true" and with
         # the sibling switches it never named.
         _rx(r"\bSet-MpPreference\b[^\n]*" + _flag(r"Disable[A-Za-z]*", r"true|1") +
             r"|\bSet-MpPreference\b[^\n]*" + _flag("MAPSReporting", "0|Disabled") +
             r"|\bUninstall-WindowsFeature\b[^\n]*Defender"),
         "turns off antivirus protection"),
    Rule("remove-user",
         _rx(r"\bRemove-LocalUser\b|\bnet(\.exe)?\s+user\b[^\n]*\s/delete\b|"
             r"\bDeleteUser\b|\[ADSI\][^\n]*\bDelete\b[^\n]*\buser\b"),
         "deletes a local user account"),
    Rule("remove-admin", _rx(r"\bRemove-LocalGroupMember\b[^\n]*Administrators"),
         "removes an administrator, which can leave nobody able to manage the machine"),
    Rule("reboot", _rx(r"\bRestart-Computer\b|\bStop-Computer\b|"
                       r"\bshutdown(\.exe)?\s+/[rs]\b"),
         "restarts or shuts down the machine without warning"),
    Rule("download-and-run",
         _rx(r"(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|curl|wget|"
             r"DownloadString|DownloadFile|DownloadData)"
             r"[^\n]*\|\s*(iex|Invoke-Expression)"),
         "downloads code from the network and executes it"),
    Rule("invoke-expression",
         # The trailing \s used to be required, so the canonical download
         # cradle - iex(New-Object Net.WebClient).DownloadString(...) - walked
         # straight through with a parenthesis where a space was expected.
         _rx(r"\b(iex|Invoke-Expression)\b"),
         "builds and runs a command from a string, which defeats every check above"),
    Rule("encoded-command",
         _rx(r"-e(nc|ncoded(command)?)?\s*[:\s]\s*[A-Za-z0-9+/]{40,}"),
         "runs a base64-encoded command, hiding what it does"),
    Rule("registry-hive-delete",
         _rx(r"\bRemove-Item\b[^\n]*HK(LM|CU|CR|U|CC):\\?\s*$|"
             r"\bReg(\.exe)?\s+delete\b[^\n]*\\(SYSTEM|SOFTWARE|SAM|SECURITY)\s*$"),
         "deletes a top-level registry hive"),
    Rule("disable-firewall-all",
         _rx(r"\bSet-NetFirewallProfile\b[^\n]*" + _flag("Enabled", r"false|0") +
             r"|netsh\s+advfirewall\s+set\s+(all|domain|private|public)profiles?\s+state\s+off"),
         "switches the firewall off"),
    Rule("scheduled-persistence",
         _rx(r"\bRegister-ScheduledTask\b|\bschtasks(\.exe)?\s+/create\b"),
         "creates a scheduled task, which is a persistence mechanism Lares does not need"),

    # -- things a tool that hardens a machine never does ----------------
    #
    # Not catastrophes. These are the specific moves an attacker makes, and a
    # program whose job is to shrink a machine's attack surface has no
    # legitimate reason to perform any of them.
    #
    # They matter most in the freehand lane, where the model writes the script.
    # The reading it is shown contains service display names and product names,
    # and those are strings an attacker can choose - malware names itself.
    # Telling the model to treat that reading as data is necessary and is done,
    # but an instruction to a 1.5B model is not a control. These hold whether
    # it was persuaded or not.
    Rule("create-user",
         _rx(r"\bNew-LocalUser\b|\bnet(\.exe)?\s+user\b[^\n]*\s/add\b|"
             r"\[ADSI\][^\n]*\bCreate\b[^\n]*\buser\b"),
         "creates a local account, which hardening never requires",
         absolute=True),
    Rule("grant-admin",
         _rx(r"\bAdd-LocalGroupMember\b[^\n]*Administrators|"
             r"\bnet(\.exe)?\s+localgroup\b[^\n]*Administrators[^\n]*\s/add\b|"
             r"\[ADSI\][^\n]*Administrators[^\n]*\bAdd\b"),
         "grants administrator rights to an account",
         absolute=True),
    Rule("antivirus-exclusion",
         _rx(r"\b(Add|Set)-MpPreference\b[^\n]*-Exclusion"),
         "adds an antivirus exclusion, which is how protection is blinded "
         "rather than improved",
         absolute=True),
    Rule("clear-event-log",
         _rx(r"\bwevtutil(\.exe)?\s+(cl|clear-log)\b|\bClear-EventLog\b|"
             r"\bRemove-EventLog\b|\bwmic(\.exe)?\b[^\n]*\bnteventlog\b[^\n]*\bcleareventlog\b"),
         "erases an event log, destroying the record of what happened",
         absolute=True),
    Rule("remote-shell",
         # System. is optional in PowerShell type literals, and leaving it off
         # was enough to defeat this entirely.
         _rx(r"(System\.)?Net\.Sockets\.(TCPClient|TcpListener)|"
             r"\bNew-PSSession\b|\bEnter-PSSession\b"),
         "opens a network session from the machine it is meant to be securing"),
    Rule("open-inbound",
         # New-NetFirewallRule defaults to Inbound and Allow, so naming neither
         # was how the old rule was beaten. Inverted: any new rule is refused
         # unless it explicitly blocks. Not absolute - undoing a rule Lares
         # added to close something legitimately means allowing it again.
         _rx(r"\bNew-NetFirewallRule\b(?![^\n]*" + _flag("Action", "Block|Deny") + r")|"
             r"netsh\s+advfirewall\s+firewall\s+add\s+rule[^\n]*action\s*=\s*allow"),
         "opens an inbound hole in the firewall",
         normalised_only=True),
)


@dataclass(frozen=True)
class ScreenResult:
    ok: bool
    hits: tuple[Rule, ...] = ()

    @property
    def summary(self) -> str:
        if self.ok:
            return "no dangerous operation found"
        return "; ".join(f"{r.name} ({r.why})" for r in self.hits)


def screen_script(script: str, *, absolute_only: bool = False) -> ScreenResult:
    """Read a rendered script for operations that must never run.

    Set *absolute_only* for rollback bodies. A rollback is by definition the
    inverse of a change Lares itself just made, so it is allowed to do things
    the forward direction would not be - DEF-001's rollback genuinely does have
    to switch real-time protection back off, because that is what the machine
    looked like before. The handful of rules marked ``absolute`` still apply,
    because nothing legitimately needs to format a disk in order to undo a
    registry edit.
    """
    if not script or not script.strip():
        return ScreenResult(True)

    # Both the script as written and the script with the cheap obfuscations
    # undone. Screening the normalised form *as well as* the original can only
    # add matches - a rule that fires on either refuses - so this cannot make
    # the screen more permissive than it was.
    joined = normalise(script)
    hits = tuple(
        rule for rule in DANGEROUS_RULES
        if (rule.absolute or not absolute_only)
        and any(rule.pattern.search(form) for form in
                ((joined,) if rule.normalised_only else (script, joined)))
    )
    return ScreenResult(not hits, hits)


# --------------------------------------------------------------------------
# 3. Situational policy
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Context:
    """What is true about this machine and this run, for policy decisions."""

    elevated: bool = False
    #: Highest risk tier the loop may apply without a person present.
    ceiling: RiskTier = RiskTier.CAUTION
    #: True when running unattended. False for an operator-driven single action.
    autonomous: bool = True
    #: Windows edition string, matched against Control.applies_to.
    edition: str = ""
    #: Changes already made this cycle, against the per-cycle budget.
    changes_made: int = 0
    change_budget: int = 8
    #: True when snapshots could not be taken; restricts what may run.
    snapshots_available: bool = True


def check_policy(control: Control, ctx: Context) -> None:
    """Raise :class:`Refused` when this control must not run in this context."""
    if not control.has_remediation:
        raise Refused(
            f"{control.id} is a report-only finding with no remediation",
            detail=control.blast_radius,
        )

    if control.needs_admin and not ctx.elevated:
        raise Refused(
            f"{control.id} needs administrator rights and this process is not elevated"
        )

    if ctx.autonomous:
        if not control.is_reversible:
            raise Refused(
                f"{control.id} cannot be undone, so it never runs unattended",
                detail=control.rollback_note or control.blast_radius,
            )
        if control.risk.rank > ctx.ceiling.rank:
            raise Refused(
                f"{control.id} is risk '{control.risk.value}', above the autonomy "
                f"ceiling of '{ctx.ceiling.value}'",
                detail=control.blast_radius,
            )
        if ctx.changes_made >= ctx.change_budget:
            raise Refused(
                f"this cycle has already made {ctx.changes_made} changes, which is the "
                f"budget of {ctx.change_budget}; the rest wait for the next cycle"
            )
        if not ctx.snapshots_available and control.rollback_policy != "additive":
            raise Refused(
                f"{control.id} changes existing state but no snapshot could be taken, "
                "so it is being left alone"
            )

    if control.applies_to and ctx.edition:
        if not any(token.lower() in ctx.edition.lower() for token in control.applies_to):
            raise Refused(
                f"{control.id} applies to {list(control.applies_to)}, "
                f"and this machine is {ctx.edition!r}"
            )


# --------------------------------------------------------------------------
# The whole gate
# --------------------------------------------------------------------------

def clear_to_run(
    control: Control,
    params: dict[str, Any] | None,
    ctx: Context,
    rendered: str | None = None,
) -> dict[str, Any]:
    """Run all three checks. Returns validated parameters or raises Refused.

    *rendered* is the remediation body after parameter substitution. It is
    optional only so that callers can validate parameters before rendering;
    the executor always passes it.
    """
    clean = validate_params(control, params)
    check_policy(control, ctx)
    if rendered is not None:
        result = screen_script(rendered)
        if not result.ok:
            raise Refused(
                f"{control.id} remediation contains a forbidden operation",
                detail=result.summary,
            )
    return clean
