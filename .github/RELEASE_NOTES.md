**An autonomous Windows hardening agent with a language model running on the machine itself.**

It looks at what the machine is, decides what to do about it, fixes what it can
undo, verifies that the fix worked, and puts back anything that made things
worse. No prompts, no dialogs, no cloud, no account.

## Which file do I want?

| File | What it is |
|---|---|
| **`lares-full-x64.exe`** | Terminal application **with the model already inside it**. One file, nothing to fetch, works offline forever. |
| `lares-x64.exe` | Terminal application. Downloads a model the first time it wants one. |
| `lares-desktop-x64.exe` | Desktop application. |
| **`lares-freehand-full-x64.exe`** | **New.** The lane with no catalogue in it — the model writes every fix — with the model inside. |
| `lares-freehand-x64.exe` | The same without a model. It refuses to run until it has one. |
| **`lares-full-arm64.exe`** | Windows on ARM **with the model inside it** — including a VM on Apple Silicon. |
| **`lares-freehand-full-arm64.exe`** | The freehand lane for Windows on ARM, with the model inside. |
| `lares-arm64.exe` · `lares-desktop-arm64.exe` · `lares-freehand-arm64.exe` | Windows on ARM, without the model. |

Check your download against `SHA256SUMS.txt` before running it.

Or let the installer choose, verify and put it on your PATH:

```powershell
irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 | iex
```

## New in this release

### `lares-freehand.exe` — no catalogue at all

A separate program, because it answers the question that matters most about a
tool like this — *who wrote the code that runs on your machine* — differently
from `lares.exe`, and that is too large a difference to hide behind a flag.

It reads the machine: installed software and versions, every listening TCP and
UDP socket and who owns it, running services and their image paths, local
accounts, and the settings that decide what is reachable. It hands that to the
model, asks what is wrong, then asks for the PowerShell that fixes each thing —
a check, a fix and an undo — and runs what the model wrote.

```powershell
lares-freehand --recorded    # read the whole lane through, no model needed
lares-freehand --dry-run     # your machine, the real model, no changes
lares-freehand               # let it act on what the model writes
```

What is still not the model's to decide is a blocklist of catastrophes —
formatting a disk, deleting shadow copies, editing the boot configuration,
`Invoke-Expression`, turning the firewall off, rebooting. The check script is
screened too, because it runs before the fix and even in a dry run.

**Two things worth reading before you run it.** The screen stops catastrophes,
not mistakes: a model-written fix that is merely wrong will run. And the undo is
written by the same model as the fix, so when the model is wrong about reversing
its own change it is wrong in the same direction. Both scripts are kept verbatim
in the journal. Take a VM snapshot first.

### `--live` — watch it think

Every exchange was already recorded, but only once it was over, and on four
cores that is minutes of spinner. `--live` streams the conversation instead:
what is sent, then the answer one token at a time as the model writes it.

```powershell
lares consult --live
lares run --model-only --live
```

### Small models, and what they do when they are out of their depth

A 1.5B asked to write prose will sometimes find a sentence it likes and repeat
it until its token budget is gone — a release build caught one saying the same
thing forty-five times inside a single JSON string, never reaching the part of
the answer that mattered. Four things changed because of it:

- every piece of **prose** the model writes is bounded in the schema, so where
  the backend compiles that into a grammar the limit is enforced by the
  sampler — the scripts deliberately are not, because llama.cpp refuses a
  grammar with that many repetitions and then generates with no grammar at
  all, which is strictly worse;
- the findings are **asked for before the summary**, so if the model does lose
  itself in prose it does so *after* the part worth having;
- a reply that **ran out of room is recovered** rather than discarded — rewound
  to the last complete point and closed — though a reply cut off before
  anything completed is still refused, because an empty object reads as a
  confident "nothing is wrong with this machine";
- and a model that gets stuck is **told apart from malformed output**, because
  those have different causes and different answers.

## Letting the model lead

`lares run` hands the model a scan and asks it to choose. `lares consult`
inverts that — the model asks what it wants to look at, those checks are run,
and it is asked again until it gives a verdict.

```powershell
lares consult
lares consult --apply
```

Everything it can ask for is a read-only check from the catalogue, and its
verdict goes through the same guard as any other plan. `--model-only` is the
simpler form: the ordinary scan, but the model is the sole decision-maker and
nothing is changed if it cannot answer.

## Start here

`doctor` says whether this machine can run it. `scan` changes nothing. `plan`
shows what it *would* do and why. Only then `run`.

```powershell
lares doctor
lares scan
lares plan
lares run
```

Double-clicking the executable opens a menu rather than flashing a usage message
and closing.

## What is in it

- **Thirty controls** across network, identity, defence, services and system —
  each with a detection probe, a fix, a rollback, a risk tier and a paragraph of
  plain English.
- **The model chooses from that catalogue and never writes the code that runs.**
  Everything it says is validated before anything happens.
- **Every change is verified**, health-checked against name resolution, gateway,
  administrator access, RDP and WinRM, and undone on the spot if it did not work
  or broke something else.
- **A circuit breaker** halts autonomy after two consecutive bad cycles.
- **Three records**: what was changed and how to undo it, what happened, and what
  was said to the model and what was done with its answer.
- **A built-in planner** that needs no model at all, so the machine is still
  hardened when the model is missing, too large, or fails to load.

## Known limits, stated plainly

**The engine is tested. Most of the PowerShell has run once, on one machine.**
482 tests run on Windows and Linux across Python 3.10 and 3.12, and CI installs
this release with `install.ps1` on a clean x64 and a clean ARM64 machine and
runs the result — including the freehand walkthrough, and a check that the
freehand binary really has no catalogue in it.

8 of the 30 controls have applied and verified against a live Windows 11 ARM64
VM. The other 22 have never executed on real hardware: they were written against
Microsoft's documentation, reviewed by hand, and exercised in demo mode, which
fakes the PowerShell round trip.

Try it on a machine you can afford to restore, and take a VM snapshot first.
Findings from real hardware are the most useful thing anyone could contribute.

**ARM64 now gets the model too.** `llama-cpp-python` publishes no ARM64 wheel,
so CI compiles one — and llama.cpp refuses to build with MSVC on ARM ("use
clang"), so it goes through clang-cl. `lares doctor` says exactly what is
available on your machine.

**The executables are not code-signed**, so SmartScreen will warn on first run.
