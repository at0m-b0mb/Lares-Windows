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
| **`lares-full-arm64.exe`** | Windows on ARM **with the model inside it** — including a VM on Apple Silicon. |
| `lares-arm64.exe` · `lares-desktop-arm64.exe` | Windows on ARM, without the model. |

Check your download against `SHA256SUMS.txt` before running it.

Or let the installer choose, verify and put it on your PATH:

```powershell
irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 | iex
```

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

**The engine is tested; the PowerShell is not.** 439 tests run on Windows and
Linux across Python 3.10 and 3.12, and CI installs this release with
`install.ps1` on a clean x64 and a clean ARM64 machine and runs the result. But no control in the catalogue has yet
executed against a live Windows machine — every probe and remediation was written
against Microsoft's documentation and exercised in demo mode, which fakes the
PowerShell round trip.

Try it on a machine you can afford to restore, and take a VM snapshot first.
Findings from real hardware are the most useful thing anyone could contribute.

**ARM64 now gets the model too.** `llama-cpp-python` publishes no ARM64 wheel,
so CI compiles one — and llama.cpp refuses to build with MSVC on ARM ("use
clang"), so it goes through clang-cl. `lares doctor` says exactly what is
available on your machine.

**The executables are not code-signed**, so SmartScreen will warn on first run.
