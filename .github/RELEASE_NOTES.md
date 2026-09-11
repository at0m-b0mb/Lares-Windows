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
| `lares-arm64.exe` · `lares-desktop-arm64.exe` | Windows on ARM, including a VM on Apple Silicon. |

Check your download against `SHA256SUMS.txt` before running it.

Or let the installer choose, verify and put it on your PATH:

```powershell
irm https://raw.githubusercontent.com/at0m-b0mb/Lares-Windows/main/install.ps1 | iex
```

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

**The engine is tested; the PowerShell is not.** 331 tests run on Windows and
Linux across Python 3.10 and 3.12, and CI installs this release with
`install.ps1` on a clean x64 and a clean ARM64 machine and runs the result. But no control in the catalogue has yet
executed against a live Windows machine — every probe and remediation was written
against Microsoft's documentation and exercised in demo mode, which fakes the
PowerShell round trip.

Try it on a machine you can afford to restore, and take a VM snapshot first.
Findings from real hardware are the most useful thing anyone could contribute.

**On ARM64 there is no embedded model.** `llama-cpp-python` publishes no ARM64
wheel, so the built-in planner is the product there. Everything else — scanner,
catalogue, executor, rollback, both applications — runs natively. `lares doctor`
says exactly what is and is not available on your machine.

**The executables are not code-signed**, so SmartScreen will warn on first run.
