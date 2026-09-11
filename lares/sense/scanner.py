"""Looking at the machine.

There is no separate detection logic in Lares. The scanner runs each control's
own ``detect`` probe from the catalogue and turns every non-compliant answer into
a Finding. That is a deliberate structural choice: the code that decides a
problem exists is the exact same code that later decides the fix worked, so the
two can never drift apart. A control whose probe is wrong is wrong consistently,
which is a bug you can find, rather than intermittently, which is a bug you
cannot.

Probes are run in parallel because most of the time is spent waiting on
PowerShell rather than computing anything, and a sequential pass over thirty
controls on a slow machine takes minutes.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .. import logs
from ..act.execute import ProbeReading, demo_reading, read_probe
from ..catalog.loader import Catalog
from ..core import Control, Fact, Finding, Scan, Severity, dedupe, utcnow
from ..demo_data import FACTS as DEMO_FACTS
from ..winsys import is_demo
from . import facts as facts_mod

#: More than this many concurrent PowerShell processes hurts on a 2-core box,
#: which is squarely the hardware this is meant to run on.
MAX_WORKERS = 4

Progress = Callable[[str, int, int], None]


def findings_from(control: Control, reading: ProbeReading) -> list[Finding]:
    """Turn one probe answer into zero or more findings.

    A probe that reports ``instances`` produces one finding per instance, each
    carrying its own parameters - three open ports are three separate problems
    with three separate fixes, not one finding that has to be fixed three times.
    """
    if not reading.usable:
        return []
    if reading.compliant:
        return []

    common = dict(
        control_id=control.id,
        title=control.title,
        severity=control.severity,
        detail=control.rationale,
        domain=control.domain,
        remediable=control.has_remediation,
        expected="compliant with " + control.id,
    )

    if reading.instances:
        out: list[Finding] = []
        for raw in reading.instances:
            if not isinstance(raw, dict):
                continue
            params = raw.get("params")
            out.append(Finding(
                **common,
                observed=str(raw.get("observed", "") or reading.observed),
                evidence=str(raw.get("evidence", "") or reading.evidence),
                params=params if isinstance(params, dict) else {},
            ))
        if out:
            return out
        # An instances array that parsed to nothing usable still means the
        # control is non-compliant, so fall through to the single-finding form
        # rather than silently losing the problem.

    return [Finding(
        **common,
        observed=reading.observed,
        evidence=reading.evidence,
        params=reading.params or {},
    )]


def scan(
    catalog: Catalog,
    *,
    domains: list[str] | None = None,
    only: list[str] | None = None,
    progress: Progress | None = None,
    workers: int = MAX_WORKERS,
) -> Scan:
    """Run every applicable probe and collect what is wrong with the machine.

    *only* restricts the pass to named controls. The model-led consultation
    uses it to run exactly the checks the model asked for and no others, so
    that what it is shown is what it requested rather than everything.
    """
    started = time.monotonic()
    result = Scan(demo=is_demo())

    wanted = {c.strip().upper() for c in only} if only else None
    controls = [
        c for c in catalog
        if (not domains or c.domain in domains) and (wanted is None or c.id in wanted)
    ]
    total = len(controls)

    if result.demo:
        result.facts = [Fact(k, v, d, s) for k, v, d, s in DEMO_FACTS]
    else:
        result.facts = facts_mod.gather()

    if result.demo:
        for index, control in enumerate(controls, start=1):
            if progress:
                progress(control.id, index, total)
            result.findings.extend(findings_from(control, demo_reading(control.id)))
    else:
        done = 0
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(read_probe, c): c for c in controls}
            for future in as_completed(futures):
                control = futures[future]
                done += 1
                if progress:
                    progress(control.id, done, total)
                try:
                    reading = future.result()
                except Exception as exc:  # noqa: BLE001 - one bad probe must not end the scan
                    # A probe raising rather than returning an error is a bug in
                    # the probe, so it gets a full report with the traceback -
                    # unlike a probe that simply could not read its value, which
                    # is an ordinary condition on a locked-down machine.
                    report = logs.get().error(
                        "scan", f"Probe {control.id} raised", exc=exc,
                        control=control.id, domain=control.domain,
                    )
                    result.errors[control.id] = f"{str(exc)[:280]} ({report.error_id})"
                    continue
                if not reading.usable:
                    result.errors[control.id] = reading.error
                    continue
                result.findings.extend(findings_from(control, reading))

    result.findings = dedupe(result.findings)
    result.findings.sort(key=lambda f: (-f.severity.rank, f.control_id))
    result.duration_ms = int((time.monotonic() - started) * 1000)
    result.finished_at = utcnow()
    return result


def posture(result: Scan) -> tuple[str, str]:
    """A one-line verdict and a supporting sentence.

    Lares does not tell anyone their machine is secure. The best grade it gives
    is "nothing outstanding", because a clean run against thirty controls means
    thirty specific things were checked, not that the machine is safe.
    """
    counts = result.counts()
    critical = counts[Severity.CRITICAL]
    high = counts[Severity.HIGH]

    if critical:
        return ("Needs attention now",
                f"{critical} critical and {high} high-severity finding(s) are open.")
    if high:
        return ("Weak", f"{high} high-severity finding(s) are open.")
    if counts[Severity.MEDIUM]:
        return ("Fair", f"{counts[Severity.MEDIUM]} medium-severity finding(s) remain.")
    if counts[Severity.LOW] or counts[Severity.INFO]:
        return ("Good", "Only low-severity findings remain.")
    return ("Nothing outstanding",
            "Every control Lares checks is in the desired state. That is not the "
            "same as being secure - it means these particular checks passed.")
