"""Whether what Lares did stayed done, and what else moved on the machine.

A hardening tool that fixes something once and never looks again is half a
tool. These two features answer the half that was missing, and they answer it
without a model and without changing anything.
"""

from __future__ import annotations

import copy


from lares.act.journal import Journal
from lares.catalog import loader
from lares.core import Outcome, Status
from lares.sense import baseline as baseline_mod
from lares.sense import drift as drift_mod
from lares.sense import surface as surface_mod

CATALOG = loader.load()


# --------------------------------------------------------------------------
# Comparing two readings of the machine
# --------------------------------------------------------------------------

def moved(before, after):
    return {c.subject: c for c in baseline_mod.compare(before, after).changes}


def test_a_new_listening_port_is_seen():
    before = surface_mod.survey()
    after = copy.deepcopy(before)
    after.get("ports").rows.append(
        {"proto": "TCP", "port": 4444, "address": "0.0.0.0",
         "process": "nc", "exposed": True})

    change = moved(before, after)["TCP/4444 on 0.0.0.0"]
    assert change.kind == "appeared"
    assert change.section == "ports"


def test_a_port_that_stopped_listening_is_seen():
    before = surface_mod.survey()
    after = copy.deepcopy(before)
    after.get("ports").rows = [r for r in after.get("ports").rows
                               if r.get("port") != 445]
    assert moved(before, after)["TCP/445 on 0.0.0.0"].kind == "gone"


def test_an_account_becoming_an_administrator_is_a_change_not_a_new_account():
    """The single most important row in this comparison."""
    before = surface_mod.survey()
    after = copy.deepcopy(before)
    for row in after.get("accounts").rows:
        if row["name"] == "Guest":
            row["admin"] = True

    change = moved(before, after)["Guest"]
    assert change.kind == "changed"
    assert "administrator" in change.after and "administrator" not in change.before


def test_a_software_update_is_one_change_not_a_removal_and_an_addition():
    """Getting this wrong turns every Patch Tuesday into forty findings, which
    is how a change report becomes something nobody reads."""
    before = surface_mod.survey()
    after = copy.deepcopy(before)
    after.get("software").rows[1]["version"] = "999.0"

    changes = baseline_mod.compare(before, after).changes
    assert len(changes) == 1
    assert changes[0].kind == "changed"


def test_an_unchanged_machine_reports_nothing():
    before = surface_mod.survey()
    comparison = baseline_mod.compare(before, copy.deepcopy(before))
    assert comparison.quiet
    assert baseline_mod.summarise(comparison) == "nothing changed"


def test_a_view_that_could_not_be_read_is_not_a_view_where_nothing_changed():
    """Silence that looks like an all-clear is the worst answer available."""
    before = surface_mod.survey()
    after = copy.deepcopy(before)
    after.get("ports").error = "the collector timed out"

    comparison = baseline_mod.compare(before, after)
    assert "ports" in comparison.skipped
    assert not any(c.section == "ports" for c in comparison.changes)
    assert "could not be compared" in baseline_mod.summarise(comparison)


def test_a_malformed_row_does_not_stop_the_comparison():
    before = surface_mod.survey()
    after = copy.deepcopy(before)
    after.get("ports").rows.insert(0, {})
    baseline_mod.compare(before, after)      # must not raise


# --------------------------------------------------------------------------
# Keeping readings
# --------------------------------------------------------------------------

def test_a_demo_reading_is_never_recorded(tmp_path, monkeypatch):
    """Synthetic readings in the real history make every later comparison a
    fiction."""
    monkeypatch.setattr(baseline_mod, "directory", lambda: tmp_path)
    found = surface_mod.survey()
    assert found.demo
    assert baseline_mod.save(found) is None
    assert list(tmp_path.glob("*.json")) == []


def test_a_reading_survives_a_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline_mod, "directory", lambda: tmp_path)
    found = surface_mod.survey()
    found.demo = False

    assert baseline_mod.save(found) is not None
    back = baseline_mod.latest()
    assert back is not None
    assert {s.key for s in back.sections} == {s.key for s in found.sections}
    assert baseline_mod.compare(found, back).quiet, "a round trip changed it"


def test_old_readings_are_pruned(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline_mod, "directory", lambda: tmp_path)
    monkeypatch.setattr(baseline_mod, "KEEP", 3)
    for index in range(6):
        found = surface_mod.survey()
        found.demo = False
        found.at = f"2026-01-0{index + 1}T00:00:00Z"
        baseline_mod.save(found)
    assert len(list(tmp_path.glob("surface-*.json"))) == 3


def test_an_unreadable_file_is_skipped_rather_than_crashing(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline_mod, "directory", lambda: tmp_path)
    found = surface_mod.survey()
    found.demo = False
    found.at = "2026-01-01T00:00:00Z"
    baseline_mod.save(found)
    (tmp_path / "surface-99999999T999999.json").write_text("{ truncated", encoding="utf-8")

    assert baseline_mod.latest() is not None, "one bad file hid every good one"


def test_no_history_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline_mod, "directory", lambda: tmp_path)
    assert baseline_mod.latest() is None
    assert baseline_mod.history() == []


# --------------------------------------------------------------------------
# Did what Lares applied hold?
# --------------------------------------------------------------------------

def journal_with(tmp_path, entries):
    journal = Journal(path=tmp_path / "actions.jsonl")
    for control_id, status in entries:
        journal.record(Outcome(control_id=control_id, status=status,
                               change_in_place=status in drift_mod.APPLIED),
                       control_title=f"{control_id} title")
    return journal


def test_only_controls_that_were_actually_applied_are_checked(tmp_path):
    journal = journal_with(tmp_path, [
        ("NET-005", Status.VERIFIED),
        ("NET-004", Status.REFUSED),        # never ran
        ("SVC-003", Status.SIMULATED),      # dry run
        ("IDN-002", Status.UNVERIFIED),     # ran, nothing proved it
    ])
    report = drift_mod.check(CATALOG, journal)
    assert {d.control_id for d in report.checked} == {"NET-005", "IDN-002"}


def test_a_control_the_catalogue_no_longer_has_is_reported_not_dropped(tmp_path):
    """The change is still on the machine and there is no probe left to ask."""
    journal = journal_with(tmp_path, [("ZZZ-999", Status.VERIFIED)])
    report = drift_mod.check(CATALOG, journal)
    assert [d.state for d in report.checked] == [drift_mod.GONE]
    assert "no longer in the catalogue" in report.checked[0].detail


def test_repeated_applications_are_counted(tmp_path):
    """It did not hold the last three times either, which is the signal."""
    journal = journal_with(tmp_path, [("NET-005", Status.VERIFIED)] * 3)
    report = drift_mod.check(CATALOG, journal)
    entry = next(d for d in report.checked if d.control_id == "NET-005")
    assert entry.applications == 3 and entry.repeated


def test_an_empty_journal_says_so_rather_than_claiming_everything_held(tmp_path):
    report = drift_mod.check(CATALOG, Journal(path=tmp_path / "none.jsonl"))
    verdict, _ = report.headline()
    assert verdict == "Nothing to check"


def test_a_probe_that_cannot_run_is_not_counted_as_held(tmp_path, monkeypatch):
    """Unknown is a third state on purpose. Folding it into either of the
    other two is how a security tool ends up lying in one direction."""
    from lares.act.execute import ProbeReading

    monkeypatch.setattr(drift_mod, "read_probe",
                        lambda c, p=None: ProbeReading(compliant=False, error="access denied"))
    journal = journal_with(tmp_path, [("NET-005", Status.VERIFIED)])
    report = drift_mod.check(CATALOG, journal)

    assert report.checked[0].state == drift_mod.UNKNOWN
    assert report.undone == []
    verdict, detail = report.headline()
    assert "as far as could be checked" in verdict
    assert "not counted either way" in detail


def test_a_control_that_came_undone_is_reported(tmp_path, monkeypatch):
    from lares.act.execute import ProbeReading

    monkeypatch.setattr(drift_mod, "read_probe", lambda c, p=None: ProbeReading(
        compliant=False, observed="LLMNR is enabled again"))
    journal = journal_with(tmp_path, [("NET-005", Status.VERIFIED)])
    report = drift_mod.check(CATALOG, journal)

    assert [d.state for d in report.checked] == [drift_mod.UNDONE]
    assert "come undone" in report.headline()[0]


def test_everything_holding_is_said_plainly(tmp_path, monkeypatch):
    from lares.act.execute import ProbeReading

    monkeypatch.setattr(drift_mod, "read_probe",
                        lambda c, p=None: ProbeReading(compliant=True))
    journal = journal_with(tmp_path, [("NET-005", Status.VERIFIED)])
    assert drift_mod.check(CATALOG, journal).headline()[0] == "Everything held"


def test_only_narrows_what_is_rechecked(tmp_path, monkeypatch):
    from lares.act.execute import ProbeReading

    monkeypatch.setattr(drift_mod, "read_probe",
                        lambda c, p=None: ProbeReading(compliant=True))
    journal = journal_with(tmp_path, [("NET-005", Status.VERIFIED),
                                      ("SVC-003", Status.VERIFIED)])
    report = drift_mod.check(CATALOG, journal, only=["net-005"])
    assert [d.control_id for d in report.checked] == ["NET-005"]


# --------------------------------------------------------------------------
# The command, and the cycle it can start
# --------------------------------------------------------------------------

def test_the_drift_command_reports_without_changing_anything(capsys):
    from lares.cli.app import build_parser
    from lares.cli.render import Console

    args = build_parser().parse_args(["drift"])
    assert args.func(args, Console(plain=True)) == 0
    out = capsys.readouterr().out
    assert "CHANGES LARES MADE" in out
    assert "THE MACHINE ITSELF" in out


def test_a_narrowed_cycle_runs_only_those_probes(monkeypatch):
    """--fix re-applies what came undone and must not touch anything else."""
    from lares import config as config_mod
    from lares.autonomy.loop import build

    seen = {}
    real = drift_mod.__dict__  # keep a handle so the import is clearly used
    assert real is not None

    from lares.sense import scanner as scanner_mod
    original = scanner_mod.scan
    monkeypatch.setattr(
        scanner_mod, "scan",
        lambda catalog, **kw: seen.update(kw) or original(catalog, **kw))

    agent, _ = build(config_mod.Settings(dry_run=True), CATALOG, with_model=False)
    agent.run_cycle(only=["NET-005"])
    assert seen.get("only") == ["NET-005"]


def test_the_menu_and_help_offer_it():
    from lares.cli.app import build_parser
    from lares.cli.interactive import ITEMS

    parser = build_parser()
    parser.parse_args(["drift", "--fix"])
    for _, _, argv in ITEMS:
        parser.parse_args(argv)


def test_a_fresh_history_is_due_and_a_recent_one_is_not(tmp_path, monkeypatch):
    """A history nobody remembers to feed is a feature that never works."""
    monkeypatch.setattr(baseline_mod, "directory", lambda: tmp_path)
    assert baseline_mod.due(), "no history at all must be due"

    from lares.core import utcnow
    found = surface_mod.survey()
    found.demo = False
    found.at = utcnow()
    baseline_mod.save(found)

    assert not baseline_mod.due(max_age_hours=12)
    assert baseline_mod.due(max_age_hours=0)


def test_an_unreadable_timestamp_counts_as_due(tmp_path, monkeypatch):
    """Treating it as recent means one corrupt file silently stops the history
    ever growing again."""
    monkeypatch.setattr(baseline_mod, "directory", lambda: tmp_path)
    found = surface_mod.survey()
    found.demo = False
    found.at = "not a date"
    baseline_mod.save(found)
    assert baseline_mod.due()


def test_the_cycle_records_a_reading_when_one_is_due(monkeypatch):
    from lares import config as config_mod
    from lares.autonomy import loop as loop_mod
    from lares.autonomy.loop import build

    taken = []
    monkeypatch.setattr(loop_mod.baseline, "due", lambda *a, **k: True)
    monkeypatch.setattr(loop_mod.baseline, "save", lambda s: taken.append(s))

    agent, _ = build(config_mod.Settings(dry_run=True), CATALOG, with_model=False)
    agent.run_cycle()
    assert len(taken) == 1


def test_the_cycle_does_not_record_when_one_is_not_due(monkeypatch):
    from lares import config as config_mod
    from lares.autonomy import loop as loop_mod
    from lares.autonomy.loop import build

    taken = []
    monkeypatch.setattr(loop_mod.baseline, "due", lambda *a, **k: False)
    monkeypatch.setattr(loop_mod.baseline, "save", lambda s: taken.append(s))

    agent, _ = build(config_mod.Settings(dry_run=True), CATALOG, with_model=False)
    agent.run_cycle()
    assert taken == []


def test_a_failed_recording_does_not_cost_the_cycle(monkeypatch):
    """Never lose a hardening pass to a bookkeeping error."""
    from lares import config as config_mod
    from lares.autonomy import loop as loop_mod
    from lares.autonomy.loop import build

    monkeypatch.setattr(loop_mod.baseline, "due", lambda *a, **k: True)
    monkeypatch.setattr(loop_mod.baseline, "save",
                        lambda s: (_ for _ in ()).throw(OSError("disk full")))

    agent, _ = build(config_mod.Settings(dry_run=True), CATALOG, with_model=False)
    cycle = agent.run_cycle()
    assert not cycle.halted, "a failed recording halted the cycle"
