"""The reading of the machine, and the two applications that show it.

The survey has no opinions, which is the property worth protecting: the moment
it starts deciding that an open port is bad, the freehand lane's claim to have
nothing hardcoded in it becomes false. So most of what is asserted here is
about what it does *not* do.
"""

from __future__ import annotations

import json

from lares.sense import surface as surface_mod


def survey():
    return surface_mod.survey()


def test_every_reading_is_present_and_parsed():
    found = survey()
    keys = {s.key for s in found.sections}
    assert keys == {k for k, _, _ in surface_mod.COLLECTORS}
    assert all(s.ok for s in found.sections), found.failures


def test_the_reading_is_labelled_synthetic_off_windows():
    """Invented findings shown without saying so are worse than none."""
    for section in survey().sections:
        assert "synthetic" in section.note


def test_a_derived_note_never_erases_the_synthetic_warning():
    """Enrichment runs after the label is set, and once overwrote it."""
    found = survey()
    ports = found.get("ports")
    assert "synthetic" in ports.note
    assert "bound to every interface" in ports.note


def test_nothing_in_the_reading_grades_anything():
    """No severity, no verdict, no should. It reads; the model decides."""
    text = found = survey().render()
    for word in ("critical", "severity", "vulnerable", "insecure", "you should"):
        assert word not in text.lower(), f"the survey formed an opinion: {word}"
    assert found


def test_exposed_is_a_fact_about_the_binding_not_a_judgement():
    rows = {r["port"]: r for r in survey().rows("ports")}
    assert rows[445]["exposed"] is True          # 0.0.0.0
    assert rows[8080]["exposed"] is False        # 127.0.0.1


def test_an_unquoted_service_path_is_flagged_only_when_it_is_one():
    rows = {r["name"]: r for r in survey().rows("services")}
    assert rows["VulnAgent"]["unquoted"] is True
    assert rows["Spooler"]["unquoted"] is False, "no space, nothing to hijack"
    assert rows["sshd"]["unquoted"] is False


def test_a_view_that_was_not_read_is_not_a_view_that_found_nothing():
    """The distinction every summary line depends on."""
    found = surface_mod.survey(only=["ports"])
    assert found.has("ports")
    assert not found.has("software")
    assert found.rows("software") == []


def test_render_trims_to_a_budget_without_dropping_a_heading():
    found = survey()
    for budget in (2000, 900, 600, 300):
        tight = found.render(budget=budget)
        assert len(tight) <= budget, "the budget is a ceiling, not a suggestion"
    roomy = found.render(budget=2400)
    for section in found.sections:
        assert section.title in roomy, "a heading is how you know what is missing"


def test_a_cut_reading_says_that_it_was_cut():
    """A truncated list with no marker is a list a model will trust whole."""
    assert surface_mod.CUT_NOTE in survey().render(budget=300)


def test_render_can_omit_headings_for_a_caller_that_prints_its_own():
    found = surface_mod.survey(only=["ports"])
    assert "== Listening ports ==" in found.render()
    assert "==" not in found.render(headers=False)


def test_only_narrows_what_is_read_rather_than_what_is_shown():
    found = surface_mod.survey(only=["ports", "accounts"])
    assert {s.key for s in found.sections} == {"ports", "accounts"}


def test_both_applications_word_a_row_the_same_way():
    """The terminal and the window render rows through one function.

    Two formatters agreeing today is how a port comes to read "REACHABLE FROM
    THE NETWORK" in one place and something softer in the other.
    """
    import inspect

    from lares.gui import main_window

    source = inspect.getsource(main_window.ExposurePage.refresh)
    assert "surface_mod.line(" in source
    assert "REACHABLE" not in source, "the window is re-wording rows itself"


# --------------------------------------------------------------------------
# The command
# --------------------------------------------------------------------------

def run_cli(argv, capsys):
    from lares.cli.app import build_parser
    from lares.cli.render import Console

    args = build_parser().parse_args(argv)
    code = args.func(args, Console(plain=True))
    return code, capsys.readouterr().out


def test_surface_command_reports_without_changing_anything(capsys):
    code, out = run_cli(["surface"], capsys)
    assert code == 0
    assert "Nothing was changed" in out
    assert "REACHABLE FROM THE NETWORK" in out


def test_surface_command_says_not_read_rather_than_zero(capsys):
    """A count of 0 and a reading that never happened look identical."""
    _, out = run_cli(["surface", "--only", "ports"], capsys)
    assert "Installed products     not read" in out
    assert "Installed products     0" not in out


def test_surface_command_prints_each_heading_once(capsys):
    """The section title came from the page and from render(), both."""
    _, out = run_cli(["surface", "--only", "ports"], capsys)
    assert out.lower().count("listening ports") == 1


def test_surface_command_emits_usable_json(capsys):
    _, out = run_cli(["surface", "--json"], capsys)
    payload = json.loads(out)
    assert {s["key"] for s in payload["sections"]} == {
        k for k, _, _ in surface_mod.COLLECTORS}
    assert payload["demo"] is True


def test_the_menu_offers_it_and_the_help_names_the_other_program():
    from lares.cli.app import build_parser
    from lares.cli.interactive import ITEMS

    parser = build_parser()
    assert any(argv == ["surface"] for _, _, argv in ITEMS)
    for _, _, argv in ITEMS:
        parser.parse_args(argv)
    assert "lares-freehand" in (parser.epilog or "")


# --------------------------------------------------------------------------
# What the collectors do when the machine answers oddly
# --------------------------------------------------------------------------

class Fake:
    """One PowerShell result, shaped the way winsys returns them."""

    def __init__(self, stdout="", ok=True, stderr="", error=""):
        self.stdout, self.ok, self.stderr, self.error = stdout, ok, stderr, error

    @property
    def text(self):
        return self.stdout.strip()

    def json(self, default=None):
        import json as _json
        try:
            return _json.loads(self.stdout)
        except ValueError:
            return default


def collect(monkeypatch, result):
    """Run one collector against a canned answer, as if on Windows."""
    monkeypatch.setattr(surface_mod, "is_demo", lambda: False)
    monkeypatch.setattr(surface_mod, "IS_WINDOWS", True)
    monkeypatch.setattr(surface_mod, "powershell", lambda *a, **k: result)
    return surface_mod._collect("software", "Installed software", "irrelevant")


def test_a_reading_that_found_nothing_is_not_a_reading_that_failed(monkeypatch):
    """ConvertTo-Json prints nothing at all for an empty set.

    Read as a parse failure, every empty result became "could not be read" -
    which tells the model a view is unavailable when it was read perfectly
    well, and there is a real difference between "no third-party software" and
    "I could not see the software".
    """
    section = collect(monkeypatch, Fake(stdout="   \n"))
    assert section.ok, section.error
    assert section.rows == []


def test_one_object_is_read_as_one_row(monkeypatch):
    """ConvertTo-Json emits a bare object for a single item, an array for many."""
    section = collect(monkeypatch, Fake(stdout='{"name": "7-Zip", "version": "19.00"}'))
    assert [r["name"] for r in section.rows] == ["7-Zip"]


def test_output_that_is_not_json_is_reported_as_such(monkeypatch):
    section = collect(monkeypatch, Fake(stdout="Get-ItemProperty : Access denied"))
    assert not section.ok
    assert "not usable JSON" in section.error


def test_a_collector_that_could_not_run_says_why(monkeypatch):
    section = collect(monkeypatch, Fake(ok=False, error="timed out after 90s"))
    assert not section.ok
    assert "timed out" in section.error


def test_a_collector_failing_does_not_stop_the_others(monkeypatch):
    """A survey missing one view is worth far more than no survey."""
    monkeypatch.setattr(surface_mod, "is_demo", lambda: False)
    monkeypatch.setattr(surface_mod, "IS_WINDOWS", True)

    calls = {"n": 0}

    def flaky(script, timeout=0):
        calls["n"] += 1
        if calls["n"] == 2:
            return Fake(ok=False, error="that one broke")
        return Fake(stdout="[]")

    monkeypatch.setattr(surface_mod, "powershell", flaky)
    found = surface_mod.survey()
    assert len(found.sections) == len(surface_mod.COLLECTORS)
    assert len(found.failures) == 1
