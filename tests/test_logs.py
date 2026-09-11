"""Tests for the record-keeping.

The point of these is not that logging works in the abstract, but that the
three properties Lares actually relies on hold:

* an error produces a report that can be found again by the id the user was
  shown, with the traceback attached;
* the transcript records what the model was *asked*, what it *said*, and what
  was then *done with it* - the third part being the one that makes the record
  worth keeping;
* nothing in here can take down the agent, including a torn line, an
  unserialisable value, or a directory that cannot be written.
"""

from __future__ import annotations

import json

import pytest

from lares import logs


@pytest.fixture()
def log(tmp_path) -> logs.Log:
    return logs.Log(tmp_path / "logs", level=logs.Level.DEBUG)


@pytest.fixture()
def tape(tmp_path) -> logs.Transcript:
    return logs.Transcript(tmp_path / "logs" / "transcript.jsonl")


# --------------------------------------------------------------------------
# The narrative
# --------------------------------------------------------------------------

def test_writes_both_a_readable_and_a_parseable_copy(log):
    log.info("scan", "Scan finished", findings=28)

    assert "Scan finished" in log.text_path.read_text(encoding="utf-8")
    payload = json.loads(log.json_path.read_text(encoding="utf-8").strip())
    assert payload["area"] == "scan"
    assert payload["fields"]["findings"] == 28


def test_level_filter_suppresses_quieter_lines(tmp_path):
    log = logs.Log(tmp_path / "logs", level=logs.Level.WARN)
    log.debug("scan", "noisy")
    log.info("scan", "ordinary")
    log.warn("scan", "worth knowing")

    assert not log.json_path.exists() or "noisy" not in log.json_path.read_text()
    assert [r.message for r in log.tail()] == ["worth knowing"]


def test_tail_filters_by_level_and_area(log):
    log.info("scan", "a")
    log.warn("plan", "b")
    log.error("act", "c")

    assert [r.message for r in log.tail(area="plan")] == ["b"]
    warnings = log.tail(level=logs.Level.WARN)
    assert {r.message for r in warnings} == {"b", "c"}


def test_a_torn_final_line_does_not_lose_the_history(log):
    log.info("scan", "first")
    log.info("scan", "second")
    with log.json_path.open("a", encoding="utf-8") as fh:
        fh.write('{"at": "2026-01-01T00:00:00Z", "lev')  # interrupted write

    assert [r.message for r in log.tail()] == ["first", "second"]


def test_unserialisable_context_is_kept_as_text_rather_than_lost(log):
    class Opaque:
        def __str__(self) -> str:
            return "an opaque thing"

    log.info("act", "applied", thing=Opaque())
    assert log.tail()[0].fields["thing"] == "an opaque thing"


def test_rotation_keeps_the_log_from_growing_without_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(logs, "MAX_BYTES", 400)
    log = logs.Log(tmp_path / "logs", level=logs.Level.DEBUG)
    for index in range(60):
        log.info("scan", f"line {index} padded out to force a rollover")

    rotated = list((tmp_path / "logs").glob("lares.jsonl.*"))
    assert rotated, "expected at least one rotated generation"
    assert log.json_path.stat().st_size < 4000


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

def test_an_error_is_findable_by_the_id_the_user_was_shown(log):
    try:
        raise RuntimeError("Access is denied")
    except RuntimeError as exc:
        report = log.error("act", "NET-001 failed", exc=exc, control="NET-001")

    assert report.error_id.startswith("LR-")
    found = log.find_error(report.error_id)
    assert found is not None
    assert found.message == "NET-001 failed"
    assert found.exception_type == "RuntimeError"
    assert "Access is denied" in found.exception_text
    assert "RuntimeError" in found.traceback_text
    assert found.context["control"] == "NET-001"


def test_the_error_id_is_case_insensitive_because_people_retype_it(log):
    report = log.error("act", "something", exc=ValueError("x"))
    assert log.find_error(report.error_id.lower()) is not None


def test_an_error_also_appears_in_the_narrative_with_its_id(log):
    report = log.error("cycle", "cycle raised", exc=ValueError("boom"))
    record = log.tail()[-1]
    assert record.level is logs.Level.ERROR
    assert record.error_id == report.error_id


def test_an_error_captures_the_environment_at_the_time_it_happened(log):
    report = log.error("system", "whatever", exc=ValueError("x"))
    assert report.environment["lares"]
    assert report.environment["python"]


def test_errors_are_listed_newest_first(log):
    first = log.error("act", "one", exc=ValueError("1"))
    second = log.error("act", "two", exc=ValueError("2"))
    listed = [r.error_id for r in log.errors()]
    assert listed.index(second.error_id) < listed.index(first.error_id)


def test_a_log_directory_that_cannot_be_written_does_not_raise(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("I am a file, not a directory", encoding="utf-8")
    log = logs.Log(blocked, level=logs.Level.DEBUG)

    log.info("scan", "this has nowhere to go")          # must not raise
    report = log.error("scan", "nor this", exc=ValueError("x"))
    assert report.error_id                               # still gets an id


# --------------------------------------------------------------------------
# The model transcript
# --------------------------------------------------------------------------

def _exchange(**overrides) -> logs.Exchange:
    base = dict(
        purpose="plan",
        model="Qwen2.5-Coder-3B",
        system="You are Lares.",
        prompt="NET-001 firewall off",
        reply='{"actions": [{"control_id": "NET-001"}]}',
        tokens=120,
        seconds=8.0,
        accepted=["NET-001"],
        rejected={"XXX-999": "not in the catalogue"},
        cycle_id="cyc-1",
    )
    base.update(overrides)
    return logs.Exchange(**base)


def test_an_exchange_records_what_was_done_with_the_answer(tape):
    tape.record(_exchange())
    back = tape.recent()[0]

    assert back.prompt == "NET-001 firewall off"
    assert back.accepted == ["NET-001"]
    assert back.rejected == {"XXX-999": "not in the catalogue"}
    assert back.cycle_id == "cyc-1"


def test_an_exchange_gets_an_id_so_it_can_be_referred_to(tape):
    recorded = tape.record(_exchange())
    assert recorded.exchange_id
    assert tape.find(recorded.exchange_id) is not None


def test_turning_off_prompt_retention_keeps_the_part_that_matters(tmp_path):
    tape = logs.Transcript(tmp_path / "t.jsonl", keep_prompts=False)
    tape.record(_exchange())

    raw = json.loads(tape.path.read_text(encoding="utf-8").strip())
    assert "prompt" not in raw and "reply" not in raw
    assert raw["prompt_chars"] > 0
    # The audit trail survives redaction; that is the whole design.
    assert raw["accepted"] == ["NET-001"]
    assert raw["rejected"] == {"XXX-999": "not in the catalogue"}


def test_a_disabled_transcript_writes_nothing_but_still_returns_the_exchange(tmp_path):
    tape = logs.Transcript(tmp_path / "t.jsonl", enabled=False)
    recorded = tape.record(_exchange())

    assert not tape.path.exists()
    assert recorded.exchange_id


def test_headline_reports_a_failure_rather_than_counting_zero_actions():
    failed = logs.Exchange(purpose="plan", ok=False, error="model did not load")
    assert "failed" in failed.headline()
    assert "model did not load" in failed.headline()


def test_headline_counts_what_survived_the_guard():
    assert "1 accepted, 1 rejected" in _exchange().headline()


def test_tokens_per_second_is_zero_rather_than_dividing_by_zero():
    assert logs.Exchange(tokens=10, seconds=0.0).tps == 0.0


def test_markdown_export_shows_the_refusals(tape):
    tape.record(_exchange())
    text = tape.as_markdown()

    assert "Qwen2.5-Coder-3B" in text
    assert "Refused by the guard" in text
    assert "XXX-999" in text
    assert "NET-001 firewall off" in text


def test_markdown_export_says_so_when_there_is_nothing(tape):
    assert "No exchanges recorded yet" in tape.as_markdown()


# --------------------------------------------------------------------------
# Process wiring
# --------------------------------------------------------------------------

def test_configure_replaces_the_shared_instances(tmp_path):
    logs.configure(directory=tmp_path / "one", level=logs.Level.DEBUG)
    logs.get().info("scan", "hello")
    assert (tmp_path / "one" / "lares.jsonl").exists()
    assert logs.transcript().path.parent == tmp_path / "one"


def test_subscribers_see_records_as_they_are_written(log):
    seen: list[logs.Record] = []
    log.subscribe(seen.append)
    log.info("scan", "watch me")
    assert [r.message for r in seen] == ["watch me"]


def test_a_broken_subscriber_cannot_stop_the_log(log):
    def explode(record):
        raise RuntimeError("the view is on fire")

    log.subscribe(explode)
    log.info("scan", "still written")          # must not raise
    assert log.tail()[-1].message == "still written"
