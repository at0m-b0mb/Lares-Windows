"""Showing a conversation with the model while it is still happening.

Lares already records every exchange. ``lares transcript -v`` prints the whole
prompt and the whole reply, and the record is written whether anyone asked for
it or not. What it cannot do is show you the exchange *during* the exchange,
and on the hardware this targets that gap is the entire experience: a 1.5B
model on four cores answers at two or three tokens a second, so a planning
reply is a minute and a consultation is several. For all of that time a spinner
says nothing except that the process has not crashed yet.

This module is the other option. It attaches to the Engine, prints what is
being sent before generation starts, and then prints the answer one token at a
time as the model produces it. Nothing about the exchange changes - the same
prompt, the same reply, the same record afterwards. The difference is only
whether you can watch it.

Two details are not cosmetic:

* The spinner has to go. It rewrites its own line, which is exactly wrong next
  to output arriving a character at a time; the two would overwrite each other
  and leave neither readable. So live mode swaps it for plain progress lines.
* The system prompt is printed once. It is identical on every round of a
  consultation, and reprinting five hundred tokens of unchanged rules between
  every question buries the part that actually changed.
"""

from __future__ import annotations

import contextlib
from typing import Any, Callable, Iterator

from ..brain.engine import Reply, Watch
from .render import Console


def watch(console: Console, *, rules: bool = True) -> Watch:
    """A Watch that prints the exchange to *console* as it happens.

    Set *rules* false where the caller has already shown the system prompt
    itself and only wants the changing half echoed.
    """
    state = {"system": ""}

    def asked(system: str, user: str) -> None:
        console.blank()
        console.rule("sent to the model")
        if rules:
            if system != state["system"]:
                state["system"] = system
                console.section("The rules it is working under")
                console.script(system)
                console.blank()
            else:
                console.dim("  (the same rules as the exchange above)")
        console.section("What it is being told")
        console.script(user)
        console.blank()
        console.section("Its answer, as it is written")

    def token(text: str) -> None:
        console.token(text)

    def answered(reply: Reply) -> None:
        console.stream_end()
        console.blank()
        if reply.ok:
            console.field("Took", f"{reply.seconds:.1f}s at {reply.tps:.1f} tokens/s")
        else:
            console.error(f"The model did not answer: {reply.error}")

    return Watch(on_prompt=asked, on_token=token, on_reply=answered)


@contextlib.contextmanager
def progress(console: Console, live: bool, message: str) -> Iterator[Callable[..., Any]]:
    """A spinner normally; plain lines when model output is streaming.

    Yields the same update callable in both cases, so the caller does not have
    to know which one it got.
    """
    if not live:
        with console.status(message) as update:
            yield update
        return

    console.dim(f"  {message}...")

    def report(text: str = "") -> None:
        if text:
            console.dim(f"  {text}")

    yield report
