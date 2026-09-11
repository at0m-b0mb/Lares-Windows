"""Finding the right pages of the catalogue to put in front of the model.

A 3B model does not reliably remember what LSA protection does or which registry
value governs LLMNR, and asking it to is how hallucinated remediations happen.
It does not need to remember: the catalogue already contains a careful paragraph
about every control, written by a person. Retrieval puts the relevant ones into
the prompt, and the model's job shrinks from recall to judgement - which is the
thing small models are actually decent at.

This is BM25 over the control rationales, implemented here in about eighty lines
of standard library Python. No embedding model, no vector database, no extra
download. On a corpus of a few dozen documents with a query of a dozen words,
lexical ranking is not meaningfully worse than a neural one, and it runs in a
millisecond on hardware that would take ten seconds to embed the query.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from ..catalog.loader import Catalog
from ..core import Control

#: Standard BM25 parameters. k1 controls how fast term frequency saturates,
#: b how strongly document length is penalised.
K1 = 1.5
B = 0.75

_WORD = re.compile(r"[a-z0-9]+")

#: Words that carry no discriminating signal in a corpus that is entirely about
#: Windows security. "windows" appears in almost every document, so leaving it
#: in makes every query match everything a little.
_STOPWORDS = frozenset("""
a an and are as at be been by can could do does for from had has have how if in
into is it its may might must no not of on or should so than that the their then
there these they this to was were what when which who why will with would you
your machine windows system computer user users
""".split())


def tokenize(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS and len(w) > 2]


def _document_text(control: Control) -> str:
    """Everything about a control that is worth matching a query against.

    The scripts are deliberately excluded. Matching on PowerShell would rank a
    control highly because it happens to use Get-ItemProperty like every other
    registry control, which tells us nothing about relevance.
    """
    return " ".join([
        control.id,
        control.title,
        control.domain,
        control.rationale,
        control.blast_radius,
        " ".join(control.tags),
        " ".join(control.references),
    ])


@dataclass
class Hit:
    control: Control
    score: float

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Hit {self.control.id} {self.score:.2f}>"


@dataclass
class Index:
    """A BM25 index over a catalogue."""

    controls: list[Control] = field(default_factory=list)
    _tokens: list[list[str]] = field(default_factory=list)
    _counts: list[Counter] = field(default_factory=list)
    _df: Counter = field(default_factory=Counter)
    _avg_len: float = 0.0

    @classmethod
    def build(cls, catalog: Catalog) -> "Index":
        index = cls(controls=list(catalog))
        index._tokens = [tokenize(_document_text(c)) for c in index.controls]
        index._counts = [Counter(t) for t in index._tokens]
        for tokens in index._tokens:
            for term in set(tokens):
                index._df[term] += 1
        lengths = [len(t) for t in index._tokens]
        index._avg_len = (sum(lengths) / len(lengths)) if lengths else 1.0
        return index

    def _idf(self, term: str) -> float:
        n = len(self.controls)
        df = self._df.get(term, 0)
        if df == 0:
            return 0.0
        # The +0.5 smoothing keeps a term present in every document from going
        # negative, which would make a common word actively demote a match.
        return math.log(1 + (n - df + 0.5) / (df + 0.5))

    def search(self, query: str, limit: int = 6, boost: set[str] | None = None) -> list[Hit]:
        """Rank controls against a free-text query.

        *boost* is a set of control ids known to be directly relevant - the ones
        the scan actually raised. They get a large additive bonus, because a
        control that is definitely part of this conversation should never be
        crowded out of the context window by one that merely reads similarly.
        """
        terms = tokenize(query)
        if not terms and not boost:
            return []
        boost = boost or set()

        hits: list[Hit] = []
        for i, control in enumerate(self.controls):
            counts = self._counts[i]
            length = len(self._tokens[i]) or 1
            score = 0.0
            for term in terms:
                freq = counts.get(term, 0)
                if not freq:
                    continue
                denominator = freq + K1 * (1 - B + B * length / self._avg_len)
                score += self._idf(term) * (freq * (K1 + 1)) / denominator
            if control.id in boost:
                score += 100.0
            if score > 0:
                hits.append(Hit(control, score))

        hits.sort(key=lambda h: (-h.score, h.control.id))
        return hits[:limit]


def brief(control: Control, include_params: bool = True) -> str:
    """One control rendered for the prompt, compactly.

    Everything here earns its tokens. The model needs to know what the control
    is, why it matters, what it costs, what it takes, and whether it is allowed
    to choose it - and nothing else. The scripts are never shown: the model does
    not run them and cannot change them, so putting them in the context would
    only invite it to try.
    """
    lines = [
        f"### {control.id} - {control.title}",
        f"domain: {control.domain} | severity: {control.severity.value} | "
        f"risk: {control.risk.value} | takes effect: {control.effective}",
        f"why: {_squash(control.rationale)}",
    ]
    if control.blast_radius:
        lines.append(f"cost: {_squash(control.blast_radius)}")
    if not control.has_remediation:
        lines.append("NOTE: report-only. This control has no fix and must not be planned.")
    elif control.rollback_policy == "irreversible":
        lines.append("NOTE: cannot be undone, so it is never applied automatically.")
    if include_params and control.params:
        specs = []
        for spec in control.params:
            bits = [spec.type]
            if spec.choices:
                bits.append("one of " + "|".join(spec.choices))
            if spec.minimum is not None or spec.maximum is not None:
                bits.append(f"{spec.minimum}..{spec.maximum}")
            specs.append(f"{spec.name} ({', '.join(bits)}) - {spec.description}")
        lines.append("parameters: " + "; ".join(specs))
    else:
        lines.append("parameters: none")
    if control.depends_on:
        lines.append(f"apply after: {', '.join(control.depends_on)}")
    return "\n".join(lines)


def _squash(text: str, limit: int = 420) -> str:
    """Collapse a wrapped YAML paragraph into one line, trimmed for the prompt."""
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    cut = flat[:limit].rsplit(" ", 1)[0]
    return cut + "..."


def context_for(index: Index, queries: list[str], must_include: set[str],
                limit: int = 10) -> str:
    """Assemble the retrieved catalogue pages for one planning prompt."""
    scores: dict[str, float] = {}
    found: dict[str, Control] = {}
    for query in queries:
        for hit in index.search(query, limit=limit, boost=must_include):
            scores[hit.control.id] = max(scores.get(hit.control.id, 0.0), hit.score)
            found[hit.control.id] = hit.control

    ordered = sorted(found.values(), key=lambda c: (-scores[c.id], c.id))[:limit]
    return "\n\n".join(brief(c) for c in ordered)
