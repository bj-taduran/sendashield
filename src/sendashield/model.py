"""Canonical types shared across detection, policy and the pipeline.

`Span` is the unit every detector returns and every later layer merges. Its shape is not
arbitrary: it mirrors `expected_spans[]` in `tests/fixtures/expected.schema.json` field for
field, so a fixture's claim and a detector's output are the same thing and can be compared
directly rather than through a translation step that could itself be wrong.
"""

from __future__ import annotations

from dataclasses import dataclass


class DetectionError(Exception):
    """Raised when a detector cannot complete a scan.

    The pipeline converts this to quarantine (CLAUDE.md invariant 2, "fail closed"). It
    exists so that a detector never has to choose between returning a wrong answer and
    returning nothing: it raises, and the item is withheld.

    **Never put matched text in the message.** These messages reach logs, and CLAUDE.md
    invariant 5 forbids content leaving memory. Describe the failure by position, length or
    type — never by value.
    """


@dataclass(frozen=True, slots=True)
class Span:
    """A region of normalised text that a detector claims is sensitive.

    `start`/`end` are indices into the string `normalise()` / `normalise_calendar()`
    returned — the coordinate system documented in `normalise.py`. `text` is the exact
    slice, carried alongside the offsets so that a merge step, an audit record, or a test
    can check the two still agree without re-deriving the slice from a document it may no
    longer hold.

    `text` includes any internal separators (`4000 0025 0000 3155`, not `4000002500003155`)
    because masking replaces the span verbatim. A span covering only the digits would leave
    the separators behind as visible fragments of the identifier.
    """

    detector: str
    start: int
    end: int
    text: str


@dataclass(frozen=True, slots=True)
class DetectorConfig:
    """Per-scan configuration handed to every `detect()`.

    Deliberately empty. It exists now so the signature `detect(text, config)` is fixed
    before five more detectors copy it, rather than being retrofitted later across all of
    them — but nothing in this milestone needs a knob, and inventing one to fill the class
    would be worse than leaving it bare.

    **What must never be added here**: anything that can weaken a checksum — no
    `require_luhn=False`, no `min_digits` override, no per-detector disable that a caller
    could set from model-influenced input. CLAUDE.md invariant 3 makes an L1 detection
    absolute, and a config field able to turn arithmetic off would make it negotiable.
    Thresholds that only ever *escalate* are the shape a future field should take.

    This prohibition is **not** local to this class. It is a constraint on the policy schema
    itself — `docs/architecture.md` §5, "What policy may never configure" — because by the
    time a second knob is proposed, the person proposing it is reading the schema, not this
    docstring.
    """
