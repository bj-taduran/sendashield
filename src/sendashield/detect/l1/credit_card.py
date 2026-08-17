"""L1 detector: payment card numbers, validated by Luhn.

Runs on the output of `normalise()` / `normalise_calendar()` and returns spans whose
offsets index into that same string (see `normalise.py` for the coordinate system).

**Pattern matching alone never produces a detection.** Every candidate is Luhn-validated
and only a passing candidate becomes a span. A 16-digit order number is not a card, and the
corpus contains two near-misses (`nearmiss_order_number_fails_luhn`,
`nearmiss_card_dashed_fails_luhn`) whose entire purpose is to fail if that rule is ever
relaxed to "looks like a card".

## Finding candidates

Card numbers are written in groups — `4000 0025 0000 3155`, `5200-8282-8282-8210` — so
there is no long digit run to find, and any scan looking for one sees nothing at all. The
separators that may appear are exactly the ones `normalise.INTER_DIGIT_SEPARATOR` defines,
imported rather than restated: that class was once written out twice, the hyphen was
missing from both, and fixing one copy left the other broken.

Collapsing the text first and scanning the result is the obvious approach and is wrong
here: collapsing moves every offset, and a span has to point into the *uncollapsed* text so
that masking replaces the identifier as written, separators included. So the scan runs over
the original text and `collapse_digit_separators` is applied per candidate, to the matched
substring only, where it cannot disturb anything outside it.

Within a maximal run of digits-and-separators, every contiguous **group-aligned**
subsequence of 13-19 digits is a candidate — the whole run, and any run of whole groups
inside it. Sub-sequences that cut a group in half are deliberately not considered:

- Cutting mid-group is how a detector invents cards that are not there. A 20-digit German
  IBAN contains, on average, several Luhn-passing 13-19 digit windows; scanning arbitrary
  windows fires on eight of the nine unseparated over-length runs in the corpus — every one
  of them an account number — and, worse, finds Luhn-passing windows *inside* both
  Luhn-failing near-misses, defeating the checksum whose correctness they exist to prove.
- Whole groups are what actually happens in real text. `4242424242424242 349.00` is a card
  and a price sharing a run, because a space and a dot are both separators; the card is the
  first group and is found. `DE89370400440532013000` is one group of twenty digits, out of
  range, and yields nothing.

Overlapping candidates are resolved longest-first, then leftmost, matching the
"longest-span-first" merge rule in `docs/architecture.md` §4. Returned spans never overlap.

The full comparison of candidate strategies — sliding window, maximal-run-only,
group-aligned — with the corpus measurements behind the choice is in
`docs/architecture.md` §4, "L1 candidate selection". **Read that before writing another L1
detector**: `iban` and `steuer_idnr` face the identical trade-off, and sliding windows are
the attractive wrong answer in all three.

## Known limitations

Two, both pinned by tests in `tests/test_credit_card.py` rather than papered over. (A third
— grouping by Unicode hyphen look-alikes such as U+FF0D, which defeated this detector and
`iban` alike — was closed by adding the homoglyphs to `INTER_DIGIT_SEPARATOR`, one edit for
both detectors. `TestUnicodeLookAlikeSeparatorsDoNotDefeatDetection` now asserts detection
where it previously asserted the miss.)

1. **Split across a newline.** Newlines are not separators (`collapse_digit_separators`
   documents why — joining digits across lines manufactures identifiers out of unrelated
   numbers). `normalise()` turns `<br>` and block-element breaks into newlines, so a card
   split by markup that way survives this detector.

2. **Unseparated over-length run.** Group alignment resolves candidates at separator
   boundaries, so a run with no separators has exactly one group and admits no
   sub-candidate: `4242424242424242123456` yields nothing. This is not closable here, and
   the reason is precise — the false positive and the true positive are the same string. "A
   Luhn-valid 16-digit window inside an unseparated 20+ digit run" describes both a card in
   a blob and the phantom Visa that every German IBAN contains. Measured over the corpus,
   sub-windowing fires on eight of nine such runs, all of them account numbers; adding an
   IIN table drops that to three, which is not a fix. Resolving it needs another detector's
   verdict on the same run and therefore belongs in the merge step, not in this module —
   §4 spells out that design and why it must not be built speculatively here.

   **This gap has a deadline, not an intention.** `docs/architecture.md` §10 records it as
   an open limitation, and §15 makes resolving-or-documenting it a mandatory acceptance
   criterion of the `pipeline.py` merge session that closes Phase 2. It does not get to
   live only in a test name.

L2/L3 are the layers expected to catch both.
"""

from __future__ import annotations

import re

from sendashield.detect.l1.checksums import luhn_check
from sendashield.model import DetectionError, DetectorConfig, Span
from sendashield.normalise import INTER_DIGIT_SEPARATOR, collapse_digit_separators

DETECTOR_ID: str = "credit_card"

#: Shortest and longest card numbers in circulation: 13 (older Visa) to 19 (Maestro, and
#: the ISO/IEC 7812 maximum). Outside this range it is not a card, whatever Luhn says —
#: Luhn alone passes one random number in ten and would make any long digit run a coin toss.
MIN_CARD_DIGITS = 13
MAX_CARD_DIGITS = 19

#: A maximal run of digits joined by separators. Greedy, and `finditer` will not start a new
#: match inside one it already returned, so each match is the whole run: no boundary
#: lookaround is needed to avoid matching a fragment of a longer number.
_RUN_RE = re.compile(rf"\d(?:{INTER_DIGIT_SEPARATOR}*\d)*")

#: One group of digits within such a run.
_GROUP_RE = re.compile(r"\d+")


def detect(text: str, config: DetectorConfig) -> list[Span]:
    """Find Luhn-valid card numbers in normalised `text`.

    Pure: no I/O, no globals, no logging. Returns spans sorted by start offset, never
    overlapping.

    Raises:
        DetectionError: on any failure. Nothing is caught and converted to an empty
            result — an empty list means "scanned, found nothing", and a scan that did not
            happen must never be indistinguishable from a clean one (CLAUDE.md invariant 2).
    """
    try:
        return _detect(text)
    except DetectionError:
        raise
    except Exception as exc:
        # Not a broad catch that continues: it re-raises. The pipeline quarantines on
        # DetectionError, so translating here is what makes an unforeseen failure fail
        # closed instead of escaping as some type the pipeline does not know to treat as a
        # detection failure. The original is chained, and no matched text is in the message.
        raise DetectionError(
            f"{DETECTOR_ID} failed to scan text of length {len(text)}: {type(exc).__name__}"
        ) from exc


def _detect(text: str) -> list[Span]:
    candidates: list[tuple[int, int]] = []

    for run in _RUN_RE.finditer(text):
        candidates.extend(_candidates_in_run(run.group(), run.start()))

    # Longest first, then leftmost, so a longer identifier wins over a shorter one sharing
    # its text; ties resolve by position rather than by whatever order the scan produced.
    candidates.sort(key=lambda span: (-(span[1] - span[0]), span[0]))

    kept: list[tuple[int, int]] = []
    for start, end in candidates:
        if all(end <= other_start or start >= other_end for other_start, other_end in kept):
            kept.append((start, end))

    return [
        Span(detector=DETECTOR_ID, start=start, end=end, text=text[start:end])
        for start, end in sorted(kept)
    ]


def _candidates_in_run(run: str, offset: int) -> list[tuple[int, int]]:
    """Group-aligned subsequences of `run` that are Luhn-valid cards, as absolute offsets."""
    groups = [(match.start(), match.end()) for match in _GROUP_RE.finditer(run)]
    found: list[tuple[int, int]] = []

    for first in range(len(groups)):
        start = groups[first][0]
        for last in range(first, len(groups)):
            end = groups[last][1]
            digits = collapse_digit_separators(run[start:end])
            if len(digits) > MAX_CARD_DIGITS:
                # Digit count only grows as `last` advances, so nothing further from this
                # start can be in range. Without this the scan is quadratic in the number of
                # groups, on attacker-controlled text.
                break
            if len(digits) >= MIN_CARD_DIGITS and luhn_check(digits):
                found.append((offset + start, offset + end))

    return found
