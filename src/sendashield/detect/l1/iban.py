"""L1 detector: IBANs, validated by ISO 13616 mod-97 **and** registry length.

Runs on the output of `normalise()` / `normalise_calendar()` and returns spans whose
offsets index into that same string (see `normalise.py` for the coordinate system).

**Pattern matching alone never produces a detection.** Every candidate is mod-97 validated,
and the corpus contains two near-misses (`nearmiss_iban_transposed_digits`,
`nearmiss_reference_fails_iban_checksum`) whose entire purpose is to fail if that rule is
ever relaxed to "looks like an IBAN".

## Two checks, not one — and they are not interchangeable

mod-97 passes one arbitrary number in ninety-seven. That is a far weaker filter than it
looks, and it is *not* improved by the input being long: truncating or extending a valid
IBAN gives a different number with the same 1-in-97 chance of passing. The checksum alone
would therefore accept plenty of order references and part numbers.

The second check is the ISO 13616 registry: **an IBAN's country code determines its exact
length**, and both must match. `DE` is 22 characters, always. This is the IBAN analogue of a
card's issuer-prefix table with one decisive difference — for cards a prefix table is a
heuristic, whereas here it is definitional. A token whose first two letters are not a
registered IBAN country is not an IBAN, and one whose length disagrees with its own country
code is not one either. Rejecting those is correctness, not a trade-off.

The cost of that is `IBAN_LENGTHS` going stale (see its note). It is a table of facts, so it
can be checked rather than trusted, and `tests/test_iban.py` does.

## Finding candidates

The country code plus two check digits (`[A-Z]{2}\\d{2}`) is a much stronger anchor than
anything a card offers, and the registry then fixes exactly how many more characters to
take. So this detector does not face `credit_card`'s search problem at all: there is one
candidate per anchor, of one known length, rather than a set of group-aligned subsequences
to sift. `docs/architecture.md` §4 ("L1 candidate selection") records why sliding windows
were rejected for `credit_card`; the anchor is what lets this module sidestep that question
rather than answer it, and it should not be taken as evidence the question is easy.

IBANs are printed in groups of four (`DE89 3704 0044 0532 0130 00`) and copied that way, so
separators are consumed between characters — the ones `normalise.INTER_DIGIT_SEPARATOR`
defines, imported rather than restated. As in `credit_card`, the scan runs over the
*uncollapsed* text and collapsing happens per candidate: a span has to point at the
identifier as written so that masking replaces it whole, separators included.

A candidate must not be **immediately** adjacent to another alphanumeric character on either
side, so `XDE89370400440532013000` and `DE89370400440532013000X` are both rejected: each is
a fragment of some longer token, and reporting a fragment as an identifier is how a detector
starts inventing them.

Immediate adjacency, deliberately — the check does not look through separators. It therefore
still fires inside `RE-2026-01/DE89370400440532013000`, which is right (that is a real
invoice reference containing a real IBAN, and it must be masked), and it accepts
`DE89 3704 0044 0532 0130 00 12,50` where an amount trails the grouping. The residual risk
is the mirror of that permissiveness: an anchor sitting at a group boundary *inside* a
longer IBAN could in principle take its own country's length and stop short. It cannot
happen for a same-country prefix — a country code fixes exactly one length, so no IBAN is a
prefix of another from the same country — and reaching it otherwise needs a longer IBAN that
literally spells a second country code plus two digits at one of its own group boundaries.
Erring toward detection is the correct direction here regardless (`CLAUDE.md`: a miss is a
leak, over-masking is not), which is why the looser check is the one kept.

## Known limitations

Pinned by tests in `tests/test_iban.py` rather than papered over:

1. **Split across a newline.** Newlines are not separators — see
   `collapse_digit_separators` for why joining across lines manufactures identifiers.
   Shared with `credit_card`, from the same one definition.
2. **Unregistered country codes.** A genuine IBAN from a country added to ISO 13616 after
   `IBAN_LENGTHS` was last updated is not detected. This is the one limitation here that
   degrades over time rather than staying constant, which is why it is a dated table with a
   test rather than a comment.

Grouping by Unicode hyphen look-alikes (`DE89－3704－…`, U+FF0D) was a third, and was a live
evasion against this detector although no line of this module ever mentioned a hyphen: the
separator class was ASCII-only, so the anchor matched and the body pattern then failed. It
was closed by adding the homoglyphs to `INTER_DIGIT_SEPARATOR`, which fixed `credit_card` in
the same edit — the argument for one shared definition, demonstrated rather than asserted.
`TestUnicodeLookAlikeSeparatorsDoNotDefeatDetection` now asserts detection across eight
look-alikes, and asserts that en dash, em dash and horizontal bar remain *non*-separators.
"""

from __future__ import annotations

import re

from sendashield.detect.l1.checksums import (
    IBAN_MAX_LENGTH,
    IBAN_MIN_LENGTH,
    iban_mod97_check,
)
from sendashield.model import DetectionError, DetectorConfig, Span
from sendashield.normalise import INTER_DIGIT_SEPARATOR, collapse_digit_separators

DETECTOR_ID: str = "iban"

#: ISO 13616 registry: country code -> total IBAN length, country code included.
#:
#: **This is a dated snapshot of an external registry, current as of the 2025 edition.** It
#: is the one part of this detector that decays: SWIFT publishes new entries, and an IBAN
#: from a country missing here is not detected at all. That failure is silent — a missing
#: key produces no candidate, which is indistinguishable from clean text.
#:
#: Two reasons it is still a hard table rather than a permissive length range. First, an
#: IBAN's country code is *defined* by this registry, so a token outside it is not an IBAN
#: however well it validates. Second, mod-97 passes 1 in 97, so dropping the length check
#: would put the whole detector's precision on a coin that lands wrong once per ninety-seven
#: identifier-shaped tokens in a mailbox.
#:
#: Deliberately excludes the "partial"/non-registry codes that circulate in some IBAN
#: libraries (various West African and Central African states, Comoros, Madagascar, ...).
#: They are not in ISO 13616, and adding unverifiable entries to a table whose whole value
#: is being verifiable would be a bad trade. Add one only against the published registry.
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
    "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
    "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "YE": 30,
}  # fmt: skip

#: How many separators may sit between two characters of one IBAN. Bounded, unlike the
#: equivalent in `credit_card`'s run pattern, because this scan is anchored and reaches
#: *forward* for a fixed number of characters: unbounded here would let `DE89` plus a
#: kilobyte of whitespace plus eighteen digits read as one identifier. Real grouping uses a
#: single space; three is slack for double spaces and stray punctuation.
_MAX_SEPARATOR_RUN = 3

#: Country code and check digits. Case-insensitive by design — see `_candidate_at`. Not
#: anchored on a word boundary here; adjacency is checked explicitly, because `\b` is
#: satisfied by `-` and `.`, which are exactly the characters that could be joining this
#: token to a longer one.
_ANCHOR_RE = re.compile(r"[A-Za-z]{2}[0-9]{2}")

#: One IBAN character, optionally preceded by separators. Repeated a country-specific number
#: of times by `_body_pattern`.
_BODY_UNIT = rf"(?:{INTER_DIGIT_SEPARATOR}{{0,{_MAX_SEPARATOR_RUN}}}[A-Za-z0-9])"

#: A character that would make an adjacent candidate part of some longer token instead.
_ALNUM_RE = re.compile(r"[A-Za-z0-9]")


def _body_pattern(remaining: int) -> re.Pattern[str]:
    """Compiled matcher for an anchor followed by exactly `remaining` more IBAN characters."""
    return re.compile(rf"[A-Za-z]{{2}}[0-9]{{2}}{_BODY_UNIT}{{{remaining}}}")


#: One compiled pattern per distinct registry length, built at import. There are far fewer
#: distinct lengths than countries, so this is a handful of patterns rather than ninety.
_BODY_PATTERNS: dict[int, re.Pattern[str]] = {
    length: _body_pattern(length - 4) for length in set(IBAN_LENGTHS.values())
}


def detect(text: str, config: DetectorConfig) -> list[Span]:
    """Find mod-97-valid IBANs of registry length in normalised `text`.

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
        # Re-raises rather than continuing: the pipeline quarantines on DetectionError, so
        # translating here is what makes an unforeseen failure fail closed instead of
        # escaping as a type the pipeline does not recognise as a detection failure. The
        # original is chained, and no matched text appears in the message.
        raise DetectionError(
            f"{DETECTOR_ID} failed to scan text of length {len(text)}: {type(exc).__name__}"
        ) from exc


def _detect(text: str) -> list[Span]:
    candidates: list[tuple[int, int]] = []

    for anchor in _ANCHOR_RE.finditer(text):
        found = _candidate_at(text, anchor.start())
        if found is not None:
            candidates.append(found)

    # Longest first, then leftmost — the same rule `credit_card` uses and the same one
    # `docs/architecture.md` §4 merges by, so two detectors never disagree about which of
    # two overlapping claims wins.
    candidates.sort(key=lambda span: (-(span[1] - span[0]), span[0]))

    kept: list[tuple[int, int]] = []
    for start, end in candidates:
        if all(end <= other_start or start >= other_end for other_start, other_end in kept):
            kept.append((start, end))

    return [
        Span(detector=DETECTOR_ID, start=start, end=end, text=text[start:end])
        for start, end in sorted(kept)
    ]


def _candidate_at(text: str, start: int) -> tuple[int, int] | None:
    """The IBAN beginning at `start`, or None. Offsets are into `text`, separators included.

    Case-insensitive: a lower-cased IBAN is still an IBAN, and a miss is a leak while the
    extra false-positive surface is negligible — the country code must still be in the
    registry, the length must still match exactly, and mod-97 must still pass. The span
    keeps the text's own casing, because masking replaces the identifier as written.
    """
    if start > 0 and _ALNUM_RE.match(text[start - 1]):
        # Mid-token: the anchor is the tail of some longer alphanumeric string.
        return None

    country = text[start : start + 2].upper()
    length = IBAN_LENGTHS.get(country)
    if length is None:
        return None

    match = _BODY_PATTERNS[length].match(text, start)
    if match is None:
        return None
    if match.end() < len(text) and _ALNUM_RE.match(text[match.end()]):
        # More alphanumerics follow, so this is a prefix of a longer token — which is
        # exactly how a 34-character IBAN would otherwise be reported as a 22-character one.
        return None

    compact = collapse_digit_separators(match.group()).upper()
    if len(compact) != length:
        # Unreachable while `INTER_DIGIT_SEPARATOR` and `collapse_digit_separators` agree on
        # what a separator is, which is the point: they were once two definitions that
        # disagreed. A mismatch here means they have diverged again, and it must not be
        # answered with a quiet `None` that reads downstream as "no IBAN here".
        raise DetectionError(
            f"{DETECTOR_ID}: matched {length} characters for {country} but collapsed to "
            f"{len(compact)} — INTER_DIGIT_SEPARATOR and collapse_digit_separators disagree"
        )
    if not IBAN_MIN_LENGTH <= length <= IBAN_MAX_LENGTH:  # pragma: no cover - table invariant
        raise DetectionError(
            f"{DETECTOR_ID}: IBAN_LENGTHS[{country}] is {length}, outside the ISO 13616 "
            f"range {IBAN_MIN_LENGTH}-{IBAN_MAX_LENGTH}"
        )

    return (start, match.end()) if iban_mod97_check(compact) else None
