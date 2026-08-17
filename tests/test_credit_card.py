"""The `credit_card` L1 detector.

The property test is the real gate: it asserts the detector's verdict equals the checksum's
verdict across the whole input space, which is a claim no number of examples can make.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sendashield.detect.l1 import credit_card
from sendashield.detect.l1.checksums import luhn_check
from sendashield.detect.l1.credit_card import DETECTOR_ID, detect
from sendashield.model import DetectionError, DetectorConfig, Span

CONFIG = DetectorConfig()

VALID = "4242424242424242"
INVALID = "4242424242424241"

#: Digit strings of card length. Bounded to 13-19 so the detector's length rule is not what
#: the comparison is measuring — out-of-range lengths get their own test below.
card_length_digits = st.text(alphabet="0123456789", min_size=13, max_size=19)


def texts(spans: list[Span]) -> list[str]:
    return [span.text for span in spans]


class TestTheDetectorAgreesWithTheChecksum:
    @given(card_length_digits)
    def test_detection_is_exactly_luhn_validity(self, digits: str) -> None:
        """The gate from `docs/build-plan.md` Phase 2, stated as written there."""
        assert bool(detect(digits, CONFIG)) == luhn_check(digits)

    @given(card_length_digits, st.sampled_from([" ", "-", ".", " "]))
    def test_grouping_never_loses_a_detection(self, digits: str, separator: str) -> None:
        """Every separator `normalise()` can leave behind must be transparent to detection.

        Card numbers are printed in groups and are copied that way, so a detector that only
        sees contiguous digits misses the commonest real spelling. NBSP is in the list
        because `normalise()` deliberately preserves it (NFC, not NFKC).

        Stated one-directionally on purpose. The converse - "grouped text detects only when
        the whole string is valid" - is false by design, see
        `test_ragged_grouping_can_expose_a_shorter_valid_card` below.
        """
        grouped = separator.join(digits[i : i + 4] for i in range(0, len(digits), 4))
        if luhn_check(digits):
            assert texts(detect(grouped, CONFIG)) == [grouped]

    def test_ragged_grouping_can_expose_a_shorter_valid_card(self) -> None:
        """A trailing part-group makes the prefix its own candidate. This is the design.

        `0000 0000 1111 3388 1` is not a valid 17-digit card, but its first sixteen digits
        are a valid one, so a span is returned. The same rule is what finds a card sharing a
        run with a price (`4242424242424242 349.00`), which whole-run-only matching misses
        entirely - a miss being a leak and this being over-masking, the trade is taken
        deliberately in that direction.
        """
        assert texts(detect("0000 0000 1111 3388 1", CONFIG)) == ["0000 0000 1111 3388"]

    def test_full_width_digits_are_detected(self) -> None:
        """NFC leaves full-width digits alone, so they reach L1 as written."""
        card = "\uff14\uff12" * 8
        assert texts(detect(f"Karte {card} belastet", CONFIG)) == [card]

    @given(card_length_digits)
    def test_a_detected_span_slices_back_to_itself(self, digits: str) -> None:
        """Offsets and text must agree, or masking replaces the wrong region."""
        body = f"Card on file: {digits} (expires soon)"
        for span in detect(body, CONFIG):
            assert body[span.start : span.end] == span.text

    @given(st.text(alphabet="0123456789", min_size=20, max_size=40))
    def test_digit_runs_longer_than_a_card_are_never_detected(self, digits: str) -> None:
        """A 20-digit German IBAN must not surface as a card.

        Contiguous runs have one group, so no group-aligned subsequence exists below the
        whole run — this is what stops the detector inventing cards inside account numbers.
        """
        assert detect(digits, CONFIG) == []

    @given(st.text(alphabet="0123456789", min_size=1, max_size=12))
    def test_digit_runs_shorter_than_a_card_are_never_detected(self, digits: str) -> None:
        assert detect(digits, CONFIG) == []


class TestSpansCoverTheIdentifierAsWritten:
    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            (f"Charged {VALID} today", VALID),
            ("Charged 4242 4242 4242 4242 today", "4242 4242 4242 4242"),
            ("Charged 4242-4242-4242-4242 today", "4242-4242-4242-4242"),
            ("Charged 4242.4242.4242.4242 today", "4242.4242.4242.4242"),
            ("Charged 4242 4242 4242 4242 today", "4242 4242 4242 4242"),
            ("Charged 4242-4242 4242.4242 today", "4242-4242 4242.4242"),
        ],
    )
    def test_span_includes_internal_separators(self, body: str, expected: str) -> None:
        """Masking replaces the span verbatim, so the span must cover the whole identifier.

        A span over only the digits would leave `----` behind — visibly a card number with
        its digits removed, which is a fragment of the identifier rather than its removal.
        """
        assert texts(detect(body, CONFIG)) == [expected]

    def test_span_stops_at_the_identifier(self) -> None:
        body = f"Card {VALID}, exp 09/28."
        (span,) = detect(body, CONFIG)
        assert (span.start, span.end) == (5, 5 + len(VALID))
        assert span.detector == DETECTOR_ID

    def test_card_adjacent_to_another_number_is_still_found(self) -> None:
        """A space and a dot are both separators, so a card and a price share one run.

        Taking the whole run and checking it once would miss this entirely: the run is 21
        digits, out of card range. Group alignment is what finds the card inside it.
        """
        body = f"Card {VALID} 349.00 EUR charged"
        assert texts(detect(body, CONFIG)) == [VALID]


class TestUnicodeLookAlikeSeparatorsDoNotDefeatDetection:
    """Homoglyph grouping was a live evasion against both L1 detectors until U+FF0D landed.

    A human reads `4242－4242－4242－4242` as an ordinary hyphen-grouped card. The ASCII-only
    separator class did not, so the run split into four four-digit fragments and nothing was
    in card range — a miss, produced by a character the reader cannot distinguish. Fixed in
    `INTER_DIGIT_SEPARATOR`, which is why `iban` was fixed by the same edit.
    """

    @pytest.mark.parametrize(
        ("name", "separator"),
        [
            ("U+2010 HYPHEN", "‐"),
            ("U+2011 NON-BREAKING HYPHEN", "‑"),
            ("U+2012 FIGURE DASH", "‒"),
            ("U+2212 MINUS SIGN", "−"),
            ("U+FE63 SMALL HYPHEN-MINUS", "﹣"),
            ("U+FF0D FULLWIDTH HYPHEN-MINUS", "－"),
            ("U+FE52 SMALL FULL STOP", "﹒"),
            ("U+FF0E FULLWIDTH FULL STOP", "．"),
        ],
    )
    def test_a_card_grouped_with_a_look_alike_separator_is_found(
        self, name: str, separator: str
    ) -> None:
        grouped = separator.join(VALID[i : i + 4] for i in range(0, len(VALID), 4))
        assert texts(detect(grouped, CONFIG)) == [grouped], f"{name} did not group the card"

    @pytest.mark.parametrize(
        ("name", "separator"),
        [("U+2013 EN DASH", "–"), ("U+2014 EM DASH", "—"), ("U+2015 HORIZONTAL BAR", "―")],
    )
    def test_range_dashes_are_deliberately_not_separators(self, name: str, separator: str) -> None:
        """The other half of the rule, or the first half means nothing.

        A test that only asserts "more characters are separators now" is satisfied by making
        *every* punctuation mark one, which would join `1990–2000` into `19902000` and start
        manufacturing identifiers out of ranges. The line is homoglyph, not dash — see
        `_HYPHEN_HOMOGLYPHS`. These three look like dashes and mean "to".
        """
        grouped = separator.join(VALID[i : i + 4] for i in range(0, len(VALID), 4))
        assert detect(grouped, CONFIG) == [], f"{name} must not join digit groups"


class TestNearMissesDoNotFire:
    @pytest.mark.parametrize(
        "body",
        [
            f"Order number {INVALID} confirmed",
            "Booking reference 5555-5555-5555-4440 confirmed",
            "Tracking 1Z999AA10123456784 dispatched",
            "Rechnung DE-2026-0845217 vom Januar",
            "Tel. +49 30 23125 10 or +49 30 23125 24",
            "IBAN DE89370400440532013000 for the transfer",
        ],
    )
    def test_luhn_failing_or_wrong_shaped_values_produce_nothing(self, body: str) -> None:
        assert detect(body, CONFIG) == []


class TestOverlapResolution:
    def test_adjacent_cards_both_detected_without_overlapping(self) -> None:
        body = f"Old {VALID} new 5555555555554444 end"
        spans = detect(body, CONFIG)
        assert texts(spans) == [VALID, "5555555555554444"]
        assert spans[0].end <= spans[1].start

    def test_returned_spans_never_overlap(self) -> None:
        """A run can yield several Luhn-valid group ranges; only a disjoint set survives."""
        body = "Ref 4242 4242 4242 4242 0000 0000 0000 tail"
        spans = detect(body, CONFIG)
        for earlier, later in zip(spans, spans[1:], strict=False):
            assert earlier.end <= later.start
        assert [s.start for s in spans] == sorted(s.start for s in spans)

    def test_longest_candidate_wins(self) -> None:
        """`docs/architecture.md` §4 merges longest-span-first; a shorter overlap loses."""
        body = "4000000000000077"  # 16 digits, Luhn-valid
        (span,) = detect(body, CONFIG)
        assert span.text == body


class TestFailsClosed:
    def test_checksum_failure_propagates_as_detection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exploding checksum must reach the pipeline, not become an empty result.

        `[]` means "scanned, found nothing" and the item is allowed. If a crash produced the
        same value, a detector that stopped working would be indistinguishable from a clean
        message — CLAUDE.md invariant 2, and the exact shape this project exists to avoid.
        """

        def explode(digits: str) -> bool:
            raise RuntimeError("checksum table unavailable")

        monkeypatch.setattr(credit_card, "luhn_check", explode)
        with pytest.raises(DetectionError):
            detect(f"Card {VALID} charged", CONFIG)

    def test_unexpected_internal_failure_propagates_as_detection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Exploding:
            def finditer(self, text: str) -> Any:
                raise ValueError("compiled pattern corrupted")

        monkeypatch.setattr(credit_card, "_RUN_RE", Exploding())
        with pytest.raises(DetectionError):
            detect("anything at all", CONFIG)

    def test_detection_error_from_below_is_not_rewrapped_into_something_else(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(digits: str) -> bool:
            raise DetectionError("deliberate")

        monkeypatch.setattr(credit_card, "luhn_check", explode)
        with pytest.raises(DetectionError, match="deliberate"):
            detect(f"Card {VALID} charged", CONFIG)

    def test_error_message_never_contains_the_card(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(digits: str) -> bool:
            raise RuntimeError("boom")

        monkeypatch.setattr(credit_card, "luhn_check", explode)
        with pytest.raises(DetectionError) as caught:
            detect(f"Card {VALID} charged", CONFIG)
        assert VALID not in str(caught.value)

    def test_empty_text_is_a_clean_scan_not_an_error(self) -> None:
        assert detect("", CONFIG) == []


class TestKnownLimitations:
    """Pinned, not fixed — the convention in `CLAUDE.md` invariant 14.

    Each test below asserts the *current, defective* behaviour, so it goes red the moment
    the gap closes and closing it is a visible edit flipping an assertion. A comment saying
    "we don't handle X" cannot be falsified, ages silently, and survives X being fixed or
    getting worse. A limitation nobody has written down is one nobody can weigh; one written
    only in prose is one nobody can check.
    """

    def test_a_card_split_across_a_newline_is_not_found(self) -> None:
        """Newlines are not separators, so `<br>`-split digits survive the detector.

        `collapse_digit_separators` documents why joining across lines is refused: it
        manufactures identifiers out of unrelated numbers on consecutive lines. The cost is
        this case. `normalise()` turns `<br>` into a newline, so an attacker who splits a
        card that way defeats L1 — L2/L3 are the layers expected to catch it, and this test
        exists so the gap is visible rather than discovered by a leak.
        """
        assert detect("4242 4242\n4242 4242", CONFIG) == []

    @pytest.mark.parametrize(
        "body",
        [
            f"{VALID}123456",  # card then six digits — 22, one group
            f"123456{VALID}",  # six digits then card — 22, one group
            f"{VALID}349",  # card then an amount, no space at all — 19, one group
        ],
    )
    def test_a_card_concatenated_against_other_digits_is_not_found(self, body: str) -> None:
        """An unseparated over-length run has one group, so no sub-candidate exists.

        This is a real miss, and it is deliberately not fixed by sub-windowing, because the
        false positive and the true positive are *the same string*: "a Luhn-valid 16-digit
        window inside an unseparated 20+ digit run" describes both this card and the phantom
        Visa that a German IBAN contains. `test_sub_windowing_would_invent_a_card_inside_an_iban`
        below demonstrates that rather than asserting it.

        **This gap has a deadline.** `docs/architecture.md` §10 carries it in the threat
        model as `OPEN`, and §15 makes resolving-or-formally-accepting it a mandatory
        acceptance criterion of the Phase 2 merge session — the first point at which one
        detector can see another's verdict, which is the information the fix needs. Per
        `CLAUDE.md` invariant 14 a test name is not a schedule; those two sections are.
        """
        assert detect(body, CONFIG) == []

    def test_sub_windowing_would_invent_a_card_inside_an_iban(self) -> None:
        """The evidence for the limitation above, executed rather than cited.

        A comment claiming "sub-windowing breaks IBANs" is unfalsifiable and rots. This runs
        the rejected strategy against a real corpus IBAN and shows what it produces: a
        flawless sixteen-digit Visa — Luhn-valid, leading `4` — made entirely of an account
        number. If this ever stops holding, the trade-off in §4 deserves revisiting, and this
        test is what will say so.
        """
        iban_digits = "45007001001234567890"  # de_iban_rechnung_zahlung, digits only
        windows = [
            iban_digits[i : i + n]
            for i in range(len(iban_digits))
            for n in range(13, 20)
            if i + n <= len(iban_digits) and luhn_check(iban_digits[i : i + n])
        ]
        assert "4500700100123456" in windows
        # And the detector as written produces none of them.
        assert detect(iban_digits, CONFIG) == []

    def test_full_width_spaces_are_separators_and_do_not_defeat_detection(self) -> None:
        """`[^\\S\\n]` matches any Unicode whitespace, so U+3000 works."""
        card = "4242　4242　4242　4242"
        assert texts(detect(card, CONFIG)) == [card]
