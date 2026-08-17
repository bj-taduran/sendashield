"""The `iban` L1 detector.

As in `test_credit_card.py`, the property tests are the real gate: they assert the
detector's verdict equals the checksum's verdict over generated input, which is a claim no
number of examples can make. The difference here is that there are *two* rules to pin —
mod-97 and the ISO 13616 length registry — and the tests below keep them separable, because
a detector that passed only because one rule masked a bug in the other would look identical
to a correct one.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from sendashield.detect.l1 import iban
from sendashield.detect.l1.checksums import (
    IBAN_MAX_LENGTH,
    IBAN_MIN_LENGTH,
    iban_mod97_check,
)
from sendashield.detect.l1.iban import DETECTOR_ID, IBAN_LENGTHS, detect
from sendashield.model import DetectionError, DetectorConfig, Span

CONFIG = DetectorConfig()

#: Every IBAN the golden corpus declares, plus the two near-misses. Kept here as literals
#: rather than read from the fixtures: this module tests the detector in isolation, and a
#: test that derives its own expectations from the thing under test proves nothing.
VALID = "DE89370400440532013000"
TRANSPOSED = "DE89730400440532013000"  # 37 -> 73; mod-97 False
BAD_CHECKSUM = "DE00123456780987654321"

CORPUS_IBANS = [
    "DE89370400440532013000",
    "DE94500700100123456789",
    "DE91100100100567891234",
    "DE03200410610044556677",
    "DE73600501010009876543",
    "DE51300209000987654321",
]


def texts(spans: list[Span]) -> list[str]:
    return [span.text for span in spans]


def check_digits_for(country: str, body: str) -> str:
    """The check digits that make `country + dd + body` valid, per ISO 7064.

    Used to *generate* valid IBANs for arbitrary countries rather than hard-coding a
    handful. Implemented from the standard's definition (`98 - (rearranged mod 97)`), which
    is deliberately not the same expression `iban_mod97_check` evaluates — checking a
    checksum with the code that computes it tests only that it is self-consistent.
    """
    rearranged = body + country + "00"
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return f"{98 - (int(digits) % 97):02d}"


def make_iban(country: str) -> str:
    """A synthetic, mod-97-valid IBAN of the registry length for `country`."""
    body = "".join(str((i * 7 + 3) % 10) for i in range(IBAN_LENGTHS[country] - 4))
    return country + check_digits_for(country, body) + body


class TestTheDetectorAgreesWithTheChecksum:
    @given(st.sampled_from(sorted(IBAN_LENGTHS)))
    def test_a_generated_valid_iban_is_detected_for_every_registry_country(
        self, country: str
    ) -> None:
        """The whole registry, not the handful of countries the corpus happens to contain.

        A table of ninety entries with six exercised is eighty-four untested rows that look
        tested. This constructs a valid IBAN for each and requires it to be found.
        """
        value = make_iban(country)
        assert iban_mod97_check(value), "test helper produced an invalid IBAN"
        assert texts(detect(f"Bitte an {value} ueberweisen", CONFIG)) == [value]

    @given(st.sampled_from(sorted(IBAN_LENGTHS)), st.integers(min_value=1, max_value=96))
    def test_detection_is_exactly_mod97_validity(self, country: str, offset: int) -> None:
        """Perturb the check digits and the detection must disappear with the checksum.

        `offset` walks the check digits away from correct, so the country code and the
        length stay exactly right and the *only* thing varying is the arithmetic. That is
        what makes this a test of the checksum rather than of the shape.
        """
        value = make_iban(country)
        broken = f"{country}{(int(value[2:4]) + offset) % 100:02d}{value[4:]}"
        assume(broken != value)
        assert bool(detect(broken, CONFIG)) == iban_mod97_check(broken)

    @given(st.sampled_from(CORPUS_IBANS), st.sampled_from([" ", "-", ".", " "]))
    def test_grouping_never_loses_a_detection(self, value: str, separator: str) -> None:
        """IBANs are printed in fours and copied that way.

        NBSP is in the list because `normalise()` deliberately preserves it (NFC, not
        NFKC — see `normalise.py`), so a detector must handle it rather than assume it was
        folded to a space upstream.
        """
        grouped = separator.join(value[i : i + 4] for i in range(0, len(value), 4))
        assert texts(detect(f"IBAN {grouped} — danke", CONFIG)) == [grouped]

    def test_a_lower_cased_iban_is_detected_and_masked_as_written(self) -> None:
        """A lower-cased IBAN is still an IBAN; a miss would be a leak.

        The span keeps the source's casing, because masking replaces the identifier as
        written — returning an upper-cased span would replace the wrong characters.
        """
        (span,) = detect(f"iban {VALID.lower()} bitte", CONFIG)
        assert span.text == VALID.lower()

    @given(st.sampled_from(CORPUS_IBANS))
    def test_a_detected_span_slices_back_to_itself(self, value: str) -> None:
        """Offsets and text must agree, or masking replaces the wrong region."""
        body = f"Konto: {value} (Sparkasse)"
        for span in detect(body, CONFIG):
            assert body[span.start : span.end] == span.text


class TestLengthIsCheckedIndependentlyOfTheChecksum:
    """The two rules must both be live. Either alone would pass a lot of the suite."""

    @given(st.sampled_from(sorted(IBAN_LENGTHS)))
    def test_a_truncated_iban_is_not_detected(self, country: str) -> None:
        value = make_iban(country)
        assert detect(f"Ref {value[:-1]} end", CONFIG) == []

    @given(st.sampled_from(sorted(IBAN_LENGTHS)))
    def test_an_extended_iban_is_not_detected(self, country: str) -> None:
        """Appending a character makes it the wrong length *and* trailing-adjacent."""
        value = make_iban(country)
        assert detect(f"Ref {value}7 end", CONFIG) == []

    def test_an_unregistered_country_code_is_never_detected(self) -> None:
        """`ZZ` is not in ISO 13616, so nothing beginning `ZZ` is an IBAN.

        Built by taking a valid DE IBAN and swapping only the country code, so the length
        is right and the digits are unchanged — the country code is the sole difference.
        """
        assert "ZZ" not in IBAN_LENGTHS
        assert detect(f"Ref ZZ{VALID[2:]} end", CONFIG) == []

    def test_a_valid_checksum_at_the_wrong_registry_length_is_not_detected(self) -> None:
        """The sharp case: mod-97 passes, the length does not match the country code.

        `NO` is 15 characters. A 22-character string starting `NO` can be made mod-97 valid,
        and it is still not a Norwegian IBAN. Without the length rule this would be found —
        which is precisely the 1-in-97 false positive the registry exists to suppress.
        """
        body = "0" * 18
        value = "NO" + check_digits_for("NO", body) + body
        assert len(value) == 22
        assert iban_mod97_check(value), "test setup: this must pass the checksum"
        assert IBAN_LENGTHS["NO"] == 15
        assert detect(f"Ref {value} end", CONFIG) == []


class TestNearMissesDoNotFire:
    @pytest.mark.parametrize(
        "body",
        [
            f"IBAN {TRANSPOSED}. Weiter",  # two digits transposed
            f"Referenz {BAD_CHECKSUM}. Q",  # deliberately checksum-invalid
            "Tracking 1Z999AA10123456784 dispatched",
            "Card 4242424242424242 charged",  # the other L1 detector's territory
            "Rechnung DE-2026-0845217 vom Januar",
            "Tel. +49 30 23125 10",
        ],
    )
    def test_wrong_shaped_or_checksum_failing_values_produce_nothing(self, body: str) -> None:
        assert detect(body, CONFIG) == []

    def test_the_transposed_near_miss_differs_from_a_real_iban_only_by_a_swap(self) -> None:
        """Guards the near-miss itself: it must actually be a near miss.

        If `TRANSPOSED` drifted into something that fails for a cheaper reason — wrong
        length, bad country — the test above would still pass while no longer exercising
        the checksum at all. That is the vacuous-guard shape CLAUDE.md invariant 12 names.
        """
        assert len(TRANSPOSED) == len(VALID) == IBAN_LENGTHS["DE"]
        assert sorted(TRANSPOSED) == sorted(VALID)
        assert TRANSPOSED != VALID
        assert not iban_mod97_check(TRANSPOSED)


class TestSpansCoverTheIdentifierAsWritten:
    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            (f"Konto {VALID} bitte", VALID),
            ("Konto DE89 3704 0044 0532 0130 00 bitte", "DE89 3704 0044 0532 0130 00"),
            ("Konto DE89-3704-0044-0532-0130-00 bitte", "DE89-3704-0044-0532-0130-00"),
            ("Konto DE89.3704.0044.0532.0130.00 bitte", "DE89.3704.0044.0532.0130.00"),
        ],
    )
    def test_span_includes_internal_separators(self, body: str, expected: str) -> None:
        """Masking replaces the span verbatim, so it must cover the whole identifier.

        A span over only the alphanumerics would leave the grouping behind as visible
        fragments of an account number.
        """
        assert texts(detect(body, CONFIG)) == [expected]

    def test_span_stops_at_the_identifier(self) -> None:
        body = f"IBAN {VALID}, BIC COBADEFFXXX"
        (span,) = detect(body, CONFIG)
        assert (span.start, span.end) == (5, 5 + len(VALID))
        assert span.detector == DETECTOR_ID

    def test_an_iban_inside_a_longer_reference_is_still_found(self) -> None:
        """A real invoice reference joining an IBAN to other tokens with punctuation.

        `-` and `/` are not alphanumeric, so the IBAN is not a fragment of a longer word —
        it is an IBAN embedded in a reference, and it must be masked.
        """
        assert texts(detect(f"RE-2026-01/{VALID} bezahlt", CONFIG)) == [VALID]

    @pytest.mark.parametrize("body", [f"X{VALID}", f"{VALID}X", f"9{VALID}", f"{VALID}9"])
    def test_an_alphanumeric_neighbour_rejects_the_candidate(self, body: str) -> None:
        """Immediately adjacent alphanumerics mean this is a fragment of a longer token."""
        assert detect(body, CONFIG) == []

    def test_two_ibans_are_both_found_without_overlapping(self) -> None:
        body = f"Alt {VALID} neu {CORPUS_IBANS[1]} Ende"
        spans = detect(body, CONFIG)
        assert texts(spans) == [VALID, CORPUS_IBANS[1]]
        assert spans[0].end <= spans[1].start


class TestUnicodeLookAlikeSeparatorsDoNotDefeatDetection:
    """The same evasion `credit_card` had, closed by the same one-line edit.

    This class is the evidence for that claim. `iban` never had a homoglyph rule of its own
    and never needed one: adding U+FF0D to `INTER_DIGIT_SEPARATOR` fixed both detectors at
    once, which is what a single shared definition is *for*.
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
    def test_an_iban_grouped_with_a_look_alike_separator_is_found(
        self, name: str, separator: str
    ) -> None:
        grouped = separator.join(VALID[i : i + 4] for i in range(0, len(VALID), 4))
        assert texts(detect(grouped, CONFIG)) == [grouped], f"{name} did not group the IBAN"

    @pytest.mark.parametrize(
        ("name", "separator"),
        [("U+2013 EN DASH", "–"), ("U+2014 EM DASH", "—"), ("U+2015 HORIZONTAL BAR", "―")],
    )
    def test_range_dashes_are_deliberately_not_separators(self, name: str, separator: str) -> None:
        """Homoglyph, not dash. See `_HYPHEN_HOMOGLYPHS` in `normalise.py`."""
        grouped = separator.join(VALID[i : i + 4] for i in range(0, len(VALID), 4))
        assert detect(grouped, CONFIG) == [], f"{name} must not join IBAN groups"


class TestFailsClosed:
    def test_checksum_failure_propagates_as_detection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exploding checksum must reach the pipeline, not become an empty result.

        `[]` means "scanned, found nothing" and the item is allowed. If a crash produced the
        same value, a detector that stopped working would be indistinguishable from a clean
        message — CLAUDE.md invariant 2.
        """

        def explode(value: str) -> bool:
            raise RuntimeError("checksum table unavailable")

        monkeypatch.setattr(iban, "iban_mod97_check", explode)
        with pytest.raises(DetectionError):
            detect(f"IBAN {VALID} bitte", CONFIG)

    def test_unexpected_internal_failure_propagates_as_detection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Exploding:
            def finditer(self, text: str) -> Any:
                raise ValueError("compiled pattern corrupted")

        monkeypatch.setattr(iban, "_ANCHOR_RE", Exploding())
        with pytest.raises(DetectionError):
            detect("anything at all", CONFIG)

    def test_detection_error_from_below_is_not_rewrapped_into_something_else(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(value: str) -> bool:
            raise DetectionError("deliberate")

        monkeypatch.setattr(iban, "iban_mod97_check", explode)
        with pytest.raises(DetectionError, match="deliberate"):
            detect(f"IBAN {VALID} bitte", CONFIG)

    def test_error_message_never_contains_the_iban(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(value: str) -> bool:
            raise RuntimeError("boom")

        monkeypatch.setattr(iban, "iban_mod97_check", explode)
        with pytest.raises(DetectionError) as caught:
            detect(f"IBAN {VALID} bitte", CONFIG)
        assert VALID not in str(caught.value)

    def test_a_separator_definition_that_drifts_raises_rather_than_returning_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The guard on `INTER_DIGIT_SEPARATOR` and `collapse_digit_separators` agreeing.

        These were once two definitions that disagreed, and the consequence was a silent
        miss. If the match consumes separators the collapse then fails to remove, the length
        check inside `_candidate_at` catches it — and must raise, not return `None`, because
        `None` reads downstream as "no IBAN here".
        """
        monkeypatch.setattr(iban, "collapse_digit_separators", lambda text: text)
        with pytest.raises(DetectionError, match="disagree"):
            detect("IBAN DE89 3704 0044 0532 0130 00 bitte", CONFIG)

    def test_empty_text_is_a_clean_scan_not_an_error(self) -> None:
        assert detect("", CONFIG) == []


class TestTheRegistryTableIsInternallyConsistent:
    """`IBAN_LENGTHS` is a snapshot of an external registry. Check what can be checked."""

    def test_every_country_code_is_two_upper_case_letters(self) -> None:
        assert all(
            len(code) == 2 and code.isascii() and code.isalpha() and code.isupper()
            for code in IBAN_LENGTHS
        )

    def test_every_length_is_within_the_iso_13616_range(self) -> None:
        assert all(IBAN_MIN_LENGTH <= n <= IBAN_MAX_LENGTH for n in IBAN_LENGTHS.values())

    @pytest.mark.parametrize(
        ("country", "length"),
        [("DE", 22), ("GB", 22), ("FR", 27), ("NO", 15), ("MT", 31), ("NL", 18), ("CH", 21)],
    )
    def test_well_known_lengths_are_right(self, country: str, length: int) -> None:
        """Spot-checks against values that are easy to verify independently.

        Not a proof the table is current — nothing in this repo can be — but it fails if
        someone edits the table carelessly, which is the realistic failure.
        """
        assert IBAN_LENGTHS[country] == length

    def test_the_table_is_large_enough_to_be_the_registry(self) -> None:
        """A floor, so a truncated table cannot pass every other test by having few rows."""
        assert len(IBAN_LENGTHS) >= 85


class TestKnownLimitations:
    """Pinned, not fixed. A limitation nobody has written down is one nobody can weigh."""

    def test_an_iban_split_across_a_newline_is_not_found(self) -> None:
        """Newlines are not separators, so `<br>`-split grouping survives the detector.

        `collapse_digit_separators` documents why joining across lines is refused: it
        manufactures identifiers out of unrelated tokens on consecutive lines. Shared with
        `credit_card`; L2/L3 are the layers expected to catch it.
        """
        assert detect("DE89 3704 0044\n0532 0130 00", CONFIG) == []

    def test_an_iban_from_a_country_outside_the_snapshot_is_not_found(self) -> None:
        """The limitation that decays with time rather than staying constant.

        `IBAN_LENGTHS` is a dated snapshot; a country added to ISO 13616 afterwards is
        missed silently. Demonstrated here with a code that is deliberately not in the
        registry, standing in for one that is not in it *yet*.
        """
        assert "ZZ" not in IBAN_LENGTHS
        body = "0" * 18
        value = "ZZ" + check_digits_for("ZZ", body) + body
        assert iban_mod97_check(value), "test setup: the checksum must pass"
        assert detect(f"Ref {value} end", CONFIG) == []
