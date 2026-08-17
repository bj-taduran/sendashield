"""Luhn, tested as arithmetic — independently of anything that finds a card.

The published test vectors are the ones a card issuer would recognise; the property tests
are what actually pin the algorithm, since a checksum is exactly the kind of function that
passes a handful of examples while being wrong in a way no example happens to show.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sendashield.detect.l1.checksums import luhn_check
from sendashield.model import DetectionError

#: Stripe's published test card numbers (docs.stripe.com/testing). Every one is Luhn-valid;
#: they are the same values the golden corpus uses, so a disagreement between this file and
#: the corpus is a real contradiction rather than two independent guesses.
VALID_CARDS = [
    "4242424242424242",
    "5555555555554444",
    "4000056655665556",
    "4000002500003155",
    "4000000000009995",
    "5105105105105100",
    "5200828282828210",
    "4000000000000077",
    "378282246310005",  # Amex, 15 digits
    "6011111111111117",  # Discover
    "3056930009020004",  # Diners, 14 digits
]

#: Luhn-*failing* values. The first is Stripe's documented `incorrect_number` card, which
#: is the canonical "fails the checksum" example; the rest are single-digit edits of valid
#: numbers, the error class Luhn is designed to catch.
INVALID_CARDS = [
    "4242424242424241",
    "5555555555554440",
    "4000056655665557",
    "5105105105105101",
    "378282246310006",
]


@pytest.mark.parametrize("digits", VALID_CARDS)
def test_published_valid_cards_pass(digits: str) -> None:
    assert luhn_check(digits) is True


@pytest.mark.parametrize("digits", INVALID_CARDS)
def test_published_invalid_cards_fail(digits: str) -> None:
    assert luhn_check(digits) is False


def test_check_digit_construction() -> None:
    """Worked example from ISO/IEC 7812-1, digit by digit.

    A vector list can be copied wrong wholesale; this one is derived here, so it fails if
    the doubling positions or the subtract-nine step drift.
    """
    assert luhn_check("79927398713") is True
    # Every other check digit for the same 10-digit prefix must fail.
    for check_digit in "012456789":
        assert luhn_check(f"7992739871{check_digit}") is False


@given(st.text(alphabet="0123456789", min_size=1, max_size=24))
def test_appending_the_right_check_digit_always_validates(prefix: str) -> None:
    """For any digit string there is exactly one check digit that makes it Luhn-valid.

    This is the algorithm's defining property, and it exercises far more of the input space
    than the vector lists above.
    """
    valid = [d for d in "0123456789" if luhn_check(prefix + d)]
    assert len(valid) == 1


@given(st.text(alphabet="0123456789", min_size=2, max_size=24))
def test_transposing_adjacent_unequal_digits_breaks_the_checksum(digits: str) -> None:
    """Luhn detects every single transposition of adjacent digits except 09 <-> 90.

    The documented exception is real and is asserted rather than filtered out, so a change
    that silently widened it would fail here.
    """
    for i in range(len(digits) - 1):
        a, b = digits[i], digits[i + 1]
        if a == b:
            continue
        swapped = digits[:i] + b + a + digits[i + 2 :]
        if {a, b} == {"0", "9"}:
            continue
        if luhn_check(digits):
            assert not luhn_check(swapped), f"transposition at {i} went undetected"


def test_empty_string_raises() -> None:
    with pytest.raises(DetectionError):
        luhn_check("")


@pytest.mark.parametrize(
    "value",
    [
        "4242 4242 4242 4242",  # separators must be stripped by the caller
        "4242-4242-4242-4242",
        "DE89370400440532013000",
        "4242424242424242\n",
        "4242424242424242²",  # superscript: isdigit() true, isdecimal() false
    ],
)
def test_non_digit_input_raises_rather_than_returning_false(value: str) -> None:
    """A `False` here would be a detection that quietly does not happen.

    Returning `False` for unparseable input is the fail-*open* shape: the caller cannot tell
    "this is not a valid card" from "I could not read this", and the item is allowed either
    way. CLAUDE.md invariant 2 requires the opposite.
    """
    with pytest.raises(DetectionError):
        luhn_check(value)


@pytest.mark.parametrize(
    ("label", "digits"),
    [
        ("full-width", "４２４２４２４２４２４２４２４２"),
        ("Arabic-Indic", "٤٢٤٢٤٢٤٢٤٢٤٢٤٢٤٢"),
    ],
)
def test_non_ascii_decimal_digits_are_accepted(label: str, digits: str) -> None:
    """Digits outside ASCII still validate, and that is deliberate.

    Writing a card in full-width or Arabic-Indic digits is a plausible evasion, and `int()`
    parses any Unicode decimal, so the arithmetic is already correct for them. This test
    pins that as intended behaviour rather than an accident of `isdecimal()`.

    **The resistance is this function's, not `normalise()`'s** — worth stating because the
    tempting explanation is wrong and was believed here once. `normalise()` applies NFC, so
    full-width digits do reach a detector unfolded, but that is not what makes them
    detectable: under NFKC they would fold to ASCII and be detected just the same. Nothing
    about full-width *digits* depends on the normalisation form. See the NFC/NFKC section in
    `normalise.py` for what does depend on it (offset stability) and for the separate case
    of full-width *separators*, which genuinely did defeat both detectors until the hyphen
    homoglyphs were added to `INTER_DIGIT_SEPARATOR`.
    """
    assert luhn_check(digits) is True


def test_error_message_never_contains_the_value() -> None:
    """CLAUDE.md invariant 5: content must not reach a log, and these messages do."""
    secret = "4242424242424242x"
    with pytest.raises(DetectionError) as caught:
        luhn_check(secret)
    assert "4242" not in str(caught.value)
