"""Checksum algorithms for the L1 detectors.

One module for all of them, separate from any detector, because the arithmetic is the part
worth testing exhaustively and it is easier to do that against a pure function taking a
digit string than through a detector that first has to find one. `iban` (mod-97) and
`steuer_idnr` (the German 11-digit check) add their algorithms here alongside `luhn_check`.

These functions decide whether an L1 detection happens at all, and CLAUDE.md invariant 3
makes an L1 detection absolute — nothing downstream may reduce it. So a bug here is not a
missed heuristic, it is either a leak or a permanent false positive, with no later layer
able to correct it.
"""

from __future__ import annotations

from sendashield.model import DetectionError


def luhn_check(digits: str) -> bool:
    """True if `digits` satisfies the Luhn checksum (ISO/IEC 7812-1).

    Doubles every second digit from the right, subtracting 9 from any result above 9, and
    requires the total to be a multiple of ten.

    Expects digits only — separators must already be removed by the caller, which owns that
    decision because it is also the thing that has to keep track of the offsets removing
    them would move. A non-digit character here means the caller is broken, so it raises
    rather than returning `False`: a silent `False` is a detection that quietly does not
    happen, which is the fail-*open* shape this project exists to avoid.

    Raises:
        DetectionError: if `digits` is empty or contains a non-digit character.
    """
    if not digits:
        raise DetectionError("luhn_check received an empty string")
    if not digits.isdecimal():
        # Deliberately reports position and length, never the value: this message can reach
        # a log, and `DetectionError` forbids content in it. `isdecimal` rather than
        # `isdigit`, which accepts superscripts (²) that `int()` then rejects.
        offending = next(i for i, ch in enumerate(digits) if not ch.isdecimal())
        raise DetectionError(
            f"luhn_check expects digits only; found a non-digit character at index "
            f"{offending} of {len(digits)}. Strip separators before calling."
        )

    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


#: ISO 7064 MOD-97-10 letter values: A=10 ... Z=35. Built once rather than computed per
#: character, and from `ord` rather than written out, so it cannot be mistyped.
_IBAN_LETTER_VALUES = {chr(ord("A") + i): str(10 + i) for i in range(26)}

#: ISO 13616 bounds on the whole IBAN, country code included. Defined here beside the
#: checksum because `iban_mod97_check` enforces the minimum itself: below it, `iban[4:]` is
#: a degenerate slice and the "rearrange" step stops meaning anything.
IBAN_MIN_LENGTH = 15
IBAN_MAX_LENGTH = 34


def iban_mod97_check(iban: str) -> bool:
    """True if `iban` satisfies the ISO 13616 / ISO 7064 MOD-97-10 checksum.

    Move the first four characters to the end, replace each letter with its position value
    (A=10 ... Z=35), read the result as one integer, and require `% 97 == 1`.

    Expects the IBAN in **electronic format**: uppercase, alphanumeric, no separators. The
    caller strips grouping, for the same reason `luhn_check`'s caller does — it is the thing
    tracking the offsets that removing separators would move.

    This function validates the *checksum only*. It does not know how long an IBAN from a
    given country should be, and mod-97 alone cannot tell: truncating or extending a valid
    IBAN yields a different number that has a 1-in-97 chance of also passing. Length is
    enforced against the ISO 13616 registry by the caller, and the two checks are not
    interchangeable.

    Raises:
        DetectionError: if `iban` is empty, shorter than the ISO minimum, or contains a
            character that is not an ASCII uppercase letter or digit. As with `luhn_check`,
            a malformed argument means the caller is broken and must not be answered with a
            quiet `False` — that is a detection that silently does not happen.
    """
    if not iban:
        raise DetectionError("iban_mod97_check received an empty string")
    if len(iban) < IBAN_MIN_LENGTH:
        raise DetectionError(
            f"iban_mod97_check received {len(iban)} characters; the ISO 13616 minimum is "
            f"{IBAN_MIN_LENGTH}. Length is the caller's check, not this function's."
        )
    for index, char in enumerate(iban):
        if not (char.isdigit() and char.isascii()) and char not in _IBAN_LETTER_VALUES:
            # Position and length only, never the value — this message can reach a log.
            raise DetectionError(
                f"iban_mod97_check expects A-Z and 0-9 only; found an invalid character at "
                f"index {index} of {len(iban)}. Strip separators and upper-case first."
            )

    rearranged = iban[4:] + iban[:4]

    # Folded incrementally instead of building one large integer. The arithmetic is
    # identical, and it keeps the work linear in length on input an attacker controls
    # rather than depending on how big an int the caller let through.
    remainder = 0
    for char in rearranged:
        for digit in _IBAN_LETTER_VALUES.get(char, char):
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1
