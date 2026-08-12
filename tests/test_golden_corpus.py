"""Golden corpus validator — Phase 1 (`docs/build-plan.md`).

No detector exists yet. This file checks that fixtures are internally consistent, not
that any detector finds what they claim:

1. Every `.expected.json` validates against `tests/fixtures/expected.schema.json`.
2. `normalise()` on the paired `.eml` produces text where every declared span offset
   slices to *exactly* the text the fixture claims. This is the point — it catches a
   fixture whose `.eml` and `.expected.json` have drifted apart (hand-edited offset,
   `normalise()` contract changed, message body tweaked without updating offsets).
3. A couple of cheap cross-field sanity checks: `allow`-action fixtures declare no spans;
   everything a fixture says must not leak actually appears somewhere in the raw
   normalised text (otherwise the fixture isn't testing what it claims to).

Deliberately not `jsonschema` (the PyPI package): the schema this corpus needs is a small,
fixed shape, and CLAUDE.md asks to ask before adding a dependency. `_validate_schema`
below is a ~40-line generic validator that actually interprets
`tests/fixtures/expected.schema.json` — not a hand-duplicated set of checks that could
drift from what the schema file documents. If the schema grows past what this supports,
that's the point to actually ask about adding `jsonschema`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from sendashield.normalise import NormalisedText, normalise, normalise_calendar

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden"
SCHEMA_PATH = Path(__file__).parent / "fixtures" / "expected.schema.json"

_SCHEMA_TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
}


def _validate_schema(instance: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Minimal recursive validator for the JSON Schema subset this project's fixtures use.

    Supports: type, required, properties, additionalProperties, items, enum, minimum,
    exclusiveMinimum, minLength. Not a general JSON Schema implementation — deliberately,
    see module docstring.
    """
    errors: list[str] = []

    expected_type = schema.get("type")
    if expected_type is not None:
        py_type = _SCHEMA_TYPES[expected_type]
        # bool is a subclass of int in Python; a JSON Schema "integer" must reject it.
        if isinstance(instance, bool) or not isinstance(instance, py_type):
            errors.append(f"{path}: expected {expected_type}, got {type(instance).__name__}")
            return errors

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in {schema['enum']}")

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key!r}")
        for key, subschema in properties.items():
            if key in instance:
                errors.extend(_validate_schema(instance[key], subschema, f"{path}.{key}"))

    if isinstance(instance, list):
        item_schema = schema.get("items")
        if item_schema is not None:
            for i, item in enumerate(instance):
                errors.extend(_validate_schema(item, item_schema, f"{path}[{i}]"))

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            errors.append(f"{path}: shorter than minLength {min_length}")

    if isinstance(instance, int) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            errors.append(f"{path}: {instance} < minimum {minimum}")
        exclusive_minimum = schema.get("exclusiveMinimum")
        if exclusive_minimum is not None and instance <= exclusive_minimum:
            errors.append(f"{path}: {instance} <= exclusiveMinimum {exclusive_minimum}")

    return errors


#: Every synthetic identifier the corpus is allowed to contain. Card numbers are Stripe's
#: published test numbers (verified against docs.stripe.com/testing); IBANs are values
#: generated to satisfy mod-97 and are not real accounts.
#:
#: `test_corpus_contains_only_declared_synthetic_identifiers` fails on any identifier-shaped
#: token in a fixture that is not listed here. The point is not to detect anything — that is
#: Phase 2's job — but to make "somebody pasted a real card or IBAN into the corpus" a loud
#: CI failure rather than a thing that sits in git history forever. `docs/build-plan.md`:
#: "Real messages in a git repo is exactly the mistake this project exists to prevent."
#:
#: **Prefer a reserved fictional range to an entry in this list.** This list is an
#: allowlist, and allowlists decay: each entry is an assertion by a past reviewer that some
#: number was safe, and nothing re-checks it. Where a regulator has set aside a range
#: precisely so that examples don't dial real people, use that instead and the guard has
#: nothing to fire on — no entry, no assertion, nothing to rot. Ranges used by this corpus:
#: Germany `+49 30 23125 xx` (Berlin, reserved for drama and examples), US `555-0100` to
#: `555-0199`, UK `07700 900xxx`. Add here only for values with no reserved equivalent —
#: card numbers and IBANs, where the published test ranges are themselves the convention.
DECLARED_SYNTHETIC_IDENTIFIERS = frozenset(
    {
        # Stripe test cards
        "4242424242424242",
        "5555555555554444",
        "4000056655665556",
        "4000002500003155",  # written NBSP-grouped in the evasion fixture
        "4000000000009995",
        "5105105105105100",
        "5200828282828210",  # written hyphen-grouped in card_dash_grouped_evasion
        "4000000000000077",  # written space-grouped in card_space_grouped_evasion
        # Checksum-*failing* near-miss values. These need no trust at all, unlike every
        # entry above: a 16-digit string that fails Luhn is not a card number, and an
        # IBAN-shaped string that fails mod-97 is not an account, so neither can be real
        # data however it was arrived at. Prefer deriving a near-miss this way over picking
        # an arbitrary number and asserting it is fictional.
        "4242424242424241",  # Stripe's documented Luhn-failing "incorrect_number" card
        "5555555555554440",  # hyphen-grouped in the fixture; Luhn False
        "DE89730400440532013000",  # valid IBAN with 37 -> 73 transposed; mod-97 False
        # Generated mod-97-valid IBANs
        "DE89370400440532013000",
        "DE94500700100123456789",
        "DE91100100100567891234",
        "DE03200410610044556677",
        "DE73600501010009876543",
        "DE51300209000987654321",
        "DE00123456780987654321",  # deliberately checksum-invalid near-miss
        # Non-identifier long tokens that legitimately appear in benign fixtures
        "1Z999AA10123456784",  # carrier tracking number, benign_shipping_notification
    }
)

#: Long digit runs and IBAN-shaped tokens. Intentionally crude: this is a corpus-hygiene
#: net, not a detector, and it errs toward flagging so nothing slips by unreviewed.
_IDENTIFIER_SHAPED_RE = re.compile(r"\b(?:[A-Z]{2}\d{2}[A-Z0-9]{10,30}|[0-9A-Z]*\d{12,})\b")

#: Any separator people put *between digit groups* — whitespace (including NBSP), hyphens,
#: dots. Removed before the second scan pass, because a card written in groups contains no
#: long digit run: "4242 4242 4242 4242" and "4242-4242-4242-4242" both have a longest run
#: of four.
#:
#: Hyphens and dots were missing until the dash-grouped fixtures were added, and the gap was
#: total rather than partial: `4242-4242-4242-4242` produced **no tokens at all**, so an
#: undeclared real card written that way passed the guard in silence. That is the precise
#: mistake this guard exists to catch, and it is how card numbers are printed on the cards
#: themselves.
#:
#: Known false positive, accepted: a dotted quad like `192.168.100.100` collapses to twelve
#: digits and will be flagged. That is the intended direction — declaring one IP address
#: costs a line, and the opposite error puts real data in git history permanently.
_INTER_DIGIT_SEPARATOR_RE = re.compile(r"(?<=\d)[\s\u00a0\-.]+(?=\d)")


def _identifier_shaped_tokens(text: str) -> set[str]:
    """Identifier-shaped tokens in `text`, both as written and with digit grouping removed."""
    return set(_IDENTIFIER_SHAPED_RE.findall(text)) | set(
        _IDENTIFIER_SHAPED_RE.findall(_INTER_DIGIT_SEPARATOR_RE.sub("", text))
    )


def _raw_fixture_path(expected_path: Path) -> Path:
    stem = expected_path.name.removesuffix(".expected.json")
    for suffix in (".eml", ".ics"):
        candidate = expected_path.with_name(stem + suffix)
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"no raw fixture (.eml or .ics) found alongside {expected_path.name}")


def _normalise_fixture(raw_path: Path) -> NormalisedText:
    """The single coordinate system a fixture's offsets are indices into.

    `.eml` goes through `normalise()`, `.ics` through `normalise_calendar()`. A calendar
    fixture must contain exactly one VEVENT: `normalise_calendar` returns one item per
    event by design, and a fixture declaring `expected_spans` against a file with several
    would have no way to say which event an offset belongs to. Multi-event splitting is a
    normalisation property and is tested in `tests/test_normalise.py`, not encoded here —
    so the constraint is asserted rather than papered over by silently taking the first.
    """
    raw = raw_path.read_bytes()
    if raw_path.suffix == ".eml":
        return normalise(raw)

    events = normalise_calendar(raw)
    assert len(events) == 1, (
        f"{raw_path.name}: calendar fixtures must contain exactly one VEVENT, found "
        f"{len(events)}. Fixture offsets are indices into a single event's text; split "
        f"multi-event cases into separate fixtures."
    )
    return events[0]


def _discover_cases() -> list[Path]:
    return sorted(GOLDEN_DIR.glob("*.expected.json"))


CASES = _discover_cases()


@pytest.mark.parametrize(
    ("label", "grouped"),
    [
        ("plain", "4111111111111111"),
        ("spaces", "4111 1111 1111 1111"),
        ("non-breaking spaces", "4111 1111 1111 1111"),
        ("hyphens", "4111-1111-1111-1111"),
        ("dots", "4111.1111.1111.1111"),
        ("mixed", "4111-1111 1111.1111"),
    ],
)
def test_hygiene_guard_sees_through_every_grouping_style(label: str, grouped: str) -> None:
    """The guard must fire on an undeclared card however it is written.

    Regression: the separator class covered only whitespace, so `4111-1111-1111-1111`
    produced no tokens at all and an undeclared real card written that way passed in
    silence. Hyphens are how card numbers are printed on the cards themselves, which makes
    that the likeliest paste format after plain digits — the guard's whole purpose is to
    make "somebody pasted a real card in here" loud rather than permanent.
    """
    undeclared = _identifier_shaped_tokens(f"card {grouped} here") - DECLARED_SYNTHETIC_IDENTIFIERS
    assert undeclared, (
        f"hygiene guard did not fire on an undeclared card grouped with {label} — "
        f"a real card written this way would reach git history unnoticed"
    )


def test_golden_corpus_is_discoverable() -> None:
    """Guards the discovery mechanism itself.

    A parametrized test over an empty list silently reports zero failures — this test
    exists so a broken glob pattern or an empty directory shows up as a real failure
    instead of a suspiciously short test run.

    The floor tracks the corpus rather than sitting at its original value: a threshold left
    far below the real count stops detecting anything short of near-total loss, which is
    the same "green gate that inspects nothing" problem in miniature. Raise it when the
    corpus grows; it is a ratchet, not a target.
    """
    assert len(CASES) >= 33, (
        f"expected at least 33 golden fixtures, found {len(CASES)} in {GOLDEN_DIR}"
    )


@pytest.mark.golden
@pytest.mark.parametrize(
    "expected_path", CASES, ids=lambda p: p.name.removesuffix(".expected.json")
)
def test_corpus_contains_only_declared_synthetic_identifiers(expected_path: Path) -> None:
    """No fixture may contain an identifier-shaped token that isn't declared synthetic.

    Guards the corpus against real data, which for this project is a repository-permanent
    mistake rather than a test failure. Runs over the normalised text so it sees through
    base64 and quoted-printable encoding — a real card pasted into a base64 body would be
    invisible to a plain grep of the .eml.
    """
    raw_path = _raw_fixture_path(expected_path)
    text = _normalise_fixture(raw_path).text

    undeclared = _identifier_shaped_tokens(text) - DECLARED_SYNTHETIC_IDENTIFIERS
    assert not undeclared, (
        f"{raw_path.name} contains identifier-shaped token(s) not declared synthetic: "
        f"{sorted(undeclared)}. If this is a new synthetic value, add it to "
        f"DECLARED_SYNTHETIC_IDENTIFIERS; if it is real data it must never be committed."
    )


@pytest.mark.golden
@pytest.mark.parametrize(
    "expected_path", CASES, ids=lambda p: p.name.removesuffix(".expected.json")
)
def test_golden_fixture_parses_without_defects(expected_path: Path) -> None:
    """A fixture that only parses by the stdlib's error recovery isn't testing what it says.

    Malformed-MIME handling deserves its own deliberate fixtures (and is unit-tested in
    tests/test_normalise.py); an *accidentally* malformed fixture here would silently
    weaken whichever case it belongs to.
    """
    raw_path = _raw_fixture_path(expected_path)
    defects = _normalise_fixture(raw_path).defects
    assert defects == (), f"{raw_path.name} parsed with defects: {defects}"


@pytest.mark.golden
@pytest.mark.parametrize(
    "expected_path", CASES, ids=lambda p: p.name.removesuffix(".expected.json")
)
def test_golden_fixture_is_internally_consistent(expected_path: Path) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    schema_errors = _validate_schema(expected, schema)
    assert not schema_errors, f"{expected_path.name} violates schema: {schema_errors}"

    raw_path = _raw_fixture_path(expected_path)
    normalised = _normalise_fixture(raw_path)
    text = normalised.text

    for span in expected["expected_spans"]:
        start, end, claimed_text = span["start"], span["end"], span["text"]
        assert 0 <= start < end <= len(text), (
            f"{expected_path.name}: span [{start}:{end}] out of bounds for "
            f"normalised text of length {len(text)}"
        )
        actual_text = text[start:end]
        assert actual_text == claimed_text, (
            f"{expected_path.name}: normalised_text[{start}:{end}] is {actual_text!r}, "
            f"fixture claims {claimed_text!r}"
        )

    if expected["expected_action"] == "allow":
        assert expected["expected_spans"] == [], (
            f"{expected_path.name}: expected_action is 'allow' but declares spans "
            f"— an allowed item should have nothing found to allow past"
        )

    for leaked in expected["must_not_appear_in_output"]:
        assert leaked in text, (
            f"{expected_path.name}: must_not_appear_in_output entry {leaked!r} does not "
            f"appear anywhere in the raw normalised text — fixture isn't testing a real leak"
        )

    raw_source = raw_path.read_text(encoding="utf-8")
    for stripped in expected.get("expected_stripped", []):
        # Two halves, and both matter. Present in the source: otherwise the fixture claims
        # to strip something that was never there, and passes forever while testing
        # nothing. Absent from the normalised text: the actual assertion.
        assert stripped in raw_source, (
            f"{expected_path.name}: expected_stripped entry {stripped!r} does not appear "
            f"in {raw_path.name} at all — the fixture cannot be testing that it is "
            f"stripped. (Note the check reads raw bytes, so the fixture must not be "
            f"base64 or quoted-printable encoded.)"
        )
        assert stripped not in text, (
            f"{expected_path.name}: expected_stripped entry {stripped!r} survived into "
            f"the normalised text — L0 invisible-content stripping did not remove it, so "
            f"it would reach the model"
        )

    if "expected_anomalies" in expected:
        # Exact set, not a subset: a new false positive appearing across the corpus is as
        # much a behaviour change as a signal that stopped being raised.
        assert set(normalised.anomalies) == set(expected["expected_anomalies"]), (
            f"{expected_path.name}: anomalies are {sorted(normalised.anomalies)}, "
            f"fixture expects {sorted(expected['expected_anomalies'])}"
        )
