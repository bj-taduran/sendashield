# Golden corpus

One pair per case: a raw message/event file plus its expected-result JSON, e.g.

```
de_sparkasse_iban.eml
de_sparkasse_iban.expected.json
cal_therapy_appointment.ics
cal_therapy_appointment.expected.json
```

```json
{
  "expected_spans": [
    { "detector": "iban", "start": 142, "end": 164, "text": "DE89370400440532013000" }
  ],
  "expected_action": "mask",
  "must_not_appear_in_output": ["DE89370400440532013000"],
  "notes": "Sparkasse payment confirmation, German, IBAN in body"
}
```

`.expected.json` is validated against `tests/fixtures/expected.schema.json`. `start`/`end`
offsets are indices into the fixture's normalised text — see the module docstrings for the
exact coordinate systems; `tests/test_golden_corpus.py` asserts every fixture is
self-consistent with its own.

| Fixture | Normalised by | Coordinate system |
|---|---|---|
| `.eml` | `normalise(raw)` | `subject \n\n body` |
| `.ics` | `normalise_calendar(raw)` | `SUMMARY \n\n LOCATION \n\n ORGANIZER \n\n ATTENDEES \n\n DESCRIPTION` |

A missing field still occupies its place in both, so an event with only a summary reads
`Standup\n\n\n\n\n\n\n\n` — the shape is fixed and an offset means the same thing across
fixtures.

**The calendar field order is frozen.** Reordering, inserting or removing a slot
invalidates every `.ics` offset in this directory, silently for any fixture that declares
no spans. `ORGANIZER` and `ATTENDEES` are reserved and always empty today; they are
populated at M4, and their slots exist now precisely so that closing that gap moves no
offset. This already happened once — adding the two slots moved
`cal_iban_in_description`'s span from 51 to 55 — which is the churn freezing the order
prevents from recurring.

**A `.ics` fixture must contain exactly one `VEVENT`.** `normalise_calendar()` returns one
item per event by design (a calendar file is a container, not a document — two events may
warrant entirely different policy, and concatenating them would let one event's decision
cover another's content). A fixture with several events would have no way to say which
event a span offset belongs to, so the corpus asserts the constraint rather than silently
taking the first. Multi-event splitting is a normalisation property and is tested in
`tests/test_normalise.py`.

Full format and coverage targets (German/English variants, formatting evasion, near-misses,
benign messages, injection payloads): `docs/build-plan.md`, "Phase 1 — The golden corpus".

**Never commit real mail here.** Hand-write fixtures or generate them — see build-plan for
how to use Claude for this without ever putting real messages in git. Card numbers must be
from a published test range (Stripe's, verified against docs.stripe.com/testing); IBANs
must be synthetic values that happen to pass mod-97, not real accounts.

**These fixtures are reviewed by hand and are not regenerated.** Whatever produced a case
initially is scaffolding and is thrown away; there is deliberately no generator script in
this repo. A corpus that can be refreshed with one command stops being a set of reviewed
assertions and becomes derived output, and the review is the only thing standing between
this directory and a fixture that quietly asserts nothing. Changing a case means editing
it and re-reading it. `pytest -m golden` will catch offsets you forgot to move — it will
not catch a case you no longer understand.

**Phone numbers and other incidental identifiers must come from a reserved fictional
range** rather than being added to `DECLARED_SYNTHETIC_IDENTIFIERS`: Germany `+49 30 23125
xx`, US `555-0100`–`555-0199`, UK `07700 900xxx`. These ranges exist precisely so examples
never dial a real person. An allowlist entry is a past reviewer's assertion that some
number was safe, and nothing re-checks it; a reserved range is safe by construction and
gives the hygiene guard nothing to fire on in the first place.

This is enforced, not just asked for: `test_corpus_contains_only_declared_synthetic_identifiers`
fails on any identifier-shaped token in any fixture that isn't listed in
`DECLARED_SYNTHETIC_IDENTIFIERS` (`tests/test_golden_corpus.py`). It scans the *normalised*
text, so a value hidden in a base64 body is still seen, and it collapses digit grouping, so
`4242 4242 4242 4242` is caught too. Adding a fixture with a new synthetic value means
adding that value to the list — deliberately a small speed bump.

Fixtures must also parse cleanly: `test_golden_fixture_parses_without_defects` rejects any
case that only survives the stdlib parser's error recovery. Malformed-MIME behaviour is
tested deliberately in `tests/test_normalise.py`, not by accident here.
