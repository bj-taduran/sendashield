# Golden corpus

Empty by design until Phase 1 (`docs/build-plan.md`).

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

Full format, coverage targets (German/English variants, formatting evasion, near-misses,
benign messages, injection payloads) and how to generate cases: `docs/build-plan.md`,
"Phase 1 — The golden corpus".

**Never commit real mail here.** Hand-write fixtures or generate them — see build-plan for
how to use Claude for this without ever putting real messages in git.
