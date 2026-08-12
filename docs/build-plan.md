# SendaShield — Build Plan & Test Strategy

How to build M1 with Claude Code, in chunks small enough to review, with a test gate on
each one.

---

## The ordering principle

**Build detection before I/O.**

Detection is pure functions — easiest to test, hardest to get right, and it *is* the
product. Adapters, MCP plumbing and auth are well-trodden work where mistakes are loud.
Detection mistakes are silent.

So the order is: model → detectors → policy → adapters → MCP → auth → wiring. You will
have a working, tested filter engine before you have fetched a single real email.

---

## Phase 0 — Scaffolding (before any feature work)

**Goal:** a repo where the test gate exists before there is anything to test.

1. `uv init`, project skeleton per `CLAUDE.md` layout
2. `CLAUDE.md` at root, architecture docs in `docs/`
3. `pytest` + `hypothesis` + `ruff` + `mypy` configured, CI running them
4. `pytest` markers registered: `golden`, `leak`, `slow`
5. Empty `tests/fixtures/` with the corpus format documented

**Test gate:** CI green on an empty project. Sounds trivial; skipping it means every later
"is this broken?" question has two possible causes.

---

## Phase 1 — The golden corpus (do this before detectors)

This is the single highest-value artefact in the project. Everything downstream is
measured against it.

**Format** — one pair per case:

```
tests/fixtures/golden/
  de_sparkasse_iban.eml
  de_sparkasse_iban.expected.json
  us_card_in_signature.eml
  us_card_in_signature.expected.json
  cal_therapy_appointment.ics
  cal_therapy_appointment.expected.json
  benign_newsletter.eml
  benign_newsletter.expected.json
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

**Where Phase 1 ends and Phase 2 begins.** As originally written, this phase said to build
40–60 cases covering "each detector, in isolation" *before* writing any detector, while
Phase 2 step 1 says to write each detector's fixtures immediately before implementing it.
Those contradict each other. The resolution, decided during Phase 1:

> **Phase 1 owns `normalise()` and corpus infrastructure. Per-detector fixtures move to
> Phase 2, written immediately before each detector.**

The reason is that a fixture is a claim about what a detector should do, and that claim is
only reviewable against a spec you are about to implement — written months earlier it
becomes a guess nobody can check, which is worse than no fixture because it looks like
coverage. What Phase 1 must deliver is everything a fixture *depends* on: the coordinate
system, the hygiene gates, the schema, and enough cases across every category to prove that
infrastructure works. `credit_card` and `iban` cases are built here as that proof, since
their checksums make them reviewable without any detector existing.

**Build cases covering**, at minimum:

- `credit_card` and `iban` in isolation, in realistic messages — the two whose correctness
  is checkable by arithmetic today. The other four detectors' fixtures belong to Phase 2
- **German and English** variants of each
- **Formatting evasion**: spaces, dashes, non-breaking spaces, zero-width characters
  inside a card number
- **Near-misses that must NOT fire**: an order number that looks like a card but fails
  Luhn; a random 22-character string that isn't a valid IBAN
- **Benign messages** — newsletters, meeting invites, threads. These catch over-masking,
  which is the failure mode nobody tests for
- **Calendar events with no body** — `Vorstellungsgespräch bei Siemens`,
  `Onkologie Nachsorge`, `Termin Dr. Weber`
- **Injection payloads**: white-on-white text, `font-size:0`, HTML comments

**Never use real mail.** Write these by hand or have Claude generate them. Real messages
in a git repo is exactly the mistake this project exists to prevent.

**How to use Claude here:** give it a detector's spec and ask for fixture cases including
adversarial and near-miss ones. Reviewing generated fixtures is far faster than writing
them, and Claude is good at thinking of evasion variants you wouldn't.

---

## Phase 2 — L1 detectors

One detector per chunk. For each:

1. Ask Claude for the fixtures first (or write them). Per the boundary note in Phase 1,
   this is where a detector's fixtures are written — immediately before implementing it,
   while its spec is in front of you and the claims are reviewable
2. **You review the fixtures** — this is where you verify the spec, not the code
3. Ask Claude to implement `detect(text, config) -> list[Span]` to pass them
4. Add a `hypothesis` property test

**Property tests are the point here.** For checksummed identifiers you can generate
exhaustively:

```python
@given(valid_iban())
def test_all_valid_ibans_detected(iban):
    assert detect(f"Please transfer to {iban} today")

@given(st.text(alphabet="0123456789", min_size=16, max_size=16))
def test_only_luhn_valid_cards_detected(digits):
    assert bool(detect(digits)) == luhn_check(digits)
```

That second one is worth more than fifty fixtures — it asserts the detector's behaviour
across the whole input space.

**Order:** `credit_card` (Luhn) → `iban` (mod-97) → `steuer_idnr` (German 11-digit check) →
`secret` (API keys, private keys) → `ssn` → `versicherungsnummer`.

**Test gate:** 100% of golden corpus cases for implemented detectors pass, plus property
tests, plus zero firings on the benign fixtures.

---

## Phase 3 — Pipeline and policy

Pure functions still. No network.

- `pipeline.py`: run layers, merge spans, longest-first, dedupe, **fail closed**
- `policy/`: `(Item, Policy) -> Decision` with actions and thresholds

**The critical tests here are the invariant tests**, and they're different in kind from
unit tests:

```python
@pytest.mark.leak
def test_detector_exception_quarantines():
    """Invariant 2: fail closed."""
    with mock_detector_raising(RuntimeError):
        assert pipeline.process(any_item()).action == "quarantine"

@pytest.mark.leak
def test_l2_cannot_downgrade_l1():
    """Invariant 3: L1 is absolute."""
    item = item_with_valid_iban()
    with mock_l2_returning(confidence=0.0):
        assert "iban" in pipeline.process(item).categories

@pytest.mark.leak
def test_no_expected_secret_survives_any_policy():
    """Invariant 1, brute force."""
    for fixture in all_golden_fixtures():
        for policy in all_shipped_policies():
            out = pipeline.process(fixture.item, policy)
            for secret in fixture.must_not_appear_in_output:
                assert secret not in serialise(out)
```

That last one is the test that matters most. It runs every fixture through every shipped
policy and asserts no known-sensitive string appears anywhere in the output. Keep it fast
enough to run on every commit.

**Test gate:** all `leak`-marked tests pass. Treat a failure here as a build break, not a
bug ticket.

---

## Phase 4 — Adapters

Now I/O, but still no MCP.

- Define `MailSource` / `CalendarSource` protocols
- `FakeMailSource` reading from the golden corpus — **write this first**
- Gmail adapter with `fetch_many()` (batch or concurrent — never a serial loop)
- Google Calendar adapter

**Test gate:** the entire pipeline runs end-to-end against `FakeMailSource` with no network.
Gmail adapter tested against recorded HTTP fixtures (`vcrpy` or hand-written), not live
Gmail.

**First live test:** connect *your own* Google account, run in `--dry-run`, and compare the
output against what you know is in your inbox. This is the first time real data touches the
code, and it should be read-only.

---

## Phase 5 — MCP surface

- Tool definitions with descriptions (the descriptions carry the routing directive and the
  no-solicitation instruction — they're product surface, not comments)
- `search_messages`, `get_message`, `list_events`, `get_event`, `list_withheld`,
  `check_configuration`

**Test gate — the meta-test that enforces Invariant 1:**

```python
@pytest.mark.leak
def test_every_registered_tool_filters():
    """No tool may return content that bypasses the pipeline."""
    for tool in mcp_server.list_tools():
        result = call_with_fixture(tool, sensitive_fixture())
        assert no_known_secret_in(result)
```

This runs over the *tool registry*, so a tool added six months from now is covered
automatically. That's what makes the invariant durable rather than a comment someone
forgets.

**Manual gate:** `npx @modelcontextprotocol/inspector` against your local server. Exercise
each tool by hand before any assistant sees it.

---

## Phase 6 — Auth and dashboard

- First-boot setup token to logs, Argon2id, session cookie, rate limiting
- OAuth 2.1 + DCR for the MCP endpoint
- Minimal dashboard: withheld list, activity view, policy editor

**Test gate:** no default credentials exist (assert the app refuses to serve before setup);
session fixation and rate-limit tests; OAuth flow tested with a scripted client.

---

## Phase 7 — Wiring and first real connection

- Dockerfile, `docker compose`, `.env.example`
- Tailscale Funnel, connect claude.ai

**Test gate — the one that actually matters:**

1. Send yourself three test emails: one with a Stripe test card, one with a valid IBAN,
   one benign
2. Ask Claude to triage your unread mail
3. Open `/activity` and compare **what Claude said** against **what SendaShield sent**

They must match exactly. If Claude mentions anything the activity log shows as withheld,
stop — either the filter leaked or a native connector is still enabled. Both are critical.

---

## Test matrix — what to run at each phase and what it catches

Ordered by phase. Each row is a *type* of test, not an individual case. The "catches"
column is what breaks in production if you skip it.

| Phase | Test type | Catches |
|---|---|---|
| 0 | CI green on empty repo | Ambiguity later about whether a failure is yours or the setup's |
| 1 | **Fixture schema validation** — every `.eml` has an `.expected.json`, JSON matches schema, and every declared offset actually points at the claimed text | Fixtures that silently disagree with themselves; a corpus you can't trust |
| 2 | Unit per detector against golden fixtures | Straightforward misses |
| 2 | **Property tests** over generated input (`hypothesis`) | Whole classes of input you didn't imagine — the main value here |
| 2 | **Benign corpus: assert zero firings** | Over-masking. The failure nobody tests for, and the one that makes the product unusable |
| 2 | **Evasion variants** — spaces, dashes, NBSP, zero-width inside identifiers | Trivially bypassed detection |
| 3 | **Leak test**: every fixture × every shipped policy, assert no known secret in output | Invariant 1. The single most important test in the repo |
| 3 | Fail-closed test: mock each detector raising | Invariant 2. Errors silently passing content through |
| 3 | L1-absolute test: mock L2 returning zero confidence | Invariant 3. Model confidence overriding a checksum |
| 3 | Span merge/overlap correctness | Partially masked identifiers — half an IBAN is still a leak |
| 4 | **Adapter contract suite** — one shared test suite every adapter must pass | A leaky abstraction. This is what proves provider-agnosticism is real rather than aspirational |
| 4 | Recorded HTTP fixtures (`vcrpy`), no live calls | Tests that fail when Gmail is slow; accidental quota burn |
| 4 | **Assert no network in unit runs** (block sockets in `conftest.py`) | A test that quietly hits the real API |
| 4 | Malformed input fuzzing — broken MIME, 50 MB bodies, deeply nested HTML, bad encodings | Crashes that fail *open* if error handling is wrong |
| 4 | **Attachment fixtures** — text-layer PDF (extract), scanned PDF (quarantine), password-protected ZIP (quarantine), `.docx`, mislabelled MIME, nested archive past depth | Attachment path failing open; safety inferred from filename |
| 5 | **Tool registry meta-test** — iterate every registered tool, assert filtering | A tool added later that bypasses the pipeline. Durable enforcement of Invariant 1 |
| 5 | Tool schema validation against MCP spec | Silent client incompatibility |
| 5 | Manual: MCP Inspector against local server | Anything the schema allows but no client can actually use |
| 6 | Assert app refuses to serve before setup completes | Default credentials — the classic self-hosted disaster |
| 6 | Rate limit and lockout tests | Brute force against a public dashboard |
| 6 | Session fixation, cookie flags, CSRF | Standard web exposure on a box holding mailbox tokens |
| 6 | Scripted OAuth 2.1 + PKCE flow | A connector that can't actually connect |
| 6 (M6) | **Cross-user isolation matrix** — every tool, every ref, called as user B with user A's identifiers | A leak between users inside a privacy product. The worst possible failure |
| 6 (M6) | Admin-cannot-read tests — assert admin role is refused on every data endpoint | Admin privilege quietly becoming data access |
| 7 | **Activity-log reconciliation** — what the assistant said vs. what was sent | The bypass, and any real leak. The only test that exercises the whole claim |
| 7 | Performance smoke: 50 messages within the wall-clock budget | Timeouts that return nothing to the user |
| 4 (M4) | **L3 regression fixtures** — 50–100 whole messages, DE and EN, expected topic, no spans | Silent accuracy loss; makes model upgrades reviewable instead of a leap of faith |
| 4 (M4) | L3 malformed-output tests — mock the model returning prose, invalid JSON, out-of-range confidence, timeout | Lenient parsing failing *open* |
| 4 (M4) | L3 injection fixtures — messages containing "ignore previous instructions", fake JSON, delimiter-escape attempts | Verify the worst case is spurious quarantine, never de-escalation |
| all | Snapshot/regression on detection output | Unintended behaviour drift when refactoring |

**Run on every commit:** everything except `slow` and manual. `pytest -m leak` in a
pre-commit hook.

**Run before every release:** the full suite, plus manual Inspector, plus a real
reconciliation test against your own inbox.

---



---

## How to feed requirements to Claude

**Three tiers, deliberately separated:**

1. **`CLAUDE.md`** — loads every session. Short. Invariants, stack, commands, conventions.
   If it grows past ~150 lines, move something to `docs/`.
2. **`docs/architecture.md`** — read on demand. When starting work on the policy engine,
   say *"read the Policy model section of docs/architecture.md, then implement…"*.
3. **Per-task prompt** — the specific chunk, with its test gate stated.

**Do not paste the whole architecture doc into every session.** Nine hundred lines of
context dilutes attention on the fifty that matter, and you'll pay for it in wrong details.

**A good task prompt looks like:**

> Read the "Detection pipeline" and "Policy model" sections of docs/architecture.md.
> Implement the `steuer_idnr` L1 detector: German 11-digit tax ID with the check-digit
> algorithm. Write the fixtures first — include at least three near-misses that must not
> fire. Then implement. Invariant 3 applies: this is deterministic and must never be
> downgraded by L2.

**A bad one:** *"add German tax ID detection"* — Claude will produce something plausible
that fails on check digits, and you won't notice until it matters.

---

## Discipline for a security product

Vibe coding works well for UI, glue, and plumbing. It is dangerous for detection and the
tool surface, because a wrong result looks identical to a right one.

**Review at different depths depending on the file:**

| Area | Review |
|---|---|
| `detect/`, `policy/`, `mcp/tools.py` | **Line by line.** Every diff. No exceptions |
| `store/vault.py`, auth | Line by line |
| Adapters | Skim, trust the tests |
| Dashboard, HTMX templates | Skim |
| Docs, fixtures | Review the *content*, not the code |

**Red flags — reject immediately:**

- A parameter that returns unfiltered content, however it's framed
- `except Exception: pass` anywhere in the detection path
- A detector that catches its own errors and returns `[]` instead of raising
- Content in a log line
- A new dependency added without asking
- A test weakened to make a change pass — check *why* it failed first

**Working rhythm:**

- One chunk per branch, one branch per session. If a session sprawls, the chunk was too big
- Use plan mode before anything touching detection or the tool surface
- Run `pytest -m leak` before every commit; wire it into a pre-commit hook
- When Claude proposes something clever in the detection path, ask it to explain what
  happens on malformed input first
