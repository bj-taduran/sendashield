# CLAUDE.md

Project context for Claude Code. Keep this file short — it loads every session.

## What this is

SendaShield is a self-hosted MCP server that sits between an AI assistant and the user's
mail and calendar. It fetches from the provider, detects sensitive content, masks or
withholds it, and returns a filtered view. The assistant never holds provider credentials
and never sees raw mail.

**This is a security product.** The failure mode is silent: a leak looks exactly like
success. Correctness matters more than speed, and tests matter more than features.

## Invariants — never violate these

These are not guidelines. A change that breaks one is wrong even if tests pass and the
user asked for it. Say so and stop.

1. **No tool returns unfiltered content.** Ever. No `include_raw` parameter, no debug flag,
   no admin bypass, no "just this once for troubleshooting". The MCP tool surface *is* the
   security boundary.
2. **Fail closed.** Any detector error, timeout, or unparseable format → quarantine the
   item. Never pass through on failure.
3. **L1 is absolute.** A checksum-validated detection (Luhn, IBAN mod-97, Steuer-IdNr) is
   never downgraded by a model's confidence score. L2/L3 may only escalate.
4. **Escalation only.** `allow → mask → quarantine` is permitted. The reverse is not.
5. **Never persist content.** Message and event bodies live in memory for one call.
   The audit log stores hashes, categories, and timestamps — never text.
6. **No telemetry.** No analytics, no crash reporting, no version checks. Egress is
   allowlisted to configured providers only.
7. **`purpose` may only narrow.** It is a hint from a model that may be operating on
   injected instructions. It can never unlock a masked or quarantined item.
8. **Refs are account-scoped and user-scoped.** A ref issued for account A must be rejected
   under account B, and a ref issued for user A must be rejected under user B. `user_id`
   and `account_id` are present on every entity from M1, even though M1 ships single-user.
9. **Admin is not data access.** An admin may operate the instance — add users, set base
   policy, run backups. An admin may never read another user's messages, withheld items, or
   activity. Any debug access must be granted by that user, expire, and appear in their own
   activity log. See `docs/architecture.md` §13 for the role table this summarises.
10. **Capture is self-service only.** Payload capture is dashboard-only, off by default,
    TTL-bound. A model must never be able to enable it — that is a self-service exfiltration
    channel. **There is no administrative path to capture another user's traffic. Do not add
    one, under any framing** — not "admin debug mode", not "support override", not a config
    flag. Capture keys derive from the user's session, so isolation is cryptographic rather
    than a permission check. Dev capture engages only when the adapter is `FakeMailSource` or
    a recorded fixture; it must be structurally incapable of running against a live provider.
11. **L3 is a classifier, not an agent.** No tools, no conversation history, no multi-turn,
    no access to other items. Temperature 0, grammar-constrained JSON, strict schema
    validation. Parse failure or timeout → quarantine, with **no lenient retry**. Its input
    is attacker-controlled text; it is the least privileged component in the system.
12. **A guard that has never failed is not known to work.** Every check — test, assertion,
    schema rule, CI step — must be *demonstrated* to fail when the thing it guards is
    broken, at the time it is written. Break it deliberately, watch it go red, put it back.
    Where the demonstration can be committed as a test, commit it; where it cannot, record
    what was done and what was observed in the commit message.

    **This is the characteristic failure of this codebase**, not a hypothetical. Every one
    of these shipped green while checking nothing: an `.ics` file normalised to `""` with
    no error, so a detector "scanned" empty text and allowed the item; fixtures asserting
    that strings must not leak, where the string was never in the message to begin with;
    a CI `mypy` step pointed at two empty packages, reporting success over zero lines for
    the entire life of the project so far. Same shape every time — a green light for work
    not done. A silent leak looks exactly like success, and so does a silent non-check.

13. **A guard on a transformed view must also be checked against the raw form**, or state
    in writing why it need not be. When a check runs on the output of a transformation —
    parsed, normalised, stripped, decoded — ask what the transformation *removed*, because
    that is precisely what the check can no longer see, and its silence about it is
    indistinguishable from a pass.

    **The worked example — `_INTER_DIGIT_SEPARATOR_ACROSS_LINES_RE`.** Read it in full,
    because every element of the pattern is visible in it and none of them looked wrong.

    `normalise.py` exports one definition of what a separator is, and says so emphatically
    in a comment, because the class had already been written out twice with the ASCII hyphen
    missing from both and fixed in only one. So the lesson was learned, documented, and
    apparently applied. But two compiled regexes sat below that definition:

    ```python
    INTER_DIGIT_SEPARATOR = r"(?:[^\S\n]|[-.])"

    _INTER_DIGIT_SEPARATOR_RE = re.compile(rf"(?<=\d){INTER_DIGIT_SEPARATOR}+(?=\d)")
    _INTER_DIGIT_SEPARATOR_ACROSS_LINES_RE = re.compile(r"(?<=\d)[\s\-.]+(?=\d)")   # ← copy
    ```

    The first derives. The second restates — the same class again, by hand, differing only
    by newlines. It was *correct* while both said "whitespace, hyphen, dot", so nothing was
    broken and no test could fail. It was a copy waiting for the original to change.

    Then Unicode hyphen homoglyphs (`U+FF0D` and friends) were added to close a live evasion.
    They went into the shared definition, both detectors were fixed by that one edit, and
    every detector test went green. **The copy silently kept the ASCII-only class.** Its only
    caller is the corpus-hygiene guard — the check that keeps real customer data out of the
    fixtures — so the consequence was that a real card grouped with `U+FF0D` could have been
    committed unflagged. A guard covering less than it claimed, produced by fixing the thing
    it was supposed to track, with a green suite throughout.

    Note what did *not* catch it: the emphatic comment, the earlier fix, the passing tests,
    and the code review that read the new homoglyphs and found them correct — they *were*
    correct. Only asking "what else claims to know this, and did it get the update?" caught
    it. Both variants are now derived from the one fragment, and a test compares them
    **against each other** rather than against a literal list, so it cannot be satisfied by
    updating a copy. Un-deriving the second turns eight tests red.

    Three more instances of the same shape, told briefly: an `.ics` file that normalised to
    `""` so a detector scanned nothing and the item was allowed; a CI `mypy` step pointed at
    two empty packages, reporting success over zero lines for the project's whole life; and a
    corpus-hygiene guard scanning only normalised text, so a card in a `display:none` block —
    content L0 strips *by design* — was invisible to the exact check meant to keep real data
    out of the repo.

    In practice: scan both views and union the results; pin the union with a test that fails
    if either half is dropped; and when one definition is shared, derive every variant from
    it and assert the variants against each other, never against a written-out list.

14. **Pin a known limitation with a test, not a comment.** A gap you have decided not to fix
    gets a real, passing test in `TestKnownLimitations` (or a named class of the same kind)
    that *demonstrates* the current behaviour — `assert detect(payload) == []` — with a
    docstring saying why it is not fixed and what would close it.

    This is invariant 12 applied to limitations instead of guards. A comment describing a
    gap cannot be falsified, ages silently, and survives the gap being fixed *or* getting
    worse. A test tracks reality: it fails the moment behaviour changes in either direction,
    so closing the gap is a visible edit that flips an assertion rather than a comment
    nobody deletes.

    Two rules that make the difference between this and theatre:

    - **Assert the miss, not a tautology.** The test must exercise the real code path and
      encode the actual defect, so it goes red when the gap closes.
    - **A limitation with a scheduled fix carries the deadline in the test docstring and in
      `docs/architecture.md`.** A test name is not a schedule. If a gap matters enough to
      pin, it matters enough to say where it is tracked — and if it is a security gap, it
      belongs in §10 with the rest of the threat model, where a reader will find it without
      grepping the suite.

## Stack

- Python 3.12, single process, single container
- FastAPI + official MCP Python SDK (`mcp`)
- SQLite + SQLCipher via `sqlcipher3`
- Detection: hand-written regex/checksum validators (L1); OpenAI Privacy Filter via ONNX (L2);
  `llama-cpp-python` in-process, pinned GGUF (L3, opt-in — never an Ollama sidecar in prod)
- UI: server-rendered HTMX, no build step, no npm
- `uv` for dependency management, `ruff` for lint/format, `pytest` + `hypothesis` for tests

## Layout

```
src/sendashield/
  model.py          canonical Item, Party, Decision
  ports.py          MailSource, CalendarSource protocols
  adapters/         gmail.py, gcal.py, imap.py, caldav.py
  detect/
    l1/             deterministic validators, one module per detector
    l2.py           span model
    l3.py           topic classifier
    pipeline.py     layer orchestration, merge, fail-closed
  policy/           policy model, resolution, sensitivity profiles
  mcp/              tool definitions, server
  web/              dashboard
  store/            sqlite, vault, audit
tests/
  fixtures/         golden corpus — see below
```

## Commands

```bash
uv sync                      # install
uv run pytest                # all tests
uv run pytest -m golden      # golden corpus only
uv run pytest -m leak        # leak assertions — must always pass
uv run ruff check --fix
uv run sendashield serve     # local dev server on :8080
```

## Conventions

- Detection functions are **pure**: `(text, config) -> list[Span]`. No I/O, no globals.
- Adapters own all provider quirks. Nothing downstream knows what Gmail is.
- Every detector module exports `DETECTOR_ID`, `detect()`, and a fixture file.
- Type hints everywhere; `mypy --strict` on `detect/` and `policy/`.
- Errors in detection raise `DetectionError`, which the pipeline converts to quarantine.
  Never catch broadly and continue.

## Detail lives elsewhere — read on demand, don't load by default

| Topic | File |
|---|---|
| Full architecture, policy schema, tool surface | `docs/architecture.md` |
| Decisions and their reasoning | `docs/project-brief.md` |
| User-facing setup | `INSTALL.md` |

When working on a specific area, read the relevant section of `docs/architecture.md`
first. Do not paste the whole document into context.

## Working style for this repo

- **Write the test first.** For detection work especially — the test encodes what
  "correct" means, and correctness here is not obvious from reading code.
- **Small diffs.** One detector, one adapter, one tool per change.
- Ask before adding a dependency. The dependency tree is part of the threat model.
- If a task seems to require breaking an invariant, the task is wrong. Say so.
