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
