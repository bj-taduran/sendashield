# Contributing to SendaShield

Thanks for your interest. A few things to know before you start.

## This is a security product

The failure mode here is silent: a leak looks exactly like success. That shapes how
contributions are reviewed.

Please read [`CLAUDE.md`](CLAUDE.md) before writing code. The **invariants** listed there
are not guidelines — a change that breaks one will be rejected even if every test passes.

Changes to `detect/`, `policy/`, `mcp/tools.py`, `store/vault.py`, and the auth code are
reviewed line by line. Adapters, dashboard, and templates are reviewed more lightly.

## Tests

- **Write the test first**, especially for detection. The test encodes what "correct"
  means, and correctness here is not obvious from reading code.
- Every detector needs golden fixtures, including **near-misses that must not fire** and
  **benign messages with zero expected detections**. Over-masking is a real failure, not a
  safe default.
- `pytest -m leak` must pass. Treat a failure as a build break.
- **Never commit real email.** All fixtures are synthetic. Real messages in git history are
  permanent, and it is precisely the mistake this project exists to prevent.

## Dependencies

Ask before adding one. The dependency tree is part of the threat model — this process
handles mailbox credentials and plaintext correspondence.

## Contributor Licence Agreement

Contributions require signing a CLA before merge.

**Why, stated plainly:** the maintainers intend to offer a commercial edition alongside
this AGPL-3.0 project. Under AGPL without a CLA, relicensing any part of the codebase later
would require the agreement of every past contributor — some of whom become unreachable —
which would make a commercial edition impossible.

The CLA grants the maintainers the right to relicense your contribution. It does **not**
take away your rights: you keep copyright in your work and can use it however you like.

The open-source edition will remain complete and genuinely usable. **No detector, provider,
or filtering capability will ever be paywalled** — if the free edition detected less, the
free edition would leak, and the entire premise would collapse. The commercial boundary is
organisational administration and compliance paperwork, not protection.

If you disagree with this arrangement, that is entirely reasonable, and we would rather you
know before investing time.

## Reporting security issues

Do not open a public issue. See `SECURITY.md`.
