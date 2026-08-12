# SendaShield — Project Brief & Decisions Log

*Bird's-eye summary of the full design conversation. Companion to
`docs/architecture.md` (technical detail), `INSTALL.md` (user-facing setup), and
`private/commercial-plan.md` (parked).*

---

## 1. The problem being solved

When someone connects Gmail and Google Calendar to an AI assistant, **every message the
assistant fetches lands raw in its context window**. There is no filter. A request as
ordinary as "triage my unread mail" can pull bank statements, medical correspondence, a
lawyer's letter, or tax identifiers into a third party's system — and into a chat history
the user cannot delete.

SendaShield inspects every item before it reaches the assistant, masks or withholds
sensitive content according to a policy the user controls, and reports honestly on what
was held back.

**The promise is reduction and visibility, never certainty.** Automated detection is
imperfect. The README must say so.

### What made this hard

The obvious architecture — sanitise data on its way to an LLM API — doesn't work for
consumer claude.ai, where connectors run server-side in Anthropic's cloud. There is no
point in that data path we can intercept.

Three candidate interception points were considered:

| Option | Verdict |
|---|---|
| **A.** Own the whole pipeline (our app calls the LLM) | Rejected — that's building a rival assistant, not protecting an existing one |
| **B.** Become the connector (be the MCP server) | **Chosen** — we hold the OAuth token, the assistant never touches Google |
| **C.** Proxy the LLM API | Rejected — cannot reach consumer claude.ai at all |

---

## 2. Name

**SendaShield** — from **Sen**sitive **Da**ta **Shield**.

Path to it: *HedgeAI* (existing NY fintech entity; "hedge" misreads as hedge-fund) →
*Hedgerow* (living, selectively permeable boundary — but Hedgerow Software Ltd has held
the name in EHS software since the 1990s) → *DataVeil* (an active commercial data-masking
product in the identical category — ruled out) → *Sedashield* → **SendaShield**.

The extra `n` exists to avoid a spoken collision with Seagate's SeaShield. A happy
accident: lowercased for URLs and packages it reads `sendashield` — "send a shield" — which
fits an email tool.

**Still to do before the repo is public:** verify GitHub org, PyPI, npm, and domain
availability in one sitting. Two candidate names died on exactly this check.

---

## 3. Licensing

**AGPL-3.0 + Contributor Licence Agreement.**

- **AGPL** because its network clause forces anyone *hosting* a modified version to publish
  their changes. That is the specific protection against a vendor turning this into the
  subscription product the project exists to avoid.
- **CLA** because a commercial edition is planned. Without one, AGPL cannot be
  dual-licensed later without the consent of every contributor — some of whom will be
  unreachable, making the licence permanent.
- **Deadline: before the first outside pull request is merged.** While authorship is sole,
  all options remain open.
- State the reason for the CLA plainly in `CONTRIBUTING.md`. Undisclosed CLAs breed
  resentment; disclosed ones are broadly accepted.
- **Trademark is separate from copyright.** The name can be owned and defended even though
  the code is AGPL. This is the only real protection against a fork trading on the
  project's reputation.

---

## 4. Architectural design

### Deployment: self-hosted, one instance per user

Each user runs their own instance with their own Google OAuth client. This is not a
preference — it is what makes the project possible:

| If we hosted it | Consequence |
|---|---|
| Process others' mail | GDPR **processor**: Art. 28 DPA, Art. 30 records, Art. 32 security, Art. 33 breach notification in 72h, Art. 35 DPIA |
| Restricted-scope data transits our servers | Google **CASA** audit, paid annual assessment by an approved lab |
| Store users' refresh tokens centrally | A **honeypot** — one breach exposes every connected mailbox simultaneously |

Self-hosting moves all three to the user, who is covered by GDPR's **household exemption**
(Art. 2(2)(c)) for personal use.

**Key correction to a common misunderstanding:** zero retention does *not* avoid GDPR.
Processing includes any operation on personal data — erasure is explicitly listed as
processing. Data held in RAM for 40 ms is processed. There is no "mere conduit" exemption
in data protection law. And most of the affected people are not the user: every mailbox
contains personal data about senders, recipients, and everyone mentioned in the bodies.

### Interception: SendaShield *is* the MCP server

```
user prompt
  → assistant picks a tool + arguments  (search_messages, q="is:unread newer_than:1d")
  → SendaShield receives the call, validates args
  → SendaShield calls the provider API, gets raw data
  → detection + policy
  → filtered payload + withheld count returns to the assistant
```

**Important:** the assistant still composes the query. SendaShield is a tool provider, not
an orchestrator. Consequences: search arguments are attacker-controllable and must be
validated; result *metadata and counts* need filtering too, not just bodies.

### Provider abstraction

Adapters behind two narrow ports (`MailSource`, `CalendarSource`) normalise everything into
a canonical `Item`. Detection and policy never see provider specifics.

| Adapter | Milestone | Note |
|---|---|---|
| Gmail, Google Calendar | M1 | Reference implementation |
| Generic IMAP, CalDAV | M3 | **No cloud console needed** — lowest friction, and the contingency if Google's policy changes |
| Microsoft Graph, JMAP | M7 | |

**Calendar is a first-class provider, not an afterthought.** An event usually has no body,
so nearly all signal is in the title and attendee list. `Vorstellungsgespräch bei X`,
`Onkologie Nachsorge` contain no detectable entity and need whole-item classification. No
commercial vendor handles this — every one lists Calendar as supported and then discusses
only documents. Likely the project's sharpest differentiator.

### Detection pipeline — four layers

```
L0  Structural rules      sender/domain lists, labels, folder and calendar rules
L1  Deterministic         regex + checksum: Luhn, IBAN mod-97, Steuer-IdNr, SSN, secrets
L2  Span model            OpenAI Privacy Filter (Apache-2.0, local, 1.5B/50M active, 128k ctx)
L3  Whole-item classifier health · legal · HR · financial distress · intimate · immigration
```

**Invariants:**
1. **Fail closed.** Any error, timeout, or unparseable format quarantines the item.
2. **L1 is absolute.** A checksum-validated hit is never downgraded by model confidence.
3. **Escalation only.** L3 may move `allow → mask → quarantine`, never the reverse.
4. **Unknown format = quarantine.** Encrypted body, unsupported MIME → withhold, don't guess.

### Policy: three actions, per detector

| Action | Behaviour | When |
|---|---|---|
| `allow` | Untouched | Entity is needed for the task |
| `mask` | `[CREDIT_CARD_1]` | Item stays useful; only the value is dangerous |
| `quarantine` | Whole item withheld + notice | Sensitivity is the item, not a span |

### The action-asymmetry principle

> **The right confidence threshold depends on the action, not the detector.**

A false-positive *mask* costs almost nothing. A false-positive *withhold* may cost a
missed deadline. So:

- `mask` → `min_confidence: 0.25` — **permissive**, catch everything suspected
- `quarantine` → `min_confidence: 0.70` — **conservative**, only when confident

**With one exception:** permissive masking applies only to *value-like* detectors (account
numbers, cards, IBANs, secrets, phones, addresses). Names, organisations and dates default
to `allow`, because masking them at 0.25 renders the inbox unreadable — every sender
becomes `[PERSON_3]` and triage becomes impossible.

Exposed as a **Relaxed / Balanced / Strict** slider. Balanced ships as default.

### Report modes — how much the assistant is told

| Mode | Assistant receives | Trade |
|---|---|---|
| `out_of_band` | Nothing | **Silent incompleteness** — assistant says "nothing urgent" when the urgent item was withheld |
| `counts_only` **(default)** | `withheld_count: 4` | Honest answers, effectively no inference surface |
| `in_band` | Sender domain, category, timestamp | Useful triage, at a cost |

`in_band` adds `category_detail: coarse | fine`. Coarse emits `financial_identifier`; fine
emits `iban`. **The category field carries more inference than the sender domain** —
`sparkasse.de` is low-information, but `topic_health` is our conclusion about content we
just refused to transmit.

**What `in_band` actually costs:** aggregation over months builds a searchable index of
sensitive correspondents in chat history; that history lives under the AI provider's
retention policy and is not the user's to delete; and it gives an injected payload
targeting information.

**The solicitation pathway — applies in every mode.** Told "a message from your bank was
flagged for an IBAN," an assistant may offer *"paste the relevant line and I'll finish the
draft."* People comply with specific requests far more than vague ones. Mitigated by
tool-description text forbidding it — advisory, not enforced.

### Reversible masking and the write path

```
provider ──raw──▶ [detect] ──▶ vault {ACCOUNT_1 → "DE89 3704…"} (local, encrypted, TTL)
                       └──masked──▶ assistant ──▶ draft containing [ACCOUNT_1]
provider ◀── rehydrated ◀── [restore] ◀────────────┘
```

Restoration happens **only** at the provider boundary, never in a tool response.

**`secret` and `credit_card` are destructively masked** — original discarded, no
rehydration possible by any path. An assistant should never be able to cause an API key or
card number to be emitted. `iban`, `phone`, `address` remain restorable, since sharing an
IBAN in a reply is a normal German workflow.

### Write path: drafts by default, but the two providers differ

- **Gmail** → write a native Gmail draft. It sits in Drafts, the user edits it in a familiar
  UI, nothing sends until they press send.
- **Calendar** → **an approval queue inside SendaShield.** Calendar has no draft state:
  creating an event with attendees sends invitations immediately and irreversibly. Nothing
  touches Google Calendar until the user approves. Adding attendees requires its own
  separate confirmation.

This implements the user's original requirement literally: *"do not send anything without
my approval."*

---

## 5. Features

### Core (open source, complete)

- Filtered MCP tool surface: `search_messages`, `get_message`, `list_events`, `get_event`,
  `list_withheld`, `draft_reply`, `check_configuration`
- Four-layer detection, three-action policy, per-detector configuration
- Multi-account, multi-provider, in one instance
- **Simulation mode** — scan the last N days and see what *would* be filtered, before any
  assistant is connected. Trust is driven by verifiable consistency more than raw accuracy.
- **Capture sessions** — opt-in, TTL-bound recording of the exact JSON payloads sent to the
  assistant. The content-free audit log answers *"what has this been doing?"*; capture answers
  *"did the filter actually work?"*. Off by default, never enablable by a tool call.
  **Strictly self-service: there is no administrative path, by design.** A user captures their
  own traffic, reviews it, and decides what to share — which is the entire support flow. Keys
  derive from the user's session, so isolation is cryptographic rather than a permission check;
  an active capture shows an unsuppressible banner; start/stop is written to the user's own
  tamper-evident log. *"No such feature exists"* is a far stronger claim than *"the feature
  exists but is restricted"* — and it is what makes a §87 BetrVG works-council conversation
  straightforward.
- **Dev capture and shadow mode** — feature testing without touching real mail. Dev capture
  engages only against `FakeMailSource` or recorded fixtures, structurally unable to run on a
  live connection. Shadow mode (M4) runs a new policy or model version alongside the current
  one and records **only the diff** — which items changed decision and how — with no content.
  Also how any user safely evaluates an upgrade before adopting it.
- Withheld-items dashboard, content-free audit log, activity view
- Reversible masking with local vault; approval queue for calendar writes
- Background pre-scanning and decision cache
- Prompt-injection normalisation and defanging

### The `purpose` parameter — closed enum, M4

`Literal["triage","search_specific","summarise","draft_reply","schedule","unspecified"]`.
Task-conditioned minimisation: policy asks *is this sensitive?*, `purpose` adds *does this
task need it?*

**Free text was rejected.** Interpreting it needs either brittle keyword matching or a model
call — and a model reading attacker-influenced text to decide filtering behaviour would add
an injection surface inside a feature meant to reduce exposure. An enum is a lookup table.

**Language independent.** A German request still yields `purpose="triage"`; the assistant
maps intent to a fixed machine value. German coverage is needed in the *fixtures*, not the
enum.

**The safety property:** `unspecified` is the baseline, and **no value is more permissive
than baseline**. Every other value only tightens. A manipulated `purpose` can therefore only
over-restrict — never unlock.

**Handling manipulation:** valid-but-wrong value → proceed and log the anomaly (cannot leak).
Out-of-enum value → coerce to the most restrictive purpose, proceed, flag. Never error —
that confirms the probe to an attacker and breaks buggy clients. **Anomalies surface in the
dashboard, never to the model**, which would hand an attacker a feedback channel.

Accepted and logged from M1, narrowing implemented at M4, so the tool schema never breaks.

### L3 — a classifier, never an agent

L3 returns a judgment about the whole document (`{"topic":"health","confidence":0.82}`),
catching what span detectors structurally cannot: a clinic letter with no identifier in it,
a Kündigung, a calendar entry reading only `Onkologie Nachsorge`.

**No tools, no history, no multi-turn, no access to other messages, no authority to decide.**
Its input is attacker-controlled text — anyone can send an email — so it is the least
privileged component in the system: reads a string, returns an enum. It *proposes* an
escalation; the policy engine decides.

Engine: **`llama-cpp-python` in-process**, not an Ollama sidecar. Identical injection risk
(same weights), but no second process holding plaintext and no daemon to maintain.

Temperature 0, fixed seed, grammar-constrained JSON, pinned GGUF hash. Parse failure or
timeout → quarantine, with **no lenient retry**. Escalation-only bounds a successful attack
on L3 to spurious quarantine — **denial of service, never disclosure**.

**Maintenance is near zero by design.** A local model is frozen bytes: no model drift, unlike
a hosted API where the provider changes the model underneath you. Concept drift in these
categories is measured in years — an oncologist's letter in 2031 reads like one in 2026, and
nobody is trying to make their therapy appointment look like a newsletter. 50–100 regression
fixtures in CI make model upgrades an afternoon rather than a leap of faith.

**Distillation to an encoder classifier is deliberately deprioritised** — it would remove the
injection surface and cut RAM from 3–4 GB to under 1 GB, but requires a hand-built labelled
dataset maintained forever. A permanent obligation traded for an optimisation.

**L3 is additive and opt-in.** If it fails or is disabled, checksum-validated detection of
every high-value identifier still runs. You lose topic detection, not the product.

### Prompt-injection defence — a second value proposition

**The attacker is the sender, not a man in the middle.** Anyone who knows the address can
place text in the inbox; models treat tool results as authoritative. Cost of attack: one
email.

Nearly free to defend, because we already parse every body. And there is a direct synergy:
zero-width characters and invisible CSS hide injection payloads *and* evade PII detection
(`4111␏1111…` slips past a card regex). **Normalising invisible text strengthens the PII
filter and defeats injection simultaneously.**

| Control | Nature |
|---|---|
| Normalise before scanning — strip zero-width, `font-size:0`, `display:none` | Deterministic |
| Label provenance — wrap bodies in untrusted-data delimiters | Advisory |
| Detect AI-directed imperatives | Heuristic |
| Defang exfiltration — remote image URLs, links with query params | Deterministic |

Claim *raises the cost of the attack*. Never *prevents it*.

---

## 6. Tech stack

**Python 3.12, single process, single container.**

| Concern | Choice |
|---|---|
| MCP + HTTP | FastAPI + official MCP Python SDK |
| L1 detectors | Hand-written regex + checksum validators |
| L2 spans | OpenAI Privacy Filter via ONNX Runtime (CPU-only) |
| L3 topics | `llama-cpp-python` **in-process** (opt-in), pinned GGUF |
| Storage | SQLite + SQLCipher |
| UI | Server-rendered HTMX |
| Packaging | Multi-arch Docker |

### Why Python, not Go or Java

1. **The detection ecosystem is Python.** Privacy Filter ships PyTorch weights with a
   Python reference implementation; Presidio, spaCy, GLiNER are all Python. Reimplementing
   via ONNX bindings means owning tokenisation, span decoding, and offset mapping yourself
   — precisely where an off-by-one turns into half an IBAN leaking.
2. **No IPC boundary carrying plaintext.** A Go server with a Python detection sidecar
   sends cleartext mail across a localhost socket on every call — a second process, second
   heap, second potential crash dump. Bad trade for a tool whose entire claim is minimising
   where plaintext exists.
3. **The workload doesn't reward Go.** One user, a few calls per hour, I/O-bound on
   provider APIs and inference. The GIL is irrelevant while waiting on Gmail.

**Where this changes:** if inference latency dominates in production, **Rust** (not Go) is
the target for a v2 detection core — `ort` bindings, memory safety for a secrets-handling
tool, single-binary distribution. Java is ruled out: same ecosystem gap as Go without the
deployment advantage.

**Presidio is deliberately not a core dependency** — Privacy Filter plus hand-written
validators covers the same ground with a far smaller dependency tree. Available as an
optional extra engine.

### Detection profiles — matched to hosting

| Profile | Layers | RAM | Runs on |
|---|---|---|---|
| **Lite** | L1 only | ~150 MB | Anything, including free PaaS tiers |
| **Standard** | L1 + small NER | ~700 MB | 1 GB tiers |
| **Full** | L1 + L2 + L3 | 3–4 GB | Hetzner, home machine |

**Lite is not a toy** — checksum detection covers cards, IBANs, Steuer-IdNr and secrets with
near-zero false positives. What it cannot do is catch a message sensitive by topic alone.

**Supply-chain note:** pin the official Privacy Filter repo and verify weight hashes in CI.
A typosquat reached #1 trending on Hugging Face in 2026 before takedown.

---

## 7. Data privacy

### What is stored

| Data | Persisted | Note |
|---|---|---|
| Message/event bodies | **Never** | In memory for one call only |
| Attachments | **Never** | Streamed, scanned, discarded |
| OAuth tokens | Yes | Encrypted; the only long-lived secret |
| Decision cache | Hash + verdict only | SHA-256 of content — not reconstructable |
| Audit log | **Content-free** | Timestamp, item hash, category, action. 6-month retention |
| Withheld notices | Metadata only | 30-day default, adjustable |
| **Capture sessions** | **Opt-in, TTL-bound** | Exact tool payloads for verification. Off by default, auto-expires, dashboard-only |
| Telemetry | **Never** | No analytics, no crash reporting, no version checks. Egress allowlist enforced |

Delete-everything button with **typed confirmation** (`DELETE`), since it is irreversible.

### Google OAuth posture — Production, unverified

| State | 7-day token expiry | Warning screen | Cap | Verification + CASA |
|---|---|---|---|---|
| Testing | **Yes** | Yes | 100 | No |
| **Production, unverified** | **No** | Yes | 100 | **No** |
| Production, verified | No | No | Unlimited | Yes, annual, paid |

The 7-day expiry is tied to **publishing status = Testing**, not to being unverified.
Publishing to Production removes it with no review, under Google's **Personal Use
exemption** (fewer than 100 users, click through the warning screen).

**Never ship a default OAuth client ID.** A shared client would exceed 100 users
immediately, forcing restricted-scope verification and a paid annual CASA assessment — the
cost that makes a free project impossible. **The per-user setup friction is what purchases
the exemption.** `INSTALL.md` walks users through creating their own.

**Policy risk:** the exemption is Google's to withdraw. Mitigation is not technical — build
IMAP and CalDAV early (M3) so a Google-free path exists before it is needed.

**Revocation handling is required regardless:** Gmail-scoped tokens are revoked when the
user changes their Google password (the most common cause, and it surprises everyone);
tokens unused six months are invalidated. SendaShield must surface `invalid_grant` loudly
— a filter that has silently lost its provider connection returns an empty result set,
indistinguishable from an empty inbox.

### Authentication

- **Dashboard:** username + password. First boot prints a single-use setup token to
  container logs — **no default password ever exists**. Argon2id, `HttpOnly`/`Secure`/
  `SameSite=Lax` cookie, rate limiting, optional TOTP. No email means no password reset;
  recovery is `docker exec … reset-password`.
- **Multi-account (M1) vs multi-user (M6)** — different things. Multi-account is *one
  person, several mailboxes*: a data-model concern. Multi-user is *several people, one
  instance*: an authorization and legal concern. `user_id` is carried on every entity from
  M1 even though M1 ships single-user, for the same reason `account_id` is — retrofitting
  an isolation boundary is how isolation bugs happen.
- **Multi-user isolation.** The MCP URL is identical for every user; **the access token
  carries the identity**, which is why OAuth 2.1 was chosen over a static bearer token — a
  shared secret cannot express who is calling. Complete isolation by default: no user sees
  another's messages, withheld items, audit entries, policy, or existence. **Admin ≠ data
  access** — an admin operates the instance and does not read it. An optional `guardian`
  role can see a named minor's withheld *notices* only, must not conceal that it is active,
  and cannot read content. Honest limit: **shell access to the host bypasses all of it.**
- **MCP endpoint:** OAuth 2.1 with Dynamic Client Registration, SendaShield acting as its
  own authorization server. User pastes their URL into claude.ai, is redirected to their own
  instance, signs in with existing dashboard credentials, approves. No secrets copied by
  hand, PKCE throughout. Bearer-token fallback for clients without OAuth.

---

## 8. Limitations and threat model

### Defends against

- Raw mail and calendar content entering an assistant's context window
- Sensitive items persisting in assistant chat history
- Broad provider access being exercised beyond the current task
- Silent filtering — the user always has a local record

### Does *not* defend against

**The bypass — the largest gap.** If the native Gmail connector stays enabled, the
assistant routes around us. **SendaShield cannot detect this.** An MCP server sees only
calls made to itself; it receives no list of the client's other connectors.
`check_configuration()` returns a checklist, never a verdict.

Controls, in descending order of reliability:

| Control | Strength |
|---|---|
| Native connector removed | **Enforcing** — the only real control |
| Standing user instruction in preferences | Strong influence |
| Tool naming and descriptions | Weak influence |
| Activity log comparison | Detection after the fact, manual |

**Wording constraint for the README:** the honest claim is *"SendaShield filters everything
that passes through it"* — never *"SendaShield prevents your assistant from reading
sensitive email."*

Also outside scope: detection error (false negatives are inherent), the user pasting
content manually, social engineering via the assistant, and compromise of the user's own
instance.

**Context window ceiling.** 500 full messages is ~500k–800k tokens; no architecture solves
this, and native connectors hit the same limit. What we control is whether hitting it
produces a timeout or an honest partial answer.

**Attachments: text extraction from M1, OCR at M7.** Plain text, OOXML, and PDFs *with a
text layer* are extracted and scanned from M1 — most business PDFs qualify, so this is a
much smaller cut than blocking all attachments. Images and scanned documents are quarantined
with reason `attachment_not_scannable`; undecodable content (password-protected, corrupt,
depth-exceeded) with `attachment_undecodable`. **The whole message is quarantined, not just
the attachment** — partial delivery creates false confidence. Notices carry MIME type and
count, never the filename.

---

## 9. Performance architecture

Four decisions that are cheap now and structural later:

1. **`fetch_many()` in the adapter port.** Gmail's list endpoint returns IDs only; 50 serial
   fetches is ~8s of round trips. Batch or concurrent brings it under a second.
2. **Two ceilings, not one.** `search_messages` default 25 / max 100; `get_message` max 10
   per call; dashboard scans unbounded. Plus a ~20s wall-clock budget returning
   `truncated: true` rather than timing out. Caps must be documented — a silent cap looks
   identical to missing mail.
3. **Decision cache** keyed on `SHA-256(content) | policy_version | detector_version`.
   Stores hash and verdict, never content. Versions in the key are mandatory, or a policy
   edit silently does nothing.
4. **Background pre-scanning** — a worker syncs continuously (Gmail `history.list`, IMAP
   `IDLE`, CalDAV `sync-collection`), scanning and caching *before* any query arrives. Query
   time becomes a cache lookup. **This is something a stateless connector cannot do** — our
   architecture is better placed on latency than the thing it replaces. Must be a documented
   setting with an off switch, since it processes mail the user never asked about.

Plus **job-and-poll** for large scans: return `{status: "scanning", job_id, scanned, total}`
immediately and let the assistant poll, converting one long call into several short ones.

---

## 10. Prior art

**Nobody serves individuals.** Every product found is enterprise: admin console, tenant
scope, per-seat pricing, an externally-defined taxonomy.

| Camp | Examples | Relevance |
|---|---|---|
| LLM API gateways | LangChain LLM Gateway, Bifrost, Gravitee, Philter | Can't reach consumer claude.ai. Worth stealing: **reversible redaction** with session-state mapping |
| **MCP gateways** | **Strac** (closest match), MCP Manager, MintMCP, Lunar.dev, Obot, TrueFoundry | Our category. TrueFoundry's threat model confirms tool results are the underguarded surface |
| Label-based exclusion | Microsoft Purview, Google IRM/CSE | Quarantine model, enterprise-only, own-AI-only. Purview's citations validate the transparency idea |
| Endpoint/browser DLP | Nightfall, Zscaler, Netskope, dope.security | Aimed at paste, not connectors |
| Academic | **AirGapAgent**, **Rescriber**, MINIM | Task-conditioned minimisation; request escalation; ternary keep/abstract/remove |

**Strac is the closest existing thing** — its Gmail MCP DLP intercepts tool calls and
redacts before the agent reads. Its weakness isn't price: **redaction runs in Strac's
cloud**, so for an individual it merely relocates trust. That is the argument for the
open-source local version — not that it's cheaper, but that the claim is verifiable.

**Findings that shaped the design:**
- Rescriber (CHI 2025): a local Llama3-8B matched GPT-4o in user perception; **comprehensiveness
  and consistency of detection** drive trust more than accuracy. → simulation mode, decision cache.
- A 2026 CHI study: users performed barely better than chance at anticipating what an LLM
  could infer; their own rewrites blocked inference only 28% of the time. → **this must be
  automatic**, users cannot self-serve it.
- AirGapAgent: minimisation should be *task-conditioned*, with **request escalation to the
  user** rather than letting the model coax data out. → the `purpose` parameter and
  conservative report defaults.

**Four unfilled gaps:** individuals are unserved; calendar is a blind spot everywhere;
whole-item topic sensitivity is unsolved outside manual labelling; and the withheld-items
report is nearly unexplored.

---

## 11. Hosting and cost

Verified August 2026; **all providers change prices often.**

| Option | Profile | Cost/month |
|---|---|---|
| **Own machine + Tailscale Funnel** | Any | **€0** + electricity |
| **Hetzner CAX11** (2 vCPU ARM, 4 GB) | Any | **~€5** |
| Hetzner CAX21 (8 GB) | Full | ~€8.50 |
| Railway Hobby | Lite | ~$5 |
| Fly.io | Lite | ~$2–3 |
| AWS t4g.medium | Any | ~$27 |
| Render free tier | ✗ | Doesn't work — 512 MB, spins down at 15 min |

Railway and Fly bill **actual usage per second** — excellent for bursty workloads, poor for
ours, since a resident model has no idle capacity to save on. A 4 GB always-on service runs
~$45 on Railway and ~$20 on Fly against €5 on Hetzner. For **Lite** the calculus flips and
their git-push deployment is genuinely nicer.

**Everything else is free:** Gmail and Calendar APIs (fraction of a percent of quota, no
billing account), TLS via Let's Encrypt, no domain required.

**Getting a URL for a home machine: Tailscale Funnel.** German connections generally cannot
port-forward — DS-Lite and CGNAT leave no public IPv4 to forward from. Funnel gives a
stable `https://machine.tailnet.ts.net` with a valid certificate, free on the Personal
plan, no domain, no port forwarding. **TLS terminates on your machine**, so Tailscale
relays encrypted bytes it cannot read. Caveat: the machine must stay awake.

---

## 12. Build order

| | Milestone | Contents |
|---|---|---|
| **M1** | Prove the boundary | Gmail + Calendar adapters, L1 only, mask/quarantine, `counts_only`, multi-account model **with `user_id` on every entity (ships single-user)**, `fetch_many`, async, dashboard auth, OAuth 2.1 MCP endpoint, Docker. Attachments withheld |
| **M2** | Real detection and speed | Privacy Filter L2, policy engine + sensitivity slider, decision cache, background pre-scanning, job-and-poll, simulation mode, audit log |
| **M3** | Provider independence | IMAP + CalDAV — validates the ports, and the contingency if Google's exemption changes |
| **M4** | Semantics | L3 topic classifier, calendar-title profile, German detector pack |
| **M5** | Write path and injection | Gmail native drafts with rehydration, egress scanning, injection defences |
| **M6** | Multi-user (household) | Per-person logins, `user_id` scoping enforced, user/admin/guardian roles, admin-without-data-access. Isolation tests are the gate |
| **M7** | v1.0 | Calendar approval queue, attachments with OCR, Microsoft Graph, hardening, docs |

**Ship M1 narrow, in Lite profile, on your own machine.** A working filtered path for one
provider beats a broad design that never proves the boundary holds.

**Multi-user is deliberately late.** It touches auth, the data model, the dashboard and
every tool call — a large authorization surface with no working filter to show for it. The
organisational layer above household multi-user sits in the commercial edition.

---

## 13. Commercial plan — parked

Full detail in `private/commercial-plan.md`. Summary:

- **Not a hosted service.** Hosting reintroduces processor status, CASA, and the token
  honeypot — the three things this architecture exists to avoid.
- **Self-hosted, per-seat, EU SMBs** using non-Microsoft AI assistants who care about
  residency. Microsoft has moved hard into this segment (Purview Suite cut to $10/user/mo)
  but cannot govern Claude or ChatGPT, cannot serve Google Workspace, and requires an IT
  function the buyer doesn't have.
- **Never paywall a detector.** The boundary is *individual protection* vs *organisational
  administration*. The paid product is the **compliance evidence pack** — Art. 30 records,
  DPIA template, auditor-readable reports, and a **Muster-Betriebsvereinbarung** for §87
  BetrVG works-council approval, which may be worth more to buyers than any feature.
- **Economics:** 50 customers × 15 seats × €7 = €63k/year, which after costs leaves less
  than an employed salary. 150–200 customers is the real target. Stay solo until 80–100.
  Note €1,000/month is below German minimum wage (€13.90/hr from Jan 2026) — that budget
  works only for offshore contractors, who then become third-country subprocessors if they
  have support access.

---

## 14. Still open

1. **Name availability check** — GitHub org, PyPI, npm, domain, trademark
2. **CLA drafted** — before the first outside PR
3. Real-world latency validation against an actual inbox
4. Whether `INSTALL.md` gets a "describes target state, not current build" header until M7

*Resolved:* languages (EN + DE) · attachments (text extraction M1, OCR M7) · false-positive posture · report mode ·
deployment model · OAuth posture · licence · auth design · multi-account · caps and budget ·
decision cache · background pre-scan · write path · retention · destructive masking ·
hosting · profiles · milestones.
