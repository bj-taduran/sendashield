<p align="center">
  <img src="assets/logo/SendaShield_Logo_v0.png" alt="SendaShield — open-source sensitive data protection" width="480">
</p>

# SendaShield

**Sen**sitive **Da**ta **Shield** — a self-hosted privacy filter that sits between your AI
assistant and your mail and calendar.

When you connect Gmail to Claude or ChatGPT, every message the assistant fetches lands raw
in its context window. A request as ordinary as *"triage my unread mail"* can pull bank
statements, medical correspondence, or a lawyer's letter into a third party's system — and
into a chat history you cannot delete.

SendaShield inspects every item before it reaches the assistant, masks or withholds
sensitive content according to a policy you control, and tells you honestly what was held
back.

You run it. Nobody else — including the authors — ever sees your data.

---

## What it does

- **Masks aggressively, withholds cautiously.** Hiding an account number costs you nothing.
  Hiding a whole message might cost you a deadline.
- **Detects by checksum, not guesswork.** Luhn for cards, mod-97 for IBANs, the German
  Steuer-IdNr check digit — near-zero false positives on the identifiers that matter most.
- **Understands whole-message sensitivity.** A letter from your lawyer contains no
  detectable identifier. SendaShield still catches it.
- **Treats calendar as a first-class problem.** An event has no body — the sensitivity is
  in the title and the attendee list. Nobody else handles this.
- **Shows you what it withheld.** In your own dashboard, on your own machine.
- **Neutralises prompt injection.** Email is attacker-controlled text, and assistants treat
  tool results as authoritative.

## What it does not do

**SendaShield reduces what your assistant sees. It does not guarantee that nothing
sensitive gets through.** Automated detection is imperfect: it will miss things, and it
will occasionally withhold something harmless. Treat it as a strong seatbelt, not an
airbag.

It also **cannot stop your assistant using a different tool.** If you leave a native Gmail
connector enabled, the assistant will route around SendaShield and there is no way for us
to detect or prevent that. Disconnecting the direct connector is the only real control.

The honest claim is *SendaShield filters everything that passes through it* — never *it
prevents your assistant from reading sensitive email*.

## Status

Early development. See [`docs/build-plan.md`](docs/build-plan.md) for milestones.
[`INSTALL.md`](INSTALL.md) describes the target state at v1.0, not the current build.

## Getting started

See [`INSTALL.md`](INSTALL.md). Roughly ten minutes for IMAP/CalDAV, twenty-five for Gmail.

Runs on anything from a Raspberry Pi to a €5/month VPS. Free hosting is possible on your
own machine via Tailscale Funnel.

## How it works

SendaShield is an **MCP server**. Your assistant connects to it instead of to Google, so
your assistant never holds provider credentials and never touches raw mail.

```
you → assistant → SendaShield → Gmail / IMAP / CalDAV
                       ↓
                 detect · mask · withhold
                       ↓
                 filtered view + honest count of what was held back
```

Works with claude.ai (web, desktop, mobile), Claude Desktop, and any other MCP client.

Full design in [`docs/architecture.md`](docs/architecture.md); the reasoning behind each
decision is in [`docs/project-brief.md`](docs/project-brief.md).

## Privacy

No telemetry. No analytics, no crash reporting, no version checks. Message bodies are
never written to disk. The audit log records that an item was filtered and its category —
never its content.

Your data goes to your AI provider (filtered) and to your mail provider. There is nowhere
else for it to go.

## Do I have legal obligations?

If you are running this on your own personal mail, **no** — GDPR's household exemption
(Art. 2(2)(c)) covers personal use entirely.

If you are a freelancer or business using it on work mail, you already have obligations as
a controller, and they exist because you hold client correspondence, not because you
installed this. SendaShield *improves* that position: it is a technical measure under
Art. 32, evidence of minimisation under Art. 5(1)(c), and an implementation of privacy by
design under Art. 25.

This is orientation, not legal advice.

## Licence

[AGPL-3.0](LICENSE). Contributions require a CLA — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

Please report vulnerabilities privately. See `SECURITY.md`.
x=1
