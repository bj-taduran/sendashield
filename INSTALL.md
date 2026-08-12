# Installing SendaShield

SendaShield is a privacy filter that sits between your AI assistant and your mail and
calendar. You run it yourself. Nobody else — including the author of this software —
ever sees your data.

**Time required:** ~10 minutes for IMAP/CalDAV, ~25 minutes for Gmail (Google's consent
screen setup is the slow part).

---

## Before you start — please read this

### What SendaShield does and does not promise

SendaShield **reduces** what your assistant sees. It does not **guarantee** that nothing
sensitive gets through. Automated detection is imperfect: it will miss things, and it
will occasionally withhold something harmless. Treat it as a strong seatbelt, not an
airbag.

### The bypass — the single most important step

**If your assistant is still connected directly to Gmail, SendaShield does nothing.**

The assistant will simply use the direct connection and ignore the filtered one. Before
you finish setup you **must** disconnect any native Gmail, Google Calendar, or Outlook
connector in your assistant's settings.

**SendaShield cannot detect this for you.** An MCP server can only see calls made to itself —
it has no visibility into what other connectors your assistant has enabled. There is no
technical control here, and no warning we can raise. It is entirely on you to check.

Step 7 covers how, and Step 8 covers how to verify it worked.

### Choosing your report mode

When SendaShield withholds a message, how much should your assistant be told? This is the one
setting where you are choosing your own risk. Choose it deliberately.

| Mode | Your assistant is told | What you gain | What it costs |
|---|---|---|---|
| `out_of_band` | Nothing | Maximum privacy | **Your assistant may tell you "nothing urgent today" when the urgent item was the withheld one.** It has no way to know it is wrong. |
| `counts_only` **(default)** | "4 items withheld" | Honest answers. The count reveals essentially nothing about which items. | You must open the dashboard to see what was held |
| `in_band` | Sender domain, category, timestamp | Useful triage — you know which withheld item to open first | See below |

**If you choose `in_band`, understand these three effects:**

1. **It accumulates.** One notice is trivial. Running daily for months builds a
   searchable index in your chat history of who your sensitive correspondents are and how
   often they contact you. Repeated health-category notices from one sender reveal a
   pattern of care even though no diagnosis was ever transmitted.
2. **You cannot delete it.** Your dashboard keeps notices for 30 days on your own server.
   Chat history lives under your AI provider's retention policy.
3. **It gives your assistant something to ask for.** Told "a message from your bank was
   flagged for an IBAN," an assistant may helpfully offer: *"paste the relevant line and
   I'll finish the draft."* Specific requests get complied with far more often than vague
   ones. SendaShield instructs the model not to do this, but that instruction is advisory.

`in_band` uses `category_detail: coarse` by default — you see `financial_identifier`
rather than `iban`. Set `fine` only if you have thought about point 1.

### How aggressive is the filter?

SendaShield **masks aggressively and withholds cautiously.**

Masking is cheap — replacing an account number with `[ACCOUNT_1]` costs you nothing, and
your assistant can still read the rest of the message. So SendaShield masks anything it
suspects, even on weak evidence.

Withholding is expensive — a whole message disappears, and if it was the urgent one, you
miss it. So SendaShield only withholds when it is confident.

One consequence worth knowing: **people's names, organisations, and dates are not masked
by default.** Masking them aggressively would make your inbox unreadable to your
assistant — every sender becomes `[PERSON_3]` and you can no longer tell your manager
from a stranger. You can turn them on in the policy screen if you want them.

The **Relaxed / Balanced / Strict** slider moves everything together. Balanced is the
default. Whatever you choose, run the simulation in Step 6 to see what it actually does
to your mail.

### Attachments are not scanned yet

SendaShield cannot currently read inside PDFs, images, scans, or archives. Rather than let
them through unchecked, **any message with an attachment SendaShield cannot inspect is
withheld**, with the reason `attachment_not_scannable`.

This means a message may be withheld even though its text is harmless. That is
deliberate — we would rather hold something back than send a scanned tax assessment to
your assistant without looking at it. Attachment scanning with OCR is planned.

### What SendaShield cannot protect you from

- Anything you paste into the chat yourself
- Your assistant asking you to paste, and you complying
- A compromise of the server you deploy this on
- Your mail provider's own access to your mail

---

## Step 1 — Choose a detection profile

How much memory SendaShield needs depends on which detection layers you run. Pick this
first, because it decides where you can host.

| Profile | Detection | RAM | Catches |
|---|---|---|---|
| **Lite** | L1 only — regex + checksum validators | ~150 MB | Credit cards (Luhn), IBAN (mod-97), German Steuer-IdNr, SSN, API keys and secrets |
| **Standard** | L1 + small NER model | ~700 MB | The above, plus names, addresses, and unusual formats |
| **Full** | L1 + Privacy Filter + topic classifier | 3–4 GB | The above, plus whole-message topic sensitivity (health, legal, employment) |

**Lite is not a toy.** Checksum-validated detection catches the highest-value identifiers
with near-zero false positives. What it cannot do is spot a message that is sensitive
without containing any identifier — a letter from your lawyer, a therapy appointment.
That needs Full.

Set it in `.env`:

```bash
SENDASHIELD_PROFILE=lite    # lite | standard | full
```

---

## Step 2 — Deploy the server

SendaShield needs to be reachable over HTTPS from the public internet, because claude.ai
connects from Anthropic's cloud rather than from your device. That is true even when the
server runs on the laptop in front of you.

> **Prices below were checked in August 2026 and change often** — Hetzner reset prices in
> June 2026, Fly removed its free tier in 2024, Render tightened spin-down. Always check
> the provider's live pricing page. The *shapes* below change far less than the numbers.

| Option | Profile | Cost/month | Best for |
|---|---|---|---|
| **Your own machine + Tailscale Funnel** | Any | **€0** + electricity | First run, and the strongest privacy story |
| **Hetzner CAX11** (2 vCPU ARM, 4 GB) | Any | **~€5** | Always-on, EU-hosted, best value |
| **Hetzner CAX21** (4 vCPU, 8 GB) | Full | ~€8.50 | Headroom |
| **Railway Hobby** | Lite | ~$5 | Zero server admin, git-push deploys |
| **Fly.io** | Lite | ~$2–3 | Same, pay-as-you-go |
| **AWS t4g.medium** | Any | ~$27 | You already live in AWS |
| **Render free tier** | ✗ none | $0 | **Does not work** — see below |

### Why not Render's free tier, Railway, or Fly for Full

Render's free plan gives 512 MB and spins down after 15 minutes idle. The Full profile
will not load, and spin-down breaks background scanning regardless.

Railway and Fly both bill for **actual usage, per second**. That is excellent for bursty
workloads and poor for ours: the Full profile keeps a model resident around the clock, so
there is no idle capacity to save on. Railway's RAM overage runs about $10/GB-month and
Fly's about $5/GB-month, which puts a 4 GB always-on service at roughly $45 and $20
respectively — against €5 on Hetzner for the same specification. Fly also bills attached
volumes and daily snapshots whether or not the machine is running.

For **Lite**, that calculus flips. At ~150 MB with no resident model, Railway Hobby covers
it inside the included credit and you get CI/CD, preview environments and rollbacks for
free. If you want zero server administration, that is a genuinely good trade.

### Option A — Your own machine (recommended for your first run)

Any always-on computer: an old laptop, a NAS, a Raspberry Pi 5. Nothing leaves your home
network except calls to your mail provider and to Anthropic.

```bash
git clone https://github.com/YOUR_USERNAME/sendashield.git
cd sendashield
cp .env.example .env
echo "SENDASHIELD_MASTER_KEY=$(openssl rand -base64 32)" >> .env
docker compose up -d
```

The server is now on `http://localhost:8080`. Step 3 gives it a public HTTPS address.

### Option B — Hetzner (or any VPS)

Create a CAX11, then run exactly the same commands as Option A. Put Caddy in front for
automatic Let's Encrypt certificates:

```
your-domain.example.com {
    reverse_proxy localhost:8080
}
```

SendaShield refuses to start on a public interface without TLS.

### Option C — Railway or Fly (Lite profile)

```bash
# Fly
fly launch --no-deploy
fly secrets set SENDASHIELD_MASTER_KEY=$(openssl rand -base64 32) SENDASHIELD_PROFILE=lite
fly deploy
```

Railway: connect the repository, set the same two variables, deploy. Note the URL you are
given — you will need it twice.

> **Save your `SENDASHIELD_MASTER_KEY`.** It encrypts your stored credentials. Lose it and
> you reconnect every account. It is never transmitted anywhere.

---

## Step 3 — Give your local server a public URL

*Skip this if you deployed to a VPS or PaaS — you already have one.*

Your home machine has no public address, and on most German connections you cannot simply
forward a port: DS-Lite and CGNAT mean your router has no public IPv4 address to forward
from. **Tailscale Funnel** solves this with no domain, no port forwarding, and no cost.

1. **Install Tailscale** on the machine running SendaShield — <https://tailscale.com/download> —
   and sign in with any identity provider. The free Personal plan includes Funnel.

2. **Enable HTTPS certificates.** In the Tailscale admin console, go to **DNS** and turn on
   **HTTPS Certificates**. Note your tailnet name, something like `tail1a2b3.ts.net`.

3. **Expose the port:**

   ```bash
   tailscale funnel 8080
   ```

4. **Copy the URL it prints**, which looks like:

   ```
   https://my-laptop.tail1a2b3.ts.net
   ```

   This is your instance URL. It is stable across restarts, so you configure it once.

**Make it permanent** so it survives reboots:

```bash
tailscale funnel --bg 8080
```

Three things worth knowing:

- **TLS terminates on your machine.** Tailscale relays encrypted bytes and cannot read
  your traffic. The certificate is issued to your node.
- **The machine must be awake.** A sleeping laptop means the connector is down and your
  assistant will say the tools are unavailable. Disable sleep, or use a Pi or NAS.
- **Funnel only serves ports 443, 8443, and 10000** publicly. The command above maps your
  local 8080 to 443, which is what you want.

**Alternatives if you would rather not use Tailscale:** Cloudflare Tunnel gives a stable
URL but its named tunnels need a domain on Cloudflare (~€10/year) — the free
`trycloudflare.com` quick tunnels change address on every restart, which breaks your
connector config. ngrok has the same problem unless you pay for a reserved domain.

---

## Step 4 — Connect your mail and calendar

Open `https://your-sendashield-url/setup` and choose your provider.

### IMAP / CalDAV — the fast path

Works with Fastmail, mailbox.org, Posteo, Proton (via Bridge), Nextcloud, iCloud, and
any self-hosted server. **No cloud console, no OAuth app, no API keys.**

You need: server hostname, port, username, and an **app-specific password** (not your
account password — generate one in your provider's security settings).

Enter them in the setup page. Done. Skip to Step 5.

### Gmail and Google Calendar

Google requires that you register your own OAuth application. This is the tedious part,
and it is also the part that keeps you in control: the credentials are yours, the API
quota is yours, and no third party is in the loop.

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create a new
   project. Name it anything.
2. **APIs & Services → Library** → enable **Gmail API** and **Google Calendar API**.
3. **APIs & Services → OAuth consent screen** → choose **External** → fill in an app
   name, your own email for both support and developer contact fields.
4. On the **Scopes** step, add exactly:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.compose` *(only if you want draft replies)*
   - `https://www.googleapis.com/auth/calendar.readonly`
5. On the **Test users** step, add your own Google account address.
6. **Publish the app to Production.** On the OAuth consent screen page, click **Publish
   app**. This is a UI toggle — no form, no review, no waiting.

   Google may show a dialog saying verification is required for these scopes. **You can
   publish without submitting for verification.** Your app qualifies for Google's
   *Personal Use* exemption: apps used by fewer than 100 people do not need verification.
   Yours has exactly one user — you.

   > **Do not skip this step, and do not leave the app in "Testing".** In Testing status,
   > Google expires your authorization after exactly 7 days and you must reconnect every
   > week. The expiry is tied to Testing status, not to being unverified. Publishing to
   > Production removes it while leaving you fully within Google's policy.

   **Never share your Client ID with another person.** The Personal Use exemption depends
   on your app having under 100 users. If a client ID were shared across many
   installations, it would require full verification and a paid annual security audit.
   One person, one OAuth client.

7. **Credentials → Create Credentials → OAuth client ID** → type **Web application**.
   Under *Authorized redirect URIs* add:
   ```
   https://your-sendashield-url/oauth/google/callback
   ```
8. Copy the **Client ID** and **Client Secret** into the SendaShield setup page and click
   **Connect**.

> **You will see a warning: "Google hasn't verified this app."** This is expected and
> correct — the app is yours, unpublished to any store, and used only by you. Click
> **Advanced → Go to (your app name)**.
>
> Google may occasionally email you about verifying the app. For genuine personal use you
> can ignore this.

### When Google access stops working

Independent of the above, Google revokes access in a few situations. SendaShield will prompt
you to reconnect; it takes about 30 seconds.

- **You changed your Google password.** This revokes Gmail-scoped access immediately.
  The most common cause by far, and it surprises everyone.
- **You didn't use SendaShield for six months.**
- **You revoked access** in your Google Account security settings.

---

## Step 5 — Set your policy

Open `https://your-sendashield-url/policy`.

Start with a preset — **Financial**, **Health**, **Employment**, or **Everything** — then
adjust. Each detector has three settings:

- **Allow** — passes through untouched
- **Mask** — the value is replaced with `[CREDIT_CARD_1]`, the rest of the message still
  reaches your assistant
- **Withhold** — the whole item is held back

Prefer **Mask** where it makes sense. An email with a masked account number is still
useful for triage. Reserve **Withhold** for cases where the sensitivity is the whole
message, not one value in it — a letter from a lawyer, a therapy appointment.

Set your **report mode** here too. Re-read the table at the top of this file first.

---

## Step 6 — Test before you trust it

**Do this before connecting any assistant.** Open `https://your-sendashield-url/simulate`.

SendaShield scans your last 7 days and shows exactly what it *would* have masked or withheld,
with nothing connected and nothing transmitted anywhere.

Look for:

- **Things it missed.** Add a custom rule or raise sensitivity.
- **Things it withheld unnecessarily.** Lower sensitivity, or add a sender exception.

Iterate here until the results look right. Five minutes now is worth more than any
amount of documentation.

---

## Step 7 — Connect your assistant

### claude.ai (web, desktop, or mobile)

1. **Settings → Connectors → Add custom connector**
2. Name: `SendaShield`
3. URL: `https://your-sendashield-url/mcp`
4. Click **Add**, then **Connect**, and sign in with the dashboard credentials you set in
   Step 2.

> Free plans allow one custom connector, which is enough for this.

### ChatGPT, Cursor, or another MCP client

Any client supporting remote MCP works. Point it at `https://your-sendashield-url/mcp`.
See `docs/clients.md` for per-client notes.

### Then — disconnect the direct connectors

Go back to your assistant's connector settings and **remove or disable any native Gmail,
Google Calendar, or Outlook connector.** If you skip this, everything above was
decorative.

Why this matters: your assistant chooses which tool to use based on the tools available
to it. If both SendaShield and a direct Gmail connector are enabled, it will sometimes pick
one and sometimes the other, with no consistent rule you can rely on. Removing the direct
connector is the only way to make the choice for it.

### Add a standing instruction (recommended)

Belt and braces, in case a direct connector gets re-enabled later. In your assistant's
settings, add to your personal preferences or custom instructions:

```
For anything involving my email or calendar, always use the SendaShield tools.
Never use a Gmail, Google Calendar, or Outlook connector directly, even if
one is available. If SendaShield is unavailable, tell me — do not fall back to
another email tool.
```

This is a strong nudge, not a guarantee. Instructions influence the assistant's choice;
they do not constrain it. Disconnecting the direct connector remains the real control.

---

## Step 8 — Verify it works

### Turn on a capture session first

Open `https://your-sendashield-url/capture` and start a session. For the next hour,
SendaShield records the **exact data it sends to your assistant** so you can check it
yourself.

Capture is off by default and expires automatically. Nothing records unless you ask it to,
your assistant cannot switch it on, and captures are deleted when the session ends.


In a new conversation:

```
Using SendaShield, run check_configuration and tell me what it reports.
```

You should see your connected providers, active policy, report mode, and any warnings.

Then try a real query:

```
Review my unread email from the past 24 hours. Classify each as urgent,
informational, or ignore.
```

Compare against `https://your-sendashield-url/capture`, which shows the exact payload sent to
the model on that call. **The two should match.** If the assistant mentions something the
activity log says was withheld, stop and open an issue — that is a bug worth reporting
immediately.

---

## Maintenance

| Task | Frequency |
|---|---|
| Update the container | Monthly (`docker compose pull && docker compose up -d`) |
| Reconnect Google (Testing mode) | Every 7 days, when prompted |
| Review the activity log | Occasionally, to confirm the filter still matches your expectations |
| Re-run simulation after policy changes | Every time |

---

## Troubleshooting

**The assistant says it cannot find the connector.** Your server must be reachable from
the public internet over HTTPS. `localhost` and Tailscale-only addresses will not work
with cloud-hosted assistants.

**The assistant is reading unfiltered email.** A direct provider connector is still
enabled. See Step 7.

**Everything is being withheld.** Your policy is too aggressive, or a detector is
misfiring on a false positive. Check `/simulate` to see which detector is responsible.

**Google keeps asking me to reconnect.** If it is roughly every 7 days, your OAuth app is
still in **Testing** status — go to the Cloud Console OAuth consent screen and click
**Publish app**. If it is occasional, you probably changed your Google password, which
revokes Gmail access.

**Nothing is being withheld.** Verify with a test email to yourself containing a
[test credit card number](https://docs.stripe.com/testing) — SendaShield should mask it.

**I think something leaked.** Start a capture session, reproduce it, and check the recorded
payload. If a sensitive value appears there, it is a filter bug — please report it (see
`SECURITY.md`). If it does not, your assistant read the message through a different
connector; check Step 7.

---

## Privacy

SendaShield sends **no telemetry**. No analytics, no crash reporting, no version checks. The
container's network egress is restricted to your configured providers.

Message and event bodies are never written to disk. The audit log records that an item
was filtered, its category, and a timestamp — never its content.

Your data goes to your AI provider (filtered) and to your mail provider. It goes nowhere
else, and there is nowhere else for it to go.

---

## Getting help

- **Issues:** https://github.com/YOUR_USERNAME/sendashield/issues
- **Security:** see `SECURITY.md` — please report privately, not as a public issue
