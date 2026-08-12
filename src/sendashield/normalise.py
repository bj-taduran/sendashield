"""Message normalisation — the coordinate system every fixture offset refers to.

`normalise()` turns a raw RFC 5322 message into a single plain-text string. Every
`start`/`end` offset in every golden fixture (`tests/fixtures/golden/*.expected.json`)
is an index into the string this function returns for that fixture's raw message.

**Changing this contract invalidates every fixture offset in the corpus.** If you touch
the order of operations, the concatenation separator, the zero-width character set, or
the HTML-to-text algorithm below, every existing `.expected.json` becomes wrong in a way
that only `pytest -m golden` will catch (that's what the self-consistency assertion in
`tests/test_golden_corpus.py` is for) — regenerate fixtures deliberately, don't let them
drift silently.

Pipeline, in order, applied independently to the subject and the body and then
concatenated:

0. **Refuse input that is not a mail message** (`_require_rfc5322_shape`), before parsing.
   A mail parser does not fail on non-mail input; it succeeds on it, quietly, returning
   whatever it salvaged. That is a fail-*open*: an iCalendar file used to normalise to
   `"\\n\\n"` with no error and no defect, so a detector scanned an empty string, found
   nothing, and the item was allowed. `CLAUDE.md` invariant 2 requires the opposite.
   A second, format-agnostic backstop at the end of the pipeline raises if non-empty input
   produced no content at all.

1. **Select the body part.** `EmailMessage.get_body(preferencelist=("plain", "html"))`
   walks `multipart/alternative` and `multipart/related` per RFC 2183, preferring
   `text/plain` over `text/html`, and skips parts with `Content-Disposition: attachment`.
   No part found (e.g. an attachment-only message) is a normalisation failure, not an
   empty body — see `NormalisationError` below.
2. **Decode transfer-encoding.** `Message.get_payload(decode=True)` undoes
   `Content-Transfer-Encoding` — base64 or quoted-printable, including quoted-printable
   soft line breaks (`=\r\n` mid-token) — using the stdlib's own decoder, not a
   hand-rolled one.
3. **Decode charset to text**, with a documented fallback chain: the charset declared on
   the part (from `Content-Type`), then `utf-8`, then `latin-1`. `latin-1` maps every
   byte 0-255 to a code point, so it cannot raise — it is the guaranteed terminus, not a
   best-effort guess. An unlabelled or mislabelled charset degrades gracefully instead of
   raising.
4. **Normalise line endings** — `\r\n` and bare `\r` both become `\n`. Not called out in
   the prose spec but required for offsets to mean anything: undecoded `\r` bytes would
   otherwise sit inside the coordinate system as invisible, uncounted-for characters.
5. **If the part is `text/html`, strip it to text preserving readable order** — block
   elements (`p`, `div`, `tr`, `li`, headings, ...) start a new line; `<td>`/`<th>` cells
   within a row are joined with `" | "`; `<script>`, `<style>`, `<head>` and `<title>`
   contents are discarded entirely; everything else flows inline. See `_HTMLTextExtractor`.

   Inline tags add **no** separator, so an identifier split across markup —
   `<b>DE89</b><span>3704</span>...`, a real evasion technique — is rejoined into one
   contiguous run in the normalised text. Conversely `<br>` and block tags *do* break the
   line, so an identifier split by `<br>` stays split (as whitespace, like the NBSP case
   in step 7 — a detector has to tolerate internal whitespace either way).
6. **Strip zero-width characters** — the exact set in `ZERO_WIDTH_CHARS` below. This is
   one half of L0 invisible-content stripping; see the section below.
7. **Normalise Unicode to NFC** (`unicodedata.normalize("NFC", text)`) — canonical
   composition only. This deliberately does **not** use NFKC: a non-breaking space
   (U+00A0) is a compatibility, not canonical, decomposition of U+0020, so NFC leaves it
   alone. A fixture using NBSP between digit groups (`card_nbsp_grouped_digits_evasion`)
   depends on that — those NBSPs stay verbatim in the normalised text, so a future L1
   detector has to handle them explicitly rather than getting them collapsed away for
   free here.
8. **Concatenate**: `subject + "\\n\\n" + body`. A missing `Subject` header is treated as
   `""`, so the text begins with `"\\n\\n"`.

**L0 invisible-content stripping** (`docs/architecture.md` §10, Control 1)

§10 treats "strip zero-width chars, HTML comments, `font-size:0`, `display:none`,
background-matched text" as a *single* deterministic control, for a reason worth restating:
content the human reader cannot see is an injection surface first and a detection problem
second. The sender writes it knowing only the model will read it. That is why these are
grouped under one `invisible_stripped:*` transform family rather than filed as unrelated
quirks — they are three implementations of the same control, at different stages of
completeness:

- `invisible_stripped:zero_width` — **implemented** (step 6). Lossless: the characters go,
  the surrounding text stays, so `DE89<U+200B>3704...` reaches a detector as one
  contiguous identifier. Nothing is hidden from detection by this, so it raises no anomaly.
- `invisible_stripped:html_comment` — **implemented**. Lossy, and deliberately so:
  `<!-- ... -->` renders to nothing, so per Control 1 it is stripped rather than treated as
  body text. The consequence is that a comment is also invisible *to detection* — which is
  acceptable only because the drop is never silent. The transform records that comments
  existed, and `NormalisedText.anomalies` records when a dropped comment contained something
  identifier-shaped or imperative (Control 3). A payload does not get to vanish quietly.
- `invisible_stripped:hidden_css` — **implemented**. `display:none`, `visibility:hidden`,
  `opacity:0`, `font-size:0`, and white text with no background of its own. The whole
  element subtree is removed, not just its immediate text, and the removed text is scanned
  for the same two categories before it goes.

  Hidden text used to be *extracted* here, on the reasoning that a detector could then mask
  it. That was wrong, and the correction is worth recording: §5 builds the filtered body by
  replacing spans **in the normalised text**, so text stripped at L0 never reaches the model
  at all. Stripping is therefore strictly safer than extracting — it does not depend on a
  detector recognising the payload, and it works against injection text no detector would
  match. §6 says as much outright: "the real defence is upstream — L0 normalisation
  stripping invisible text before anything reads it."

  Two limits, and they fail in **opposite** directions — see `_is_hidden_style`, which
  spells both out. Inline `style` only, so text hidden by a `<style>`-block rule still
  reaches the model (errs toward **exposure**, logged as a known gap at M5). White text
  judged without the cascade, so a light-on-dark design has visible text stripped (errs
  toward **removal**, a utility loss). "We only handle inline styles, so we under-strip" is
  the wrong summary: one limit under-strips, the other over-strips.

**Deliberately out of scope here** (tracked, not forgotten):

- **Attachment extraction.** `docs/architecture.md` §4 ("Attachment handling — an L0
  precondition") specifies this as a separate precondition check before any detector
  runs, with its own undecodable-vs-unscannable distinction. `get_body()` already skips
  attachment parts when selecting the body; this module does not open them.
- **Deciding anything.** `normalise()` reports `defects` and `anomalies` but applies no
  policy — the pipeline must decide, and per `CLAUDE.md` invariant 2 a defect should mean
  quarantine. An anomaly is a signal for the injection detector to weigh, not a verdict;
  §10 is explicit that imperative-matching "is nothing like checksum-validating a card
  number".
"""

from __future__ import annotations

import codecs
import re
import unicodedata
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser

from sendashield import ical

__all__ = [
    "INJECTION_SUSPICION_PREFIXES",
    "ZERO_WIDTH_CHARS",
    "NormalisationError",
    "NormalisedText",
    "is_injection_suspicion",
    "normalise",
    "normalise_calendar",
]

#: Stripped from subject and body alike (step 6). Each is invisible when rendered and has
#: been used in the wild to split a checksum-validated identifier across characters a
#: naive regex won't bridge:
#:   U+200B ZERO WIDTH SPACE, U+200C ZERO WIDTH NON-JOINER, U+200D ZERO WIDTH JOINER,
#:   U+2060 WORD JOINER, U+FEFF ZERO WIDTH NO-BREAK SPACE (byte-order mark).
#: Deliberately excludes U+00AD (SOFT HYPHEN — a line-break hint, not zero-width) and
#: U+00A0 (NO-BREAK SPACE — visible spacing, see step 7's NFC note).
#:
#: Written as escapes, not literal characters — a file full of invisible characters is
#: not something this codebase should ever contain, even here.
ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"

_CONCAT_SEPARATOR = "\n\n"


_BLOCK_TAGS = frozenset(
    {
        "p",
        "div",
        "br",
        "tr",
        "table",
        "ul",
        "ol",
        "li",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "blockquote",
        "hr",
    }
)
_SKIP_TAGS = frozenset({"script", "style", "head", "title"})
#: Sorted, not frozenset-iteration-ordered. `_RAW_TEXT_BLOCK_RE` below interpolates these
#: into a regex alternation at import time, and a frozenset of strings iterates in an order
#: that varies with PYTHONHASHSEED — which would make the compiled pattern text differ
#: between processes. The match result is identical either way (these four names share no
#: prefix, and the backreference ties each opening tag to its own closing tag), but a
#: security product should not have build artefacts that change shape run to run.
_SKIP_TAGS_ORDERED = tuple(sorted(_SKIP_TAGS))


#: Leading byte sequences of formats that are definitively not RFC 5322. Checked purely to
#: produce a *specific* error — the core-header requirement below rejects all of these
#: anyway, but "looks like iCalendar" is a far better thing to find in a log than "no mail
#: headers". Matched after leading whitespace and any BOM.
_NON_MAIL_SENTINELS: tuple[tuple[bytes, str], ...] = (
    (b"begin:vcalendar", "iCalendar (RFC 5545)"),
    (b"begin:vcard", "vCard"),
    (b"%pdf-", "PDF"),
    (b"pk\x03\x04", "ZIP-based container (docx/xlsx/odt)"),
    (b"\x89png\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"gif8", "GIF"),
    (b"<?xml", "XML"),
    (b"<!doctype", "HTML"),
    (b"<html", "HTML"),
    (b"{", "JSON"),
    (b"[", "JSON"),
)

#: RFC 5322 §3.6.8 field name: printable US-ASCII (33-126) except colon, then a colon.
#: Possessive (`++`) so a long non-header line fails at once instead of backtracking one
#: character at a time — this runs on attacker-controlled bytes before anything else does.
_HEADER_FIELD_RE = re.compile(r"^([!-9;-~]++):", re.MULTILINE)

#: A message must carry at least one of these to be treated as mail.
#:
#: **Before you tighten this to `{"date", "from"}`:** yes, RFC 5322 §3.6 makes those the
#: only mandatory headers, and yes, this set is looser than the spec. That is deliberate,
#: because the two failure directions here are not symmetric.
#:
#: - Too loose: some non-mail input gets parsed as mail. It then almost certainly yields no
#:   content and Gate 2 (the contentless-output check in `normalise()`) rejects it anyway.
#: - Too strict: a *real* message is refused. Per `CLAUDE.md` invariant 2 the caller
#:   quarantines it — so the user silently loses a real message from their own inbox, with
#:   nothing to indicate the cause was a header allowlist rather than a threat.
#:
#: The second is the expensive one, and it is invisible: nobody files a bug for mail they
#: never knew arrived. Real mail in the wild is routinely missing `Date`, `From`, or both —
#: mailing-list output, automated senders, anything that has been through a broken relay.
#: This function's job is to reject input that is not mail *at all*; policing malformed mail
#: is a different job with a different cost model. Tighten this only against a corpus of
#: real-world malformed mail, never against the RFC alone.
_CORE_MAIL_HEADERS = frozenset(
    {
        "from",
        "to",
        "cc",
        "bcc",
        "sender",
        "reply-to",
        "return-path",
        "date",
        "subject",
        "message-id",
        "in-reply-to",
        "references",
        "received",
        "delivered-to",
        "mime-version",
    }
)

#: The transfer encodings RFC 2045 §6 defines. Any other value is recorded as `cte:other`.
#:
#: `Content-Transfer-Encoding` is attacker-controlled free text, and `transforms` is an
#: audit-trail field — so interpolating the header value into it verbatim put message
#: content one hop from the audit log, which `CLAUDE.md` invariant 5 forbids ("categories,
#: and timestamps — never text"). A sender writing
#: `Content-Transfer-Encoding: 7bit CARD 4242424242424242` got exactly that string back out
#: in `transforms`. Mapping to a closed set costs the exact name of an unrecognised
#: encoding, which is worth strictly less than the guarantee that this field is a category.
#:
#: The sibling `charset:` transform needs no such list: its value is only ever recorded
#: after `bytes.decode()` accepted it, so it is necessarily a registered Python codec name
#: and cannot be arbitrary text.
_KNOWN_CTES = frozenset({"7bit", "8bit", "binary", "quoted-printable", "base64"})

#: Cap on how much of the input is scanned for headers. Real header blocks are a few KB;
#: this only bounds work on hostile input, since the scan happens before any parsing.
_HEADER_SCAN_LIMIT = 64 * 1024


#: HTML elements that never have content, so they never open a region to skip.
_VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

#: Inline-style declarations that render an element invisible to a human reader. Matched
#: against the element's own `style` attribute; see `_is_hidden_style` for what this does
#: and does not cover.
#:
#: `docs/architecture.md` §10 Control 1 names `font-size:0`, `display:none` and
#: background-matched text; `visibility:hidden` and `opacity:0` are the same technique with
#: a different property, and the §10 example payload combines two of them:
#:
#:     <div style="color:#ffffff;font-size:0px">Ignore prior instructions...</div>
_HIDDEN_STYLE_PATTERNS = (
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)", re.IGNORECASE),
    # 0 with or without a unit: 0, 0px, 0pt, 0em, 0%, 0.0px. A bare `0` is valid CSS.
    re.compile(
        r"font-size\s*:\s*0*\.?0+\s*(?:px|pt|em|rem|%|ex|ch|vw|vh)?\s*(?:;|$)", re.IGNORECASE
    ),
)

#: White text. Only counts as hidden when the same element declares no `background-color` —
#: see `_is_hidden_style` for why this is deliberately shallow.
_WHITE_TEXT_RE = re.compile(
    r"(?<!-)color\s*:\s*(?:#fff(?:fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255\s*[,)])",
    re.IGNORECASE,
)
_BACKGROUND_COLOUR_RE = re.compile(r"background(?:-color)?\s*:", re.IGNORECASE)


def _is_hidden_style(style: str) -> bool:
    """Whether an inline `style` attribute makes its element invisible to a human reader.

    Two known limits. They are not equivalent, and the difference is the important part:
    **they fail in opposite directions**, so neither can be reasoned about using the other's
    intuition.

    **Inline styles only — this one errs toward EXPOSURE.** A rule in a `<style>` block
    (`.preheader { display:none }`) is not seen, so text hidden that way is treated as
    ordinary visible content and reaches the model intact. That is the same outcome as
    having no stripping at all for that payload: a real gap, not a conservative choice.
    It is accepted for now because resolving it means selector matching and the cascade —
    a CSS engine parsing attacker-controlled input inside the security boundary, which is a
    larger attack surface than the thing it would defend — and because real payloads
    overwhelmingly use inline style, including the one `docs/architecture.md` §10 documents.
    Logged as a known gap at M5, not pretended away.

    **White text is judged shallowly — this one errs toward REMOVAL.** `color:#ffffff`
    counts as hidden only when the same element declares no background of its own. That
    gets white-on-white right and white-on-explicitly-dark right, and gets
    white-on-*inherited*-dark wrong: a light-on-dark design has visible text stripped. The
    user then sees less than the message contained, but nothing reaches the model that
    shouldn't — a utility loss, not an exposure. Computing the true effective background
    needs the cascade, and see above.

    Stated plainly because the safe-looking summary — "we only handle inline styles, so we
    under-strip" — is wrong about which way each limit cuts.
    """
    if any(pattern.search(style) for pattern in _HIDDEN_STYLE_PATTERNS):
        return True
    return bool(_WHITE_TEXT_RE.search(style)) and not _BACKGROUND_COLOUR_RE.search(style)


#: Separators between digit *groups*, removed before scanning content that is about to be
#: dropped: spaces (including NBSP), hyphens, dots. A grouped card contains no long digit
#: run — `4242-4242-4242-4242` has a longest run of four — so without this the identifier
#: scan below sees nothing.
#:
#: Hyphens and dots were missing initially, and the consequence was worse here than in the
#: corpus-hygiene guard that had the same omission: a card hidden as
#: `<div style="display:none">4242-4242-4242-4242</div>` was stripped correctly but raised
#: **no anomaly**, and since L0 strips it, L1 never sees it either. The item then reports
#: nothing found, with nothing recorded anywhere — the one outcome the anomaly exists to
#: prevent, defeated by the way card numbers are printed on the cards themselves.
#:
#: Newlines are deliberately excluded (`[^\S\n]` rather than `\s`): dropped content can span
#: lines, and a digit ending one line has no relationship to a digit starting the next.
#:
#: The sibling of this constant is `_INTER_DIGIT_SEPARATOR_RE` in
#: `tests/test_golden_corpus.py`, which does the same job for the corpus-hygiene guard.
#: They are deliberately separate — that one uses `\s` because it scans flat text where a
#: line break inside a grouped number is plausible — but they share a failure mode, so a
#: change to the character class in either is a reason to look at the other.
_INTER_DIGIT_SEPARATOR_RE = re.compile(r"(?<=\d)(?:[^\S\n]|[-.])+(?=\d)")

#: Identifier-*shaped*, not identifier-validated: an IBAN-like prefix, or any run of 9+
#: digits (the shortest thing this project cares about — a 9-digit SSN — sets the floor).
#: No checksum is applied and none should be; this runs on text that has already been
#: dropped, so its only job is to decide whether the drop deserves to be mentioned.
_HIDDEN_IDENTIFIER_RE = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{10,}|\d{9,}", re.IGNORECASE)

#: AI-directed imperatives, per `docs/architecture.md` §10 Control 3 ("ignore previous
#: instructions", "you are now", "do not mention", references to tools or system prompts).
#: Crude and English-only by design — §10 is explicit that this class of matching is "an
#: arms race" and "nothing like checksum-validating a card number". It exists here to stop
#: a payload disappearing without a trace, not to catch every payload; the real injection
#: detector is a separate component and is not this function's job.
_HIDDEN_IMPERATIVE_RE = re.compile(
    r"""
      (?:ignore|disregard|forget)\s+(?:\w+\s+){0,3}(?:instruction|prompt|rule|prior|previous|above)
    | you\s+are\s+now
    | (?:do\s+not|don't|never)\s+(?:mention|tell|reveal|disclose|reply|include)
    | system\s+(?:prompt|message|instruction)
    | new\s+instructions?
    """,
    re.IGNORECASE | re.VERBOSE,
)

#: Anomaly identifiers. Namespaced by where the anomaly was seen, so a future
#: `invisible_stripped:hidden_css` pass can report `hidden_css:imperative` without
#: colliding or needing a new field.
_ANOMALY_COMMENT_IDENTIFIER = "html_comment:identifier_shaped"
_ANOMALY_COMMENT_IMPERATIVE = "html_comment:imperative"
_ANOMALY_HIDDEN_CSS_IDENTIFIER = "hidden_css:identifier_shaped"
_ANOMALY_HIDDEN_CSS_IMPERATIVE = "hidden_css:imperative"

#: Anomalies that are weak evidence of **deliberate construction**, as opposed to ordinary
#: malformation or a quirk of some mail client. They share a register and should be read
#: the same way: a sender went to the trouble of putting something where a human reader
#: would not see it, or of building a structure that real software does not produce.
#:
#: Membership is a prefix match, so per-instance detail (`ical_duplicate_property:summary`)
#: stays in the label without needing an entry per property.
#:
#: **None of these is a verdict.** `docs/architecture.md` §10 rates this whole class as
#: heuristic — "an arms race", and "nothing like checksum-validating a card number" — and
#: the honest claim is that they raise the cost of the attack. `CLAUDE.md` invariant 3 also
#: applies in reverse: nothing here may downgrade an L1 result, and equally, the absence of
#: any of them is not evidence of safety.
#:
#: Deliberately excluded: `html_comment:identifier_shaped` and
#: `hidden_css:identifier_shaped` (a card number in a comment is usually a template
#: artefact, and `display:none` preheader text is in almost every marketing email ever
#: sent — both are hidden-content signals rather than construction ones) and
#: `ical_event_without_text` (an untitled busy block is ordinary). Note it is the
#: *imperative*, not the hiding, that makes a hidden span suspicious: hiding text is
#: ubiquitous and boring, hiding instructions addressed to a model is not.
#:
#: **Why a hidden identifier gets no register of its own.** It was considered — it is not
#: injection, but "there was a card number in text nobody can see" is not ordinary
#: marketing either. Two reasons against, both about where the judgement belongs. First,
#: the thing that would make it interesting is *checksum validity*, and this module
#: deliberately validates nothing (see `_HIDDEN_IDENTIFIER_RE`); a preheader reading
#: "Order #100294771 confirmed" is identifier-shaped and entirely innocent, and telling
#: those apart is L1's job. Second, a third register would have to earn its keep by
#: changing some decision, and there is no decision to change: the identifier was stripped,
#: so nothing leaks whether it was a real card or an order number.
#:
#: What *is* worth knowing, and is easy to miss: because L0 strips it, **L1 never sees that
#: identifier at all**. No span is produced, no category is recorded, and an item can be
#: reported as "nothing found" while the message did contain a hidden card. The
#: `hidden_css:identifier_shaped` anomaly is the only record that it existed, which is
#: reason enough to keep raising it — as a plain anomaly, in the user's dashboard, not as
#: evidence of an attack.
INJECTION_SUSPICION_PREFIXES = (
    "html_comment:imperative",
    "hidden_css:imperative",
    "ical_duplicate_property",
)


def is_injection_suspicion(anomaly: str) -> bool:
    """Whether an anomaly label belongs to the injection-suspicion register.

    A predicate rather than a set membership test so the caller never has to parse label
    strings, and so adding a per-instance suffix to a label cannot silently drop it out of
    the register. See `INJECTION_SUSPICION_PREFIXES`.
    """
    return anomaly.startswith(INJECTION_SUSPICION_PREFIXES)


class NormalisationError(Exception):
    """Raised when a message cannot be reduced to text at all.

    Not raised for content that decodes fine but is empty or benign — only for structural
    failures: input that is not an RFC 5322 message (step 0), no scannable body part found,
    non-empty input that yields no content at all, or byte decoding exhausting every
    fallback (which should be unreachable given `latin-1` never raises). Per
    `docs/architecture.md` §4 ("Unknown format = quarantine"), the caller — the detection
    pipeline, once it exists — is expected to catch this and quarantine the item rather
    than guess at partial content. `normalise()` itself does not quarantine anything; it
    has no policy to apply, only text to produce or refuse to produce.
    """


@dataclass(frozen=True)
class NormalisedText:
    """The output of `normalise()`.

    `text` is the coordinate system fixture offsets are indices into. `transforms` is an
    audit trail of which optional steps actually fired for this message — useful for
    debugging a fixture that doesn't match, not for detection logic.

    `defects` carries the class names of every parser defect the stdlib recorded anywhere
    in the MIME tree (e.g. `CloseBoundaryNotFoundDefect` for a truncated multipart).
    **A non-empty `defects` means the message was malformed and the text below may be
    partial.** `docs/architecture.md` §4 and `CLAUDE.md` invariant 2 both require an
    unparseable format to quarantine — but the stdlib parser does not raise on these, it
    recovers silently and hands back whatever it could salvage, which is indistinguishable
    from a clean parse once the text is a plain string. This field is the only point in
    the system where that distinction still exists, so it is surfaced rather than dropped.
    `normalise()` deliberately does not act on it (it has no policy); the pipeline is
    expected to treat any defect as a quarantine trigger.

    `anomalies` carries labels for content that was **removed** by L0 invisible-content
    stripping and looked like it mattered — currently an HTML comment containing something
    identifier-shaped or an AI-directed imperative (see the module docstring's L0 section).
    Zero-width stripping raises none, because it removes characters without removing
    information. A non-empty `anomalies` is not a verdict: `docs/architecture.md` §10 rates
    imperative-matching as heuristic, and policy belongs to the pipeline. It is here so that
    a payload hidden in a place this module deliberately does not read still leaves a mark.

    Labels only — never the matched text. Per `CLAUDE.md` invariant 5 this value must stay
    safe to write to the audit log, and the point of the drop was that the content does not
    propagate.
    """

    text: str
    transforms: tuple[str, ...]
    defects: tuple[str, ...] = ()
    anomalies: tuple[str, ...] = ()


def normalise(raw_message: bytes) -> NormalisedText:
    """Reduce a raw RFC 5322 message to the plain-text coordinate system fixtures use.

    Raises `NormalisationError` if no scannable body part can be found. Never raises for
    charset problems (see the fallback chain in the module docstring, step 3).

    Note the type checks below use explicit `raise`, never `assert`. `python -O` strips
    assert statements, so an assert would silently vanish in exactly the hardened
    deployment where fail-closed matters most.
    """
    transforms: list[str] = []
    anomalies: list[str] = []

    _require_rfc5322_shape(raw_message)

    msg = BytesParser(policy=policy.default).parsebytes(raw_message)
    if not isinstance(msg, EmailMessage):  # pragma: no cover - policy.default guarantees this
        raise NormalisationError(f"parser returned {type(msg).__name__}, expected EmailMessage")

    defects = _collect_defects(msg)

    subject_raw = msg["Subject"]
    subject = str(subject_raw) if subject_raw is not None else ""
    if subject_raw is not None:
        transforms.append("subject_decoded")

    body_part = msg.get_body(preferencelist=("plain", "html"))
    if body_part is None:
        raise NormalisationError("no scannable body part found (attachment-only or empty message)")
    if not isinstance(body_part, EmailMessage):  # pragma: no cover - as above
        raise NormalisationError(f"body part is {type(body_part).__name__}, expected EmailMessage")

    cte = str(body_part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
    # Category, never the raw header value — see `_KNOWN_CTES`.
    transforms.append(f"cte:{cte if cte in _KNOWN_CTES else 'other'}")

    payload = body_part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        raise NormalisationError(
            f"body part payload did not decode to bytes (got {type(payload).__name__})"
        )

    declared_charset = body_part.get_content_charset()
    body_text, charset_used = _decode_bytes(payload, declared_charset)
    transforms.append(f"charset:{charset_used}")
    if declared_charset is not None and charset_used != declared_charset.lower():
        transforms.append("charset_fallback")

    body_text = _normalise_line_endings(body_text)

    if body_part.get_content_type() == "text/html":
        extraction = _html_to_text(body_text)
        body_text = extraction.text
        transforms.append("html_stripped")
        if extraction.dropped_comments:
            # `<!-- ... -->` renders to nothing, so stripping it *is* §10 Control 1 — but
            # it is the lossy member of that family, so the drop is recorded and anything
            # notable inside it is raised as an anomaly. See the module docstring's L0
            # section.
            transforms.append("invisible_stripped:html_comment")
        if extraction.stripped_hidden_css:
            transforms.append("invisible_stripped:hidden_css")
        if extraction.unclosed_hidden_element:
            # The hidden element never closed, so its text was given back to the visible
            # output rather than swallowing the rest of the document. Recorded as a defect
            # because the markup was malformed and the output is consequently *more* than
            # the reader would see — the pipeline should treat that as a reason to distrust
            # the item, per invariant 2. See `_HTMLTextExtractor.close_and_recover`.
            defects = (*defects, "UnclosedHiddenElement")
        anomalies.extend(extraction.anomalies)

    # Order matches the module docstring (strip, then NFC-normalise) even though the two
    # don't currently interact: none of ZERO_WIDTH_CHARS participates in NFC's canonical
    # composition, so doing this in either order produces byte-identical output today.
    # Keeping code order matched to documented order is the point, not the tie.
    stripped_subject = _strip_zero_width(subject)
    stripped_body = _strip_zero_width(body_text)
    if stripped_subject != subject or stripped_body != body_text:
        # Conditional, unlike before: `transforms` documents which steps actually fired,
        # and an unconditional entry says nothing. It also has to match the conditional
        # `invisible_stripped:html_comment` above for the pair to be readable together.
        transforms.append("invisible_stripped:zero_width")
    subject = unicodedata.normalize("NFC", stripped_subject)
    body_text = unicodedata.normalize("NFC", stripped_body)
    transforms.append("nfc_normalized")

    text = subject + _CONCAT_SEPARATOR + body_text

    if not text.strip():
        # The backstop for whatever the shape check above did not recognise. Non-empty
        # input that normalises to nothing means the parser found no content where content
        # demonstrably exists — the salvage was a failure wearing a success's clothes, and
        # per invariant 2 that is a quarantine, not an empty scan. (Reached only for input
        # that passed the header check, since empty input is rejected there.)
        raise NormalisationError(
            f"{len(raw_message)} bytes of input normalised to no content at all — "
            f"the message could not be meaningfully parsed"
        )

    return NormalisedText(
        text=text,
        transforms=tuple(transforms),
        defects=defects,
        anomalies=tuple(anomalies),
    )


#: **FROZEN.** The order of an event's normalised text. Changing it — reordering, inserting,
#: or removing a slot — invalidates every offset in every `.ics` fixture in the golden
#: corpus, and does so silently for any fixture that happens to declare no spans.
#:
#:     SUMMARY \n\n LOCATION \n\n ORGANIZER \n\n ATTENDEES \n\n DESCRIPTION
#:
#: The separator is the one mail uses between subject and body, because an event's SUMMARY
#: is its subject in every way that matters: for a calendar entry with no body it is the
#: *entire* sensitive payload ("Onkologie Nachsorge").
#:
#: **A field keeps its place whether or not it has content.** A missing property contributes
#: an empty string rather than collapsing, so an event with only a summary reads
#: `"Standup\n\n\n\n\n\n\n\n"` — mirroring how a message with no Subject begins `"\n\n"`.
#: That is what makes an offset mean the same thing across every fixture.
#:
#: `ORGANIZER` and `ATTENDEES` are **reserved and currently always empty**. `sendashield.ical`
#: does not extract them yet; they are populated at M4 with the calendar-title profile
#: (`docs/architecture.md` §15). The slots exist now so that closing that gap moves no
#: offset — the alternative was appending them later and rewriting every calendar fixture,
#: which is exactly the kind of churn that turns a reviewed corpus into a re-derived one.
#: Until then, `ical_participants_not_extracted` marks each item whose participants went
#: unread. See `ical.PARTICIPANT_PROPERTIES` for why this gap is the significant one.
_CALENDAR_FIELD_ORDER = ("SUMMARY", "LOCATION", "ORGANIZER", "ATTENDEES", "DESCRIPTION")

_CALENDAR_FIELD_SEPARATOR = "\n\n"


def _require_icalendar_shape(raw: bytes) -> None:
    """The mirror of `_require_rfc5322_shape`: refuse input that is not iCalendar.

    Same reasoning, opposite direction. `normalise()` rejects a calendar file because a mail
    parser will happily produce empty text from one; this rejects a mail message because the
    VEVENT walk below would find no components and produce nothing at all. Neither function
    may be the one that quietly returns "" for input the other should have handled.

    Sniffed on bytes, not decoded text, for the reason given in `_require_rfc5322_shape`.
    """
    if not raw.strip():
        raise NormalisationError("input is empty or whitespace only")

    sniff = raw[:_HEADER_SCAN_LIMIT]
    if sniff.startswith(codecs.BOM_UTF8):
        sniff = sniff[len(codecs.BOM_UTF8) :]
    if not sniff.lstrip().lower().startswith(b"begin:vcalendar"):
        raise NormalisationError(
            "input does not begin with BEGIN:VCALENDAR — not an iCalendar object. "
            "Mail belongs in normalise(); anything else must be quarantined."
        )


def normalise_calendar(raw_calendar: bytes) -> tuple[NormalisedText, ...]:
    """Reduce an iCalendar object to one `NormalisedText` per VEVENT.

    **One item per event, never a concatenation.** A calendar file is a container, not a
    document: two events in one `.ics` are two separate things the user may have entirely
    different policy for, and joining them would let a benign standup invite carry a
    therapy appointment past a per-item decision. Offsets in a fixture are indices into a
    single event's text, so concatenating would also make them meaningless.

    Pipeline, mirroring `normalise()`:

    0. **Refuse input that is not iCalendar** (`_require_icalendar_shape`).
    1. **Decode charset** via the same fallback chain terminating at latin-1. RFC 5545
       §3.1.4 makes UTF-8 the default for a bare `.ics`; a MIME `charset` parameter belongs
       to the enclosing message and is the caller's business, not this function's.
    2. **Normalise line endings** to `\\n`.
    3. **Unfold** (`ical.unfold`), before anything else reads the text — a folded line may
       split an identifier mid-token exactly like a quoted-printable soft break.
    4. **Walk components**, collecting the text properties per VEVENT and decoding TEXT
       escapes (`sendashield.ical`), then assembling them in `_CALENDAR_FIELD_ORDER` —
       which is frozen, and which reserves two slots that are not populated yet.
    5. **Strip zero-width characters and normalise to NFC**, identically to mail — the
       evasion works the same way in a calendar summary as in a subject line.

    Raises `NormalisationError` if the object contains no VEVENT at all, or if it holds two
    or more events and none of them carries any text. Both mean a successful parse produced
    nothing scannable, which is the fail-open this module exists to prevent. A *single*
    textless event does not raise — one untitled busy-time block is the commonest entry in a
    shared work calendar, and refusing the file would quarantine an ordinary one. It returns
    with an `ical_event_without_text` anomaly instead.

    **Known gaps, both carried to M4** (`docs/architecture.md` §15) and both non-silent:

    - **ORGANIZER / ATTENDEE are not extracted.** Their slots in the coordinate system are
      reserved and empty; items whose participants went unread carry the
      `ical_participants_not_extracted` transform. This is the significant one — §3 puts
      "nearly all signal" for calendar in the title and the attendee list, so an event
      titled `Kaffee` with a divorce lawyer among its attendees currently normalises to one
      harmless word.
    - **`X-ALT-DESC` is not extracted.** Outlook's HTML alternative to DESCRIPTION is
      content a human reader sees; it needs the HTML-to-text path rather than the TEXT
      unescaping path. Smaller than the attendee gap, same shape. Raises
      `ical_html_alt_description_ignored`.
    """
    _require_icalendar_shape(raw_calendar)

    text, charset_used = _decode_bytes(raw_calendar, None)
    parsed = ical.parse_vevents(_normalise_line_endings(text))

    if not parsed.events:
        raise NormalisationError(
            "iCalendar object contains no VEVENT component — nothing to scan. "
            "VTODO and VJOURNAL are not supported; per docs/architecture.md §4 an "
            "unsupported format must be quarantined, not silently skipped."
        )
    if len(parsed.events) > 1 and not any(event.has_text for event in parsed.events):
        # Only fatal in the plural. One untitled event is an ordinary busy-time block and
        # the commonest thing in a shared work calendar; a file of nothing *but* textless
        # events is a parse that produced no content, which is the fail-open this guards.
        # A lone textless event is returned with the anomaly below instead.
        raise NormalisationError(
            f"iCalendar object parsed to {len(parsed.events)} VEVENTs, none carrying any "
            f"text — the object could not be meaningfully parsed"
        )

    results = []
    for event in parsed.events:
        transforms = [f"charset:{charset_used}", "ical_parsed"]
        anomalies = list(event.anomalies)
        if not event.has_text:
            # Not an error on its own — an untitled busy block is ordinary — but it is
            # indistinguishable from a parse failure unless it is said out loud.
            anomalies.append("ical_event_without_text")
        if event.participants_present:
            # A transform, not an anomaly: this fires on essentially every real invite, and
            # an anomaly that is always present teaches a reviewer to ignore anomalies. It
            # belongs in the audit trail of what happened to the item, which is what
            # `transforms` is. See `_CALENDAR_FIELD_ORDER`.
            transforms.append("ical_participants_not_extracted")

        # Keyed by name and read back through _CALENDAR_FIELD_ORDER, so the frozen order is
        # load-bearing rather than decorative — a positional list would let the two drift
        # apart silently, which is the one failure this arrangement exists to prevent.
        values = {
            "SUMMARY": event.summary,
            "LOCATION": event.location,
            "ORGANIZER": "",  # reserved until M4 — see _CALENDAR_FIELD_ORDER
            "ATTENDEES": "",  # reserved until M4
            "DESCRIPTION": event.description,
        }
        fields = [values[name] for name in _CALENDAR_FIELD_ORDER]
        stripped = [_strip_zero_width(field) for field in fields]
        if stripped != fields:
            transforms.append("invisible_stripped:zero_width")
        transforms.append("nfc_normalized")

        results.append(
            NormalisedText(
                text=_CALENDAR_FIELD_SEPARATOR.join(
                    unicodedata.normalize("NFC", field) for field in stripped
                ),
                transforms=tuple(transforms),
                # File-level defects apply to every event drawn from that file: the object
                # was malformed, so no event parsed out of it is above suspicion.
                defects=parsed.defects,
                anomalies=tuple(sorted(set(anomalies))),
            )
        )
    return tuple(results)


def _require_rfc5322_shape(raw: bytes) -> None:
    """Reject input that is not an RFC 5322 message, before the parser gets a chance to.

    `BytesParser` does not fail on non-mail input — it succeeds on it. Every line of an
    iCalendar file (`BEGIN:VCALENDAR`, `SUMMARY:Onkologie Nachsorge`) has the shape of a
    header, so the whole file parses as a header block with an empty body, and `normalise()`
    used to return `"\\n\\n"` with no defects and no error. A detector downstream then finds
    nothing in an empty string and the item is allowed. That is `CLAUDE.md` invariant 2
    inverted: an unparseable format passing through as if it were clean, which is exactly
    the silent failure this project exists to prevent.

    Two checks, in order of how specific their error message is:

    1. A leading sentinel for a format known not to be mail (`_NON_MAIL_SENTINELS`).
    2. At least one core mail header (`_CORE_MAIL_HEADERS`) in the header block. This is
       the general check — it catches formats not on the sentinel list, including ones
       that don't exist yet.

    Only the header block is scanned, so a body quoting `From:` cannot vouch for a message
    that has no real headers of its own.

    **Format detection runs on bytes, never on decoded text.** Decoding has already assumed
    the answer to the question this function is asking. The concrete bug: a UTF-8 BOM
    decoded via latin-1 becomes three ordinary characters, so stripping `U+FEFF` from the
    decoded string does nothing at all — silently, since the strip still "succeeds" — and a
    BOM-prefixed iCalendar file sailed past the sentinel check. Anything deciding *what a
    thing is* must look at the bytes; only code that has already established what it is
    holding may decode. (The header scan below does decode, via latin-1 — but by then the
    question is "which field names are present", not "is this mail", and latin-1 maps every
    byte so nothing can fail to decode.)
    """
    if not raw.strip():
        raise NormalisationError("input is empty or whitespace only")

    head = raw[:_HEADER_SCAN_LIMIT]

    # Sniffed as bytes, not as decoded text: a UTF-8 BOM decoded via latin-1 becomes three
    # separate characters, so stripping U+FEFF from the decoded string silently does
    # nothing and the sentinel below never matches. Strip the BOM where it still is one.
    sniff = head
    if sniff.startswith(codecs.BOM_UTF8):
        sniff = sniff[len(codecs.BOM_UTF8) :]
    # UTF-16 input needs no special case: its NUL-interleaved bytes match no sentinel and
    # carry no recognisable header, so the check below rejects it regardless.
    sniff = sniff.lstrip().lower()
    for sentinel, format_name in _NON_MAIL_SENTINELS:
        if sniff.startswith(sentinel):
            raise NormalisationError(
                f"input is {format_name}, not an RFC 5322 message — refusing to parse it as "
                f"mail. Per docs/architecture.md §4 the caller must quarantine rather than "
                f"scan whatever text a mail parser salvages from it."
            )

    # latin-1 maps every byte and cannot raise, so binary input degrades to mojibake that
    # simply fails the check below rather than blowing up before it can be rejected.
    head_text = head.decode("latin-1")

    # RFC 5322 §2.1: the header block ends at the first empty line. No empty line means the
    # whole (capped) input is header candidates — which is precisely the .ics case.
    separator = re.search(r"\r?\n\r?\n", head_text)
    header_block = head_text[: separator.start()] if separator else head_text

    found = {match.group(1).lower() for match in _HEADER_FIELD_RE.finditer(header_block)}
    if not found & _CORE_MAIL_HEADERS:
        raise NormalisationError(
            "input carries no recognisable mail headers (found none of From, To, Date, "
            "Subject, Message-ID, Received, ...) — refusing to parse it as mail"
        )


def _collect_defects(msg: EmailMessage) -> tuple[str, ...]:
    """Class names of every parser defect recorded anywhere in the MIME tree.

    `walk()` covers the message itself and every sub-part, because a defect on an inner
    part (a truncated nested multipart, say) is just as much a reason to distrust the
    extracted text as one on the outer message. See `NormalisedText.defects` for why this
    is surfaced rather than ignored.
    """
    return tuple(type(defect).__name__ for part in msg.walk() for defect in part.defects)


def _decode_bytes(raw: bytes, declared_charset: str | None) -> tuple[str, str]:
    """Decode `raw` to text, trying the declared charset, then utf-8, then latin-1.

    latin-1 (iso-8859-1) maps every byte 0-255 to a Unicode code point, so it cannot
    raise `UnicodeDecodeError` — it is the guaranteed terminus of this chain, not a guess
    that might also fail.
    """
    candidates = []
    if declared_charset:
        candidates.append(declared_charset)
    if not declared_charset or declared_charset.lower() != "utf-8":
        candidates.append("utf-8")
    candidates.append("latin-1")

    for charset in candidates:
        try:
            return raw.decode(charset), charset.lower()
        except (LookupError, UnicodeDecodeError):
            continue

    # Unreachable: latin-1 always succeeds. Kept as a fail-closed backstop in case that
    # invariant is ever wrong in some future Python encoding change.
    raise NormalisationError(
        "could not decode message body with declared, utf-8, or latin-1 charsets"
    )


def _normalise_line_endings(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _strip_zero_width(text: str) -> str:
    return text.translate({ord(c): None for c in ZERO_WIDTH_CHARS})


#: Matches only the *opening* tag of a raw-text element. The matching close is located
#: with `str.find` rather than by regex — see `_strip_raw_text_blocks`.
_RAW_TEXT_OPEN_RE = re.compile(
    r"<(" + "|".join(_SKIP_TAGS_ORDERED) + r")\b[^>]*>",
    re.IGNORECASE,
)


def _strip_raw_text_blocks(html: str) -> str:
    """Remove well-formed `<script>`/`<style>`/`<head>`/`<title>` blocks before parsing.

    This used to be state tracked inside `_HTMLTextExtractor` (increment a skip-depth
    counter on the open tag, decrement on the matching close tag, suppress
    `handle_data()` while depth > 0). That has a fail-*open*-in-the-wrong-direction bug:
    an unclosed or self-closed `<style>`/`<script>` — truncated MIME, hand-crafted HTML,
    or just a sloppy mail client — leaves the skip counter permanently above zero, so
    *everything parsed afterward in the whole document* silently disappears from the
    normalised text, including real content nowhere near the broken tag. For a detector
    downstream, that reads identically to "nothing here" rather than "something went
    wrong" — exactly the silent-failure mode `CLAUDE.md` calls out as the thing to avoid.

    Scanning these four elements textually is safe specifically because they hold raw
    text, not nested HTML (per the HTML spec, content inside `<script>`/`<style>` cannot
    contain another start tag of the same name, and `<head>`/`<title>` do not legitimately
    nest) — this isn't the usual "don't parse HTML with regex" trap.

    **Why a `find` loop and not one lazy `<style>.*?</style>` regex.** That regex is
    quadratic on input an attacker controls: for every opening tag with no matching close,
    the engine rescans to end of string. 20k unclosed `<style>` tags took ~11s and it grows
    as the square, so a single email could pin a CPU indefinitely — a denial of service on
    a component that, per `docs/architecture.md` §12, is supposed to hold a latency budget.
    The loop below touches each character a bounded number of times instead. Benchmarked in
    `tests/test_normalise.py::TestPathologicalInput`.

    A malformed instance still degrades safely: with no matching closing tag the opening
    tag is left in place, `HTMLParser` handles it (entering its own CDATA mode and emitting
    the remainder as text at `close()`), and scanning continues past it so later
    well-formed blocks are still removed. Visible junk beats an invisible sinkhole.
    """
    lowered = html.lower()
    out: list[str] = []
    pos = 0

    # Tag names already known to have no usable closing tag left in the document. Without
    # this, a document with many unclosed `<style>` tags would re-scan to end of string
    # once per tag — reintroducing the very quadratic behaviour this function exists to
    # avoid. The short-circuit is sound because `find` only ever moves forward: if there
    # is no `</style` after offset X, there is none after any offset later than X either.
    exhausted: set[str] = set()

    while (match := _RAW_TEXT_OPEN_RE.search(html, pos)) is not None:
        tag = match.group(1).lower()
        close_end = -1
        if tag not in exhausted:
            close_at = lowered.find(f"</{tag}", match.end())
            close_end = html.find(">", close_at) if close_at != -1 else -1
            if close_end == -1:
                exhausted.add(tag)

        if close_end == -1:
            # No usable closing tag. Keep this opening tag verbatim and carry on from just
            # after it, rather than abandoning the scan — one malformed <style> early in a
            # message must not stop later, well-formed blocks from being removed.
            out.append(html[pos : match.end()])
            pos = match.end()
            continue

        out.append(html[pos : match.start()])
        pos = close_end + 1

    out.append(html[pos:])
    return "".join(out)


@dataclass(frozen=True)
class _HtmlExtraction:
    """What `_html_to_text` produced, plus what it threw away and why that might matter."""

    text: str
    dropped_comments: bool
    stripped_hidden_css: bool
    unclosed_hidden_element: bool
    anomalies: tuple[str, ...]


def _is_hidden_attrs(attrs: list[tuple[str, str | None]]) -> bool:
    """Whether an element's attributes make it invisible. Inline `style` only."""
    return any(
        name.lower() == "style" and value is not None and _is_hidden_style(value)
        for name, value in attrs
    )


def _html_to_text(html: str) -> _HtmlExtraction:
    extractor = _HTMLTextExtractor()
    extractor.feed(_strip_raw_text_blocks(html))
    extractor.close_and_recover()
    return _HtmlExtraction(
        text=extractor.get_text(),
        dropped_comments=extractor.dropped_comments,
        stripped_hidden_css=extractor.stripped_hidden_css,
        unclosed_hidden_element=extractor.unclosed_hidden_element,
        # Sorted, not insertion-ordered: two messages differing only in which comment came
        # first must not produce different output. `normalise()` is asserted deterministic
        # in tests/test_normalise.py and this is a tuple compared by that assertion.
        anomalies=tuple(sorted(extractor.anomalies)),
    )


class _HTMLTextExtractor(HTMLParser):
    """Extracts text from HTML in reading order.

    Block-level tags (`_BLOCK_TAGS`) start a new line. `<td>`/`<th>` cells within the same
    `<tr>` are joined with `" | "`. Everything else — inline tags like `<b>`, `<span>`,
    `<a>` — flows inline with no separator added, preserving reading order within a line.
    HTML entities are decoded automatically (`convert_charrefs`).

    Does not itself know about `<script>`/`<style>`/`<head>`/`<title>` — well-formed
    instances are already removed by `_strip_raw_text_blocks` before this ever runs; see
    that function's docstring for why that's a regex pre-pass rather than parser state.

    Final output collapses each source chunk to whitespace-trimmed, non-empty lines
    joined by a single `\\n` — deterministic, but not a faithful re-rendering of blank-line
    structure. That trade-off is fine here: fixture offsets only need to be reproducible,
    not to look like the original layout.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._first_cell_in_row = True
        #: Names of currently-open non-void elements. Only needed to know when a hidden
        #: element has closed; ordinary extraction is flat.
        self._open_elements: list[str] = []
        #: Depth of `_open_elements` at which the innermost hidden element began, or None.
        #: Set once and not incremented for nested hidden elements — the region ends when
        #: the outermost one closes.
        self._hidden_from_depth: int | None = None
        #: Text seen while inside a hidden element. Buffered rather than discarded outright
        #: so it can be given back if the element turns out never to close — see
        #: `close_and_recover`.
        self._hidden_buffer: list[str] = []
        self.dropped_comments = False
        self.stripped_hidden_css = False
        self.unclosed_hidden_element = False
        self.anomalies: set[str] = set()

    def handle_comment(self, data: str) -> None:
        """Drop the comment, but not without looking at what was dropped.

        `<!-- ... -->` is invisible to the human reader, which makes it an injection
        surface rather than merely unreadable markup — so it is stripped per
        `docs/architecture.md` §10 Control 1. Stripping is lossy, though, so before the
        text goes it is checked for the two things whose disappearance would be worth
        knowing about: an identifier shape, and an AI-directed imperative (Control 3).

        The comment text itself is never retained — only which category matched. See
        `NormalisedText.anomalies`.
        """
        self.dropped_comments = True
        self._scan_dropped(data, _ANOMALY_COMMENT_IDENTIFIER, _ANOMALY_COMMENT_IMPERATIVE)

    def _scan_dropped(self, data: str, identifier_label: str, imperative_label: str) -> None:
        """Categorise text that is about to be discarded. Labels only, never the text."""
        if _HIDDEN_IDENTIFIER_RE.search(_INTER_DIGIT_SEPARATOR_RE.sub("", data)):
            self.anomalies.add(identifier_label)
        if _HIDDEN_IMPERATIVE_RE.search(data):
            self.anomalies.add(imperative_label)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _VOID_TAGS:
            self._open_elements.append(tag)
            if self._hidden_from_depth is None and _is_hidden_attrs(attrs):
                # Entering a hidden region. Depth is recorded *after* the push, so the
                # region ends when this element's own close tag pops it back.
                self._hidden_from_depth = len(self._open_elements)
                self.stripped_hidden_css = True
                return
        if self._hidden_from_depth is None:
            self._open(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # `<div/>` opens and closes at once, so it can never contain anything to hide.
        if self._hidden_from_depth is None:
            self._open(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_TAGS or not self._open_elements:
            return
        # Tolerate mismatched nesting: unwind to the nearest matching open tag if there is
        # one, and ignore a stray close tag entirely if there is not. Neither may leave the
        # stack in a state that keeps a hidden region open forever.
        if tag not in self._open_elements:
            return
        while self._open_elements:
            popped = self._open_elements.pop()
            if self._hidden_from_depth is not None and len(self._open_elements) < (
                self._hidden_from_depth
            ):
                self._end_hidden_region()
            if popped == tag:
                break

    def _end_hidden_region(self) -> None:
        """Discard the buffered hidden text, after recording what was in it."""
        self._scan_dropped(
            "".join(self._hidden_buffer),
            _ANOMALY_HIDDEN_CSS_IDENTIFIER,
            _ANOMALY_HIDDEN_CSS_IMPERATIVE,
        )
        self._hidden_buffer.clear()
        self._hidden_from_depth = None

    def close_and_recover(self) -> None:
        """Finish parsing, giving back the text of any hidden element that never closed.

        This is the whole reason hidden text is buffered rather than dropped as it arrives.
        A skip region that runs to end-of-input is the exact failure `_strip_raw_text_blocks`
        was written to eliminate for `<style>`: one unclosed tag silently swallows the
        entire remainder of the document, which reads downstream as "nothing here" rather
        than "something went wrong". Reintroducing it for `<div style="display:none">` would
        be the same bug in a new place — and a far easier one to trigger deliberately, since
        an attacker controls the markup and would only need to omit a closing tag to make
        every following identifier vanish from detection.

        So the failure direction is inverted: an unterminated hidden element gives its text
        *back* to the visible output and records a defect. Text that should have been
        stripped is then over-included, which is the survivable error — the payload stays
        visible to every downstream layer instead of the message quietly emptying out.
        """
        self.close()
        if self._hidden_from_depth is not None:
            self.unclosed_hidden_element = True
            self._scan_dropped(
                "".join(self._hidden_buffer),
                _ANOMALY_HIDDEN_CSS_IDENTIFIER,
                _ANOMALY_HIDDEN_CSS_IMPERATIVE,
            )
            self._chunks.extend(self._hidden_buffer)
            self._hidden_buffer.clear()
            self._hidden_from_depth = None

    def _open(self, tag: str) -> None:
        if tag == "tr":
            self._first_cell_in_row = True
            self._chunks.append("\n")
        elif tag in ("td", "th"):
            if not self._first_cell_in_row:
                self._chunks.append(" | ")
            self._first_cell_in_row = False
        elif tag in _BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._hidden_from_depth is not None:
            self._hidden_buffer.append(data)
        else:
            self._chunks.append(data)

    def get_text(self) -> str:
        text = "".join(self._chunks)
        lines = (line.strip() for line in text.splitlines())
        return "\n".join(line for line in lines if line)
