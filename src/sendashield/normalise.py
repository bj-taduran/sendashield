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
- `invisible_stripped:hidden_css` — **not implemented**. `display:none`, `font-size:0`,
  white-on-white. Hidden text is currently *extracted like any other text* (verified, not
  assumed — see `tests/test_normalise.py::TestHtmlToText`). That is the safe direction for
  L1 (a detector sees it and can mask it) but it is not the control §10 describes, and it
  leaves the §10 example payload — a `font-size:0px` div of instructions — sitting in the
  text as ordinary content. Closing this is a prerequisite for the injection-payload fixture
  batch, not for this one.

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
    "ZERO_WIDTH_CHARS",
    "NormalisationError",
    "NormalisedText",
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


#: Whitespace between two digits, removed before scanning a dropped comment. People group
#: identifiers (`4242 4242 4242 4242`), and a grouped card contains no long digit run.
_INTER_DIGIT_SPACE_RE = re.compile(r"(?<=\d)[^\S\n]+(?=\d)")

#: Identifier-*shaped*, not identifier-validated: an IBAN-like prefix, or any run of 9+
#: digits (the shortest thing this project cares about — a 9-digit SSN — sets the floor).
#: No checksum is applied and none should be; this runs on text that has already been
#: dropped, so its only job is to decide whether the drop deserves to be mentioned.
_COMMENT_IDENTIFIER_RE = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{10,}|\d{9,}", re.IGNORECASE)

#: AI-directed imperatives, per `docs/architecture.md` §10 Control 3 ("ignore previous
#: instructions", "you are now", "do not mention", references to tools or system prompts).
#: Crude and English-only by design — §10 is explicit that this class of matching is "an
#: arms race" and "nothing like checksum-validating a card number". It exists here to stop
#: a payload disappearing without a trace, not to catch every payload; the real injection
#: detector is a separate component and is not this function's job.
_COMMENT_IMPERATIVE_RE = re.compile(
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


#: Assembled per VEVENT as `SUMMARY + sep + LOCATION + sep + DESCRIPTION`, deliberately the
#: same separator mail uses between subject and body. An event's SUMMARY is its subject in
#: every way that matters: for a calendar entry with no body it is the *entire* sensitive
#: payload ("Onkologie Nachsorge"), which is exactly the case `docs/build-plan.md` Phase 1
#: calls out. A missing property contributes an empty string rather than collapsing, so the
#: shape is fixed and offsets stay predictable — an event with no LOCATION reads
#: `"Summary\n\n\n\nDescription"`, mirroring how a message with no Subject begins `"\n\n"`.
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
    4. **Walk components**, collecting SUMMARY / LOCATION / DESCRIPTION per VEVENT and
       decoding TEXT escapes (`sendashield.ical`).
    5. **Strip zero-width characters and normalise to NFC**, identically to mail — the
       evasion works the same way in a calendar summary as in a subject line.

    Raises `NormalisationError` if the object contains no VEVENT at all, or if no event in
    it has any text. Both mean a successful parse produced nothing scannable, which is the
    fail-open this module exists to prevent. An *individual* textless event among others
    that do have text is different — a busy-time block with no title is ordinary, so it is
    returned with an `ical_event_without_text` anomaly rather than taking the file down.

    **Out of scope, deliberately:** ATTENDEE and ORGANIZER, whose `CN=` parameters carry
    real names and addresses. That is `private_person` / L2 territory, and the coordinate
    system above is fixed by the three text properties; widening it later moves every
    calendar fixture offset, so it is a decision to take deliberately rather than by
    accident. `X-ALT-DESC` (Outlook's HTML description) is likewise not extracted, but its
    presence raises an anomaly rather than passing unnoticed.
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
    if not any(event.has_text for event in parsed.events):
        raise NormalisationError(
            f"iCalendar object parsed to {len(parsed.events)} VEVENT(s), none carrying any "
            f"text — the object could not be meaningfully parsed"
        )

    results = []
    for event in parsed.events:
        transforms = [f"charset:{charset_used}", "ical_parsed"]
        anomalies = list(event.anomalies)
        if not event.has_text:
            # Legitimate on its own (an untitled busy block), but indistinguishable from a
            # parse failure without saying so — and this file has other events that did
            # parse, so the parser is evidently working.
            anomalies.append("ical_event_without_text")

        fields = [event.summary, event.location, event.description]
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
    anomalies: tuple[str, ...]


def _html_to_text(html: str) -> _HtmlExtraction:
    extractor = _HTMLTextExtractor()
    extractor.feed(_strip_raw_text_blocks(html))
    extractor.close()
    return _HtmlExtraction(
        text=extractor.get_text(),
        dropped_comments=extractor.dropped_comments,
        # Sorted, not insertion-ordered: two messages differing only in which comment came
        # first must not produce different output. `normalise()` is asserted deterministic
        # in tests/test_normalise.py and this is a tuple compared by that assertion.
        anomalies=tuple(sorted(extractor.comment_anomalies)),
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
        self.dropped_comments = False
        self.comment_anomalies: set[str] = set()

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
        if _COMMENT_IDENTIFIER_RE.search(_INTER_DIGIT_SPACE_RE.sub("", data)):
            self.comment_anomalies.add(_ANOMALY_COMMENT_IDENTIFIER)
        if _COMMENT_IMPERATIVE_RE.search(data):
            self.comment_anomalies.add(_ANOMALY_COMMENT_IMPERATIVE)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._open(tag)

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
        self._chunks.append(data)

    def get_text(self) -> str:
        text = "".join(self._chunks)
        lines = (line.strip() for line in text.splitlines())
        return "\n".join(line for line in lines if line)
