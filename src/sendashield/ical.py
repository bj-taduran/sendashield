"""RFC 5545 (iCalendar) parsing — structure only, no detection and no policy.

This module knows the format: how a content line is built, how folding works, how TEXT
values are escaped, and how components nest. It deliberately does **not** know about the
normalised-text coordinate system, spans, or masking — `sendashield.normalise` owns those
and calls this. Keeping the split means the fiddly spec work is testable on its own terms.

**Why hand-rolled rather than a library.** `CLAUDE.md` asks before adding a dependency, and
the dependency tree is part of the threat model. What is needed here is three text
properties out of `VEVENT` components; the parsers on PyPI bring calendar arithmetic,
recurrence expansion and timezone databases with them, all of which would be parsing
attacker-controlled input inside the security boundary. The subset below is small enough
to read in one sitting.

**The traps this module exists to get right**, each of which is a place where a naive
implementation loses text that a human reader would see:

1. **Folding is structural and comes first** (RFC 5545 §3.1). A long line may be split by
   inserting CRLF plus one whitespace character *anywhere*, including mid-word and
   mid-identifier: `SUMMARY:DE8937040044` / `\t0532013000` is one value, and an IBAN split
   that way rejoins into a contiguous run only if unfolding happens before anything else
   looks at the text. This is the same evasion as the quoted-printable soft break in mail.
2. **Escape sequences must be processed in one pass.** `\\n` is an escaped backslash
   followed by a literal `n`, not a newline. Replacing `\n` first and `\\` second turns it
   into a line break; replacing `\\` first and `\n` second is also wrong on other inputs.
   Only a single left-to-right pass is correct.
3. **Nested components have their own properties.** A `VALARM` inside a `VEVENT` carries
   its own `SUMMARY` and `DESCRIPTION` — reminder text, not the event's. Collecting
   properties by name without tracking depth silently mixes them together.
4. **Parameter values may contain colons.** `ALTREP="cid:part1.001"` means the value does
   not start at the first colon on the line. Splitting naively truncates the property name
   and drops the real value on the floor.
5. **Duplicate properties are illegal but occur.** RFC 5545 §3.6.1 permits `SUMMARY` at
   most once per event. Keeping only the first is a hiding place: a second `SUMMARY` would
   render in some clients and be invisible to detection here. Every occurrence is kept and
   an anomaly is raised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "TEXT_PROPERTIES",
    "ParsedCalendar",
    "VEvent",
    "parse_vevents",
    "unfold",
]

#: The three text properties `sendashield.normalise` assembles into an event's coordinate
#: system, in that order. Everything else in a VEVENT is structured data (timestamps,
#: identifiers, recurrence rules) or is out of scope — see the module note in
#: `normalise.normalise_calendar` on ATTENDEE/ORGANIZER.
TEXT_PROPERTIES = ("SUMMARY", "LOCATION", "DESCRIPTION")

#: An HTML alternative to DESCRIPTION, widely emitted by Outlook. It is real content a
#: human reader may see, it is not in `TEXT_PROPERTIES`, and it needs the HTML-to-text
#: path rather than the TEXT unescaping path — so it is out of scope for now, but its
#: presence is reported rather than ignored. See `ANOMALY_HTML_ALT_DESCRIPTION`.
_HTML_ALT_DESCRIPTION = "X-ALT-DESC"

ANOMALY_DUPLICATE_PROPERTY = "ical_duplicate_property"
ANOMALY_HTML_ALT_DESCRIPTION = "ical_html_alt_description_ignored"

#: RFC 5545 §3.1: a CRLF followed by a single space or tab is a fold and both characters
#: are removed. Exactly one whitespace character — a second space belongs to the value.
#: Applied after line endings are normalised to `\n`.
_FOLD_RE = re.compile(r"\n[ \t]")

#: RFC 5545 §3.3.11 TEXT escapes: `\\`, `\;`, `\,`, and `\n`/`\N` for a line break. One
#: alternation applied in a single pass — see trap 2 in the module docstring.
_ESCAPE_RE = re.compile(r"\\([\\;,nN])")


@dataclass(frozen=True)
class VEvent:
    """The text content of one VEVENT. Missing properties are empty strings, never None.

    `anomalies` are labels only, never the matched text — these propagate to
    `NormalisedText.anomalies` and must stay safe to write to the audit log per
    `CLAUDE.md` invariant 5.
    """

    summary: str
    location: str
    description: str
    anomalies: tuple[str, ...] = ()

    @property
    def has_text(self) -> bool:
        return bool((self.summary + self.location + self.description).strip())


@dataclass(frozen=True)
class ParsedCalendar:
    """Every VEVENT found, plus structural problems found while finding them.

    `defects` mirrors `NormalisedText.defects`: the file was malformed, so the text below
    may be partial, and per `CLAUDE.md` invariant 2 the pipeline should quarantine rather
    than trust it. Recorded rather than raised because a malformed calendar still has
    content worth scanning — refusing to look at it would be the leak, not the safeguard.
    """

    events: tuple[VEvent, ...]
    defects: tuple[str, ...] = ()


def unfold(text: str) -> str:
    """Undo RFC 5545 line folding. Must run before any line-oriented parsing.

    Assumes line endings are already normalised to `\\n`.
    """
    return _FOLD_RE.sub("", text)


def unescape_text(value: str) -> str:
    """Decode RFC 5545 §3.3.11 TEXT escapes in a single left-to-right pass.

    Single pass is the whole point: `\\\\n` is a literal backslash followed by `n`, and any
    sequence of two `str.replace` calls gets that wrong in one direction or the other.
    """
    return _ESCAPE_RE.sub(lambda m: "\n" if m.group(1) in "nN" else m.group(1), value)


def split_content_line(line: str) -> tuple[str, str] | None:
    """Split `NAME;PARAM=value:VALUE` into an upper-cased name and its raw value.

    Returns None for a line with no unquoted colon, which is not a content line at all.

    The scan tracks double quotes because a parameter value may contain a colon
    (`ALTREP="cid:part1.001"`), so the first colon on the line is not necessarily the one
    that ends the property name — trap 4 in the module docstring.
    """
    in_quotes = False
    for index, char in enumerate(line):
        if char == '"':
            in_quotes = not in_quotes
        elif char == ":" and not in_quotes:
            name = line[:index].split(";", 1)[0].strip().upper()
            return name, line[index + 1 :]
    return None


def parse_vevents(text: str) -> ParsedCalendar:
    """Extract the text properties of every VEVENT, in document order.

    `text` must already have `\\n` line endings; unfolding is done here, first.

    Properties are collected only when the *innermost* open component is the VEVENT, so a
    nested VALARM's own SUMMARY and DESCRIPTION are not mistaken for the event's (trap 3).
    """
    events: list[VEvent] = []
    defects: list[str] = []
    stack: list[str] = []
    collected: dict[str, list[str]] | None = None
    anomalies: set[str] = set()

    for line in unfold(text).split("\n"):
        if not line.strip():
            continue
        parsed = split_content_line(line)
        if parsed is None:
            defects.append("MalformedContentLine")
            continue
        name, raw_value = parsed

        if name == "BEGIN":
            component = raw_value.strip().upper()
            stack.append(component)
            if component == "VEVENT":
                if collected is not None:
                    # Illegal per RFC 5545 §3.6; the outer event's properties so far would
                    # be lost silently, so say so rather than quietly picking a winner.
                    defects.append("NestedVEvent")
                collected = {}
                anomalies = set()
            continue

        if name == "END":
            component = raw_value.strip().upper()
            if not stack:
                defects.append("UnbalancedEnd")
                continue
            if stack[-1] != component:
                defects.append("MismatchedEnd")
            stack.pop()
            if component == "VEVENT" and collected is not None:
                events.append(_build_event(collected, anomalies))
                collected = None
            continue

        if collected is None or not stack or stack[-1] != "VEVENT":
            continue
        if name in TEXT_PROPERTIES:
            collected.setdefault(name, []).append(unescape_text(raw_value))
        elif name == _HTML_ALT_DESCRIPTION:
            anomalies.add(ANOMALY_HTML_ALT_DESCRIPTION)

    if collected is not None:
        # Truncated file. Emit what was collected — the text is real and a detector should
        # see it — but record the defect so the pipeline can fail closed on it.
        defects.append("UnterminatedVEvent")
        events.append(_build_event(collected, anomalies))

    return ParsedCalendar(events=tuple(events), defects=tuple(defects))


def _build_event(collected: dict[str, list[str]], anomalies: set[str]) -> VEvent:
    """Assemble one VEvent, keeping every occurrence of a duplicated property.

    A repeated SUMMARY is illegal, but dropping the extra would make text that some clients
    render invisible to detection — trap 5. Occurrences are joined with a newline so all of
    it reaches a detector, and the duplication is flagged.
    """
    values: dict[str, str] = {}
    all_anomalies = set(anomalies)
    for prop in TEXT_PROPERTIES:
        occurrences = collected.get(prop, [])
        if len(occurrences) > 1:
            all_anomalies.add(f"{ANOMALY_DUPLICATE_PROPERTY}:{prop.lower()}")
        values[prop] = "\n".join(occurrences)
    return VEvent(
        summary=values["SUMMARY"],
        location=values["LOCATION"],
        description=values["DESCRIPTION"],
        anomalies=tuple(sorted(all_anomalies)),
    )
