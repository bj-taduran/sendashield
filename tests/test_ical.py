"""Unit tests for sendashield.ical — RFC 5545 structure, one trap at a time.

Each class below corresponds to a numbered trap in the module docstring of
`sendashield/ical.py`. They are all cases where a plausible implementation loses text a
human reader would see, which for this project is a leak rather than a formatting bug.
"""

from __future__ import annotations

import pytest

from sendashield.ical import (
    ParsedCalendar,
    parse_vevents,
    split_content_line,
    unescape_text,
    unfold,
)


def _ics(*lines: str) -> str:
    """Joins lines with `\\n`, matching what normalise_calendar passes in."""
    return "\n".join(lines) + "\n"


class TestUnfolding:
    """Trap 1: folding is structural and must be undone before anything else reads text."""

    def test_space_fold_removes_both_the_newline_and_the_space(self) -> None:
        # RFC 5545 §3.1: "Unfolding is accomplished by removing the CRLF and the linear
        # white-space character that immediately follows." Both go — the space was inserted
        # by the folding, it is not part of the value. This is exactly what lets a fold
        # split an identifier with no visible trace.
        assert unfold("SUMMARY:long\n value") == "SUMMARY:longvalue"

    def test_tab_fold_is_removed(self) -> None:
        assert unfold("SUMMARY:long\n\tvalue") == "SUMMARY:longvalue"

    def test_only_one_whitespace_character_is_consumed(self) -> None:
        # RFC 5545 §3.1: the fold is CRLF plus *one* whitespace character. A second space
        # is part of the value and must survive.
        assert unfold("SUMMARY:a\n  b") == "SUMMARY:a b"

    def test_unfolded_line_break_without_whitespace_is_left_alone(self) -> None:
        assert unfold("SUMMARY:a\nLOCATION:b") == "SUMMARY:a\nLOCATION:b"

    @pytest.mark.leak
    def test_identifier_split_by_a_fold_is_rejoined(self) -> None:
        """A fold mid-identifier is the calendar equivalent of a quoted-printable soft break.

        If unfolding did not happen first, a checksum detector would see two fragments and
        never get a candidate to validate — the IBAN would pass through unmasked while
        rendering to the user as one unbroken string.
        """
        parsed = parse_vevents(
            _ics("BEGIN:VEVENT", "SUMMARY:Zahlung DE8937040044", " 0532013000", "END:VEVENT")
        )
        assert parsed.events[0].summary == "Zahlung DE89370400440532013000"


class TestTextEscapes:
    """Trap 2: escapes must be decoded in a single left-to-right pass."""

    @pytest.mark.parametrize(
        ("escaped", "expected"),
        [
            (r"a\,b", "a,b"),
            (r"a\;b", "a;b"),
            (r"a\\b", "a\\b"),
            (r"a\nb", "a\nb"),
            (r"a\Nb", "a\nb"),
        ],
    )
    def test_each_escape_is_decoded(self, escaped: str, expected: str) -> None:
        assert unescape_text(escaped) == expected

    def test_escaped_backslash_before_n_is_not_a_line_break(self) -> None:
        r"""`\\n` is a literal backslash then the letter n — the case that breaks
        any implementation built from two sequential str.replace calls."""
        assert unescape_text(r"path\\name") == r"path\name"
        assert unescape_text("C:\\\\\\\\n") == "C:\\\\n"

    def test_unknown_escape_is_left_verbatim(self) -> None:
        # Not in the RFC's escape set; dropping the backslash would invent content.
        assert unescape_text(r"50\%") == r"50\%"


class TestContentLineSplitting:
    """Trap 4: a parameter value may contain a colon."""

    def test_simple_line(self) -> None:
        assert split_content_line("SUMMARY:Standup") == ("SUMMARY", "Standup")

    def test_name_is_upper_cased(self) -> None:
        # RFC 5545 §3.1 makes property names case-insensitive.
        assert split_content_line("summary:Standup") == ("SUMMARY", "Standup")

    def test_parameters_are_dropped_from_the_name(self) -> None:
        assert split_content_line("SUMMARY;LANGUAGE=de:Termin") == ("SUMMARY", "Termin")

    def test_quoted_parameter_value_may_contain_a_colon(self) -> None:
        line = 'DESCRIPTION;ALTREP="cid:part1.001@example":real value'
        assert split_content_line(line) == ("DESCRIPTION", "real value")

    def test_value_may_contain_colons(self) -> None:
        assert split_content_line("SUMMARY:12:30 sync") == ("SUMMARY", "12:30 sync")

    def test_line_without_a_colon_is_not_a_content_line(self) -> None:
        assert split_content_line("this is not a content line") is None


class TestComponentNesting:
    """Trap 3: nested components carry their own properties."""

    def test_valarm_description_is_not_the_events(self) -> None:
        parsed = parse_vevents(
            _ics(
                "BEGIN:VEVENT",
                "SUMMARY:Real summary",
                "DESCRIPTION:Real description",
                "BEGIN:VALARM",
                "DESCRIPTION:Reminder text",
                "END:VALARM",
                "END:VEVENT",
            )
        )
        assert parsed.events[0].description == "Real description"
        assert "Reminder" not in parsed.events[0].description

    def test_properties_outside_any_vevent_are_ignored(self) -> None:
        parsed = parse_vevents(
            _ics(
                "BEGIN:VCALENDAR",
                "SUMMARY:calendar-level summary",
                "BEGIN:VEVENT",
                "SUMMARY:event summary",
                "END:VEVENT",
                "END:VCALENDAR",
            )
        )
        assert [event.summary for event in parsed.events] == ["event summary"]

    def test_timezone_component_does_not_produce_an_event(self) -> None:
        parsed = parse_vevents(
            _ics(
                "BEGIN:VCALENDAR",
                "BEGIN:VTIMEZONE",
                "BEGIN:STANDARD",
                "TZNAME:CET",
                "END:STANDARD",
                "END:VTIMEZONE",
                "BEGIN:VEVENT",
                "SUMMARY:Standup",
                "END:VEVENT",
                "END:VCALENDAR",
            )
        )
        assert [event.summary for event in parsed.events] == ["Standup"]


class TestMultipleEvents:
    def test_each_vevent_is_returned_separately_in_document_order(self) -> None:
        parsed = parse_vevents(
            _ics(
                "BEGIN:VEVENT",
                "SUMMARY:First",
                "END:VEVENT",
                "BEGIN:VEVENT",
                "SUMMARY:Second",
                "END:VEVENT",
                "BEGIN:VEVENT",
                "SUMMARY:Third",
                "END:VEVENT",
            )
        )
        assert [event.summary for event in parsed.events] == ["First", "Second", "Third"]

    def test_no_vevent_yields_no_events_and_no_defects(self) -> None:
        # A calendar of VTODOs is well-formed; it simply contains nothing this parses.
        # Refusing it is normalise_calendar's decision to make, not this module's.
        parsed = parse_vevents(_ics("BEGIN:VCALENDAR", "BEGIN:VTODO", "END:VTODO", "END:VCALENDAR"))
        assert parsed == ParsedCalendar(events=(), defects=())


class TestDuplicateProperties:
    """Trap 5: a repeated property is illegal, and dropping it creates a hiding place."""

    def test_every_occurrence_is_kept(self) -> None:
        parsed = parse_vevents(
            _ics("BEGIN:VEVENT", "SUMMARY:Visible", "SUMMARY:Hidden", "END:VEVENT")
        )
        assert parsed.events[0].summary == "Visible\nHidden"

    def test_duplication_is_flagged(self) -> None:
        parsed = parse_vevents(
            _ics("BEGIN:VEVENT", "SUMMARY:Visible", "SUMMARY:Hidden", "END:VEVENT")
        )
        assert "ical_duplicate_property:summary" in parsed.events[0].anomalies

    def test_single_occurrence_is_not_flagged(self) -> None:
        parsed = parse_vevents(_ics("BEGIN:VEVENT", "SUMMARY:Only one", "END:VEVENT"))
        assert parsed.events[0].anomalies == ()


class TestMalformedInput:
    """Structural problems are recorded, not raised — the text is still worth scanning."""

    def test_colonless_line_is_recorded_as_a_defect(self) -> None:
        parsed = parse_vevents(_ics("BEGIN:VEVENT", "garbage line", "END:VEVENT"))
        assert "MalformedContentLine" in parsed.defects

    def test_unterminated_vevent_is_emitted_with_a_defect(self) -> None:
        # Truncated file. The summary is real content and must reach a detector; the defect
        # is what lets the pipeline fail closed on it.
        parsed = parse_vevents(_ics("BEGIN:VEVENT", "SUMMARY:Truncated"))
        assert parsed.events[0].summary == "Truncated"
        assert "UnterminatedVEvent" in parsed.defects

    def test_end_without_begin_is_recorded(self) -> None:
        assert "UnbalancedEnd" in parse_vevents(_ics("END:VEVENT")).defects

    def test_mismatched_end_is_recorded(self) -> None:
        parsed = parse_vevents(_ics("BEGIN:VEVENT", "SUMMARY:x", "END:VTODO"))
        assert "MismatchedEnd" in parsed.defects

    def test_nested_vevent_is_recorded(self) -> None:
        parsed = parse_vevents(
            _ics("BEGIN:VEVENT", "SUMMARY:outer", "BEGIN:VEVENT", "SUMMARY:inner", "END:VEVENT")
        )
        assert "NestedVEvent" in parsed.defects


class TestHtmlAlternativeDescription:
    def test_x_alt_desc_is_flagged_rather_than_silently_ignored(self) -> None:
        """Outlook's HTML description is real content this module does not extract.

        It needs the HTML-to-text path, not the TEXT-unescaping path, so it is out of
        scope — but a payload sitting in it would otherwise be invisible with no trace.
        """
        parsed = parse_vevents(
            _ics(
                "BEGIN:VEVENT",
                "SUMMARY:Invoice",
                "X-ALT-DESC;FMTTYPE=text/html:<p>4242424242424242</p>",
                "END:VEVENT",
            )
        )
        assert "ical_html_alt_description_ignored" in parsed.events[0].anomalies
        assert "4242424242424242" not in parsed.events[0].description
