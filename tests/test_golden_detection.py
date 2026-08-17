"""Implemented detectors, run against the whole golden corpus.

`test_golden_corpus.py` checks that fixtures agree with themselves. This file checks that
detectors agree with the fixtures — the Phase 2 gate in `docs/build-plan.md`: "100% of
golden corpus cases for implemented detectors pass, plus property tests, plus zero firings
on the benign fixtures."

Every fixture is run, not only the ones declaring a span for the detector under test. The
cases that declare *nothing* are the ones that catch over-masking, and they are the
majority: an IBAN fixture, a near-miss, a benign newsletter and an injection payload must
all come back empty from `credit_card`. Restricting the sweep to fixtures that expect a hit
would leave exactly the false-positive failures untested.

`DETECTORS` is keyed by `DETECTOR_ID`, so adding `iban` here is one line and the whole
corpus is swept for it automatically.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from sendashield.detect.l1 import credit_card, iban
from sendashield.model import DetectorConfig, Span
from test_golden_corpus import CASES, _normalise_fixture, _raw_fixture_path, load_expected

#: Every L1 detector that exists, keyed by its `DETECTOR_ID`. Detectors not listed here have
#: their fixture spans ignored — `test_every_declared_detector_is_either_implemented_or_known`
#: is what stops that being silent.
DETECTORS: dict[str, Callable[[str, DetectorConfig], list[Span]]] = {
    credit_card.DETECTOR_ID: credit_card.detect,
    iban.DETECTOR_ID: iban.detect,
}

#: Detectors the corpus declares spans for that are not built yet (`docs/build-plan.md`
#: Phase 2 order). Listed explicitly so that finishing one and forgetting to register it
#: above fails here instead of quietly leaving its fixtures unchecked.
NOT_YET_IMPLEMENTED = frozenset({"steuer_idnr", "secret", "ssn", "versicherungsnummer"})

CONFIG = DetectorConfig()


def _expected_spans(expected: dict[str, object], detector_id: str) -> list[tuple[int, int, str]]:
    spans = expected["expected_spans"]
    assert isinstance(spans, list)
    return sorted(
        (span["start"], span["end"], span["text"])
        for span in spans
        if span["detector"] == detector_id
    )


@pytest.mark.golden
@pytest.mark.parametrize(
    "expected_path", CASES, ids=lambda p: p.name.removesuffix(".expected.json")
)
@pytest.mark.parametrize("detector_id", sorted(DETECTORS))
def test_detector_output_matches_the_corpus(detector_id: str, expected_path: Path) -> None:
    """Exact equality, in both directions.

    A missed card is a leak. A spurious one is over-masking, which `docs/build-plan.md`
    calls "the failure nobody tests for" — so a superset is not good enough either.
    """
    expected = load_expected(expected_path)
    normalised = _normalise_fixture(_raw_fixture_path(expected_path))

    found = sorted(
        (span.start, span.end, span.text)
        for span in DETECTORS[detector_id](normalised.text, CONFIG)
    )

    assert found == _expected_spans(expected, detector_id), (
        f"{expected_path.name}: {detector_id} disagrees with the fixture. A fixture is the "
        f"specification — fix the detector, never the expectation."
    )


@pytest.mark.golden
@pytest.mark.leak
@pytest.mark.parametrize(
    "expected_path", CASES, ids=lambda p: p.name.removesuffix(".expected.json")
)
def test_no_detected_span_is_missing_from_the_leak_list(expected_path: Path) -> None:
    """Anything a detector finds must be something the fixture forbids in output.

    A span found but absent from `must_not_appear_in_output` would be masked without any
    fixture asserting it stays masked, which is coverage that looks real and is not.
    """
    expected = load_expected(expected_path)
    normalised = _normalise_fixture(_raw_fixture_path(expected_path))
    forbidden = expected["must_not_appear_in_output"]
    assert isinstance(forbidden, list)

    for detect in DETECTORS.values():
        for span in detect(normalised.text, CONFIG):
            assert span.text in forbidden, (
                f"{expected_path.name}: detected {span.detector} span is not listed in "
                f"must_not_appear_in_output, so nothing asserts it stays out of output"
            )


def test_every_declared_detector_is_either_implemented_or_known() -> None:
    """No fixture may declare a detector this file silently ignores."""
    declared = {
        span["detector"] for path in CASES for span in load_expected(path)["expected_spans"]
    }
    unaccounted = declared - set(DETECTORS) - NOT_YET_IMPLEMENTED
    assert not unaccounted, (
        f"fixtures declare detector(s) {sorted(unaccounted)} that are neither implemented "
        f"nor listed as pending — their spans are being ignored by this sweep"
    )


#: Fixtures declaring a span, per implemented detector, at the time that detector was
#: written. A floor, not an expectation of exactness — the corpus grows.
SWEEP_FLOORS: dict[str, int] = {
    credit_card.DETECTOR_ID: 8,
    iban.DETECTOR_ID: 7,
}


@pytest.mark.parametrize("detector_id", sorted(SWEEP_FLOORS))
def test_the_sweep_actually_asserts_something(detector_id: str) -> None:
    """Guards the sweep itself: some fixture must expect a span from each detector.

    Every assertion above passes vacuously against a corpus containing nothing for the
    detector under test — the "green light over work not done" shape CLAUDE.md invariant 12
    names. Parametrised by detector rather than written once for `credit_card`, so
    registering a detector in `DETECTORS` without any fixture behind it fails here instead
    of contributing a row of vacuous passes to the sweep.
    """
    declaring = [path for path in CASES if _expected_spans(load_expected(path), detector_id)]
    assert len(declaring) >= SWEEP_FLOORS[detector_id], (
        f"only {len(declaring)} fixtures expect a {detector_id} span; the corpus had "
        f"{SWEEP_FLOORS[detector_id]} when this detector was written"
    )


def test_every_implemented_detector_has_a_sweep_floor() -> None:
    """The guard above only guards what it is told about.

    A detector registered in `DETECTORS` but absent from `SWEEP_FLOORS` is swept and never
    checked for having anything to sweep — the vacuous-pass hole reopened one level up.
    """
    assert set(DETECTORS) == set(SWEEP_FLOORS), (
        f"detectors {sorted(set(DETECTORS) ^ set(SWEEP_FLOORS))} are registered for the "
        f"sweep without a floor, or have a floor without being registered"
    )
