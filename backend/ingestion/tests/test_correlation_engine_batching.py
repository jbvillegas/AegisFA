
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app import correlation_engine as ce

BATCH_SIZE = 50_000
OVERLAP_SIZE = 1_000

BASE_TIME = datetime(2024, 1, 1, 0, 0, 0)

class _FakeResponse:
    def __init__(self, data):
        self.data = data


class _FakeTable:

    def __init__(self, sb, name):
        self._sb = sb
        self._name = name
        self._org_filter = None
        self._null_filter = False
        self._insert_payload = None

    # --- query builders ---------------------------------------------------
    def select(self, *_a, **_kw):
        return self

    def eq(self, col, val):
        if self._name == "correlation_rules" and col == "org_id":
            self._org_filter = val
        return self

    def is_(self, col, val):
        if (
            self._name == "correlation_rules"
            and col == "org_id"
            and val == "null"
        ):
            self._null_filter = True
        return self

    def insert(self, payload):
        self._insert_payload = payload
        return self
    
    def execute(self):
        if self._name == "correlation_rules":
            if self._null_filter:
                return _FakeResponse(
                    [r for r in self._sb.rules if r.get("org_id") is None]
                )
            if self._org_filter is not None:
                return _FakeResponse(
                    [
                        r
                        for r in self._sb.rules
                        if r.get("org_id") == self._org_filter
                    ]
                )
            return _FakeResponse(list(self._sb.rules))

        if self._name == "detections":
            self._sb.detections.append(self._insert_payload)
            return _FakeResponse([{"id": f"det-{len(self._sb.detections)}"}])

        if self._name == "correlation_errors":
            self._sb.errors.append(self._insert_payload)
            return _FakeResponse([{"id": f"err-{len(self._sb.errors)}"}])

        return _FakeResponse([])


class _FakeSupabase:
    def __init__(self):
        self.rules: list[dict] = []
        self.detections: list[dict] = []
        self.errors: list[dict] = []

    def table(self, name):
        return _FakeTable(self, name)


@pytest.fixture
def fake_supabase(monkeypatch):
    sb = _FakeSupabase()
    monkeypatch.setattr(ce, "supabase_client", sb)

    ce._rule_cache.clear()
    yield sb
    ce._rule_cache.clear()

def _entry(idx: int, event_type: str = "noise") -> dict:
    return {
        "timestamp": (BASE_TIME + timedelta(seconds=idx)).isoformat(),
        "event_type": event_type,
        "user": f"user-{idx}",
    }


def _threshold_rule(
    rule_id: str = "rule-cross",
    threshold: int = 2,
    event_type: str = "login",
) -> dict:
    return {
        "id": rule_id,
        "name": f"threshold {event_type}",
        "severity": "high",
        "rule_logic": {
            "type": "threshold",
            "filter": [
                {"field": "event_type", "op": "eq", "value": event_type}
            ],
            "threshold": threshold,
            "base_confidence": 0.9,
        },
    }


def _sequence_rule() -> dict:
    return {
        "id": "rule-seq",
        "name": "auth then exec",
        "severity": "critical",
        "rule_logic": {
            "type": "sequence",
            "steps": [
                [{"field": "event_type", "op": "eq", "value": "auth"}],
                [{"field": "event_type", "op": "eq", "value": "exec"}],
            ],
            "base_confidence": 0.95,
        },
    }


def _make_entries(n: int) -> list[dict]:
    return [_entry(i) for i in range(n)]

def test_pattern_crossing_batch_boundary_is_detected(fake_supabase):
    """
    The exact scenario from the ticket: two matching events sitting on
    opposite sides of the 50,000 boundary must produce one detection whose
    matched indices are the *global* indices, not batch-relative ones.
    """
    fake_supabase.rules.append(_threshold_rule(threshold=2))

    entries = _make_entries(BATCH_SIZE + 1)
    entries[BATCH_SIZE - 1] = _entry(BATCH_SIZE - 1, event_type="login")
    entries[BATCH_SIZE] = _entry(BATCH_SIZE, event_type="login")

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(detections) == 1, detections
    assert sorted(detections[0]["matched_event_indices"]) == [
        BATCH_SIZE - 1,
        BATCH_SIZE,
    ]

def test_sequence_rule_crossing_batch_boundary_is_detected(fake_supabase):
    """
    Same bug, different evaluator: a two-step sequence split across the
    boundary must still be detected.
    """
    fake_supabase.rules.append(_sequence_rule())

    entries = _make_entries(BATCH_SIZE + 1)
    entries[BATCH_SIZE - 1] = _entry(BATCH_SIZE - 1, event_type="auth")
    entries[BATCH_SIZE] = _entry(BATCH_SIZE, event_type="exec")

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(detections) == 1, detections
    assert sorted(detections[0]["matched_event_indices"]) == [
        BATCH_SIZE - 1,
        BATCH_SIZE,
    ]

def test_pattern_starting_in_overlap_extending_into_new_batch(fake_supabase):
   
    fake_supabase.rules.append(_threshold_rule(threshold=2))

    n = BATCH_SIZE + 200
    entries = _make_entries(n)
    entries[BATCH_SIZE - 100] = _entry(BATCH_SIZE - 100, event_type="login")
    entries[BATCH_SIZE + 100] = _entry(BATCH_SIZE + 100, event_type="login")

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(detections) == 1, detections
    assert sorted(detections[0]["matched_event_indices"]) == [
        BATCH_SIZE - 100,
        BATCH_SIZE + 100,
    ]


def test_no_duplicate_detection_for_pattern_inside_overlap(fake_supabase):

    fake_supabase.rules.append(_threshold_rule(threshold=2))

    n = BATCH_SIZE + 100
    entries = _make_entries(n)
    # Both matches sit inside batch 1's overlap (which starts at 49_000).
    entries[BATCH_SIZE - 900] = _entry(BATCH_SIZE - 900, event_type="login")
    entries[BATCH_SIZE - 800] = _entry(BATCH_SIZE - 800, event_type="login")

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(detections) == 1, detections
    assert sorted(detections[0]["matched_event_indices"]) == [
        BATCH_SIZE - 900,
        BATCH_SIZE - 800,
    ]

def test_pattern_fully_inside_first_batch_is_detected(fake_supabase):
    fake_supabase.rules.append(_threshold_rule(threshold=2))

    entries = _make_entries(10)
    entries[3] = _entry(3, event_type="login")
    entries[7] = _entry(7, event_type="login")

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(detections) == 1
    assert sorted(detections[0]["matched_event_indices"]) == [3, 7]


def test_pattern_fully_inside_second_batch_is_detected(fake_supabase):
    fake_supabase.rules.append(_threshold_rule(threshold=2))

    n = BATCH_SIZE + 500
    entries = _make_entries(n)
    entries[BATCH_SIZE + 100] = _entry(BATCH_SIZE + 100, event_type="login")
    entries[BATCH_SIZE + 200] = _entry(BATCH_SIZE + 200, event_type="login")

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(detections) == 1
    assert sorted(detections[0]["matched_event_indices"]) == [
        BATCH_SIZE + 100,
        BATCH_SIZE + 200,
    ]

def test_pattern_span_larger_than_overlap_across_boundary_is_currently_missed(
    fake_supabase,
):
    fake_supabase.rules.append(_threshold_rule(threshold=2))

    n = BATCH_SIZE + 5_000
    entries = _make_entries(n)
    # 2,000 entries before the boundary, 2,000 entries after: > overlap.
    entries[BATCH_SIZE - 2_000] = _entry(
        BATCH_SIZE - 2_000, event_type="login"
    )
    entries[BATCH_SIZE + 2_000] = _entry(
        BATCH_SIZE + 2_000, event_type="login"
    )

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert detections == [], (
        
    )

def test_no_correlation_errors_recorded_on_clean_run(fake_supabase):
    fake_supabase.rules.append(_threshold_rule(threshold=2))

    entries = _make_entries(BATCH_SIZE + 1)
    entries[BATCH_SIZE - 1] = _entry(BATCH_SIZE - 1, event_type="login")
    entries[BATCH_SIZE] = _entry(BATCH_SIZE, event_type="login")

    ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert fake_supabase.errors == []

def test_exactly_one_detection_row_is_inserted_at_the_boundary(fake_supabase):
    fake_supabase.rules.append(_threshold_rule(threshold=2))

    entries = _make_entries(BATCH_SIZE + 1)
    entries[BATCH_SIZE - 1] = _entry(BATCH_SIZE - 1, event_type="login")
    entries[BATCH_SIZE] = _entry(BATCH_SIZE, event_type="login")

    ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(fake_supabase.detections) == 1
    inserted = fake_supabase.detections[0]
    assert sorted(inserted["matched_indices"]) == [
        BATCH_SIZE - 1,
        BATCH_SIZE,
    ]
    assert inserted["org_id"] == "o1"
    assert inserted["file_id"] == "f1"

def test_small_dataset_path_unchanged(fake_supabase):
    fake_supabase.rules.append(_threshold_rule(threshold=3))

    entries = _make_entries(50)
    entries[10] = _entry(10, event_type="login")
    entries[20] = _entry(20, event_type="login")
    entries[30] = _entry(30, event_type="login")

    detections = ce.run_correlation(entries, org_id="o1", file_id="f1")

    assert len(detections) == 1
    assert sorted(detections[0]["matched_event_indices"]) == [10, 20, 30]