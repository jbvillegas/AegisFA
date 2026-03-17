import re
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional


from . import supabase_client
from .timestamp_utils import parse_timestamp as _parse_timestamp

_OPS = {
    "eq": lambda val, rule_val: val == rule_val,
    "neq": lambda val, rule_val: val != rule_val,
    "in": lambda val, rule_val: val in rule_val,
    "contains": lambda val, rule_val: rule_val in str(val) if val else False,
    "regex": lambda val, rule_val: bool(re.search(rule_val, str(val))) if val else False,
    "exists": lambda val, _: val is not None,
}

def run_correlation(
    entries: list[dict],
    org_id: str,
    file_id: str,) -> list[dict]:

    logger = logging.getLogger(__name__)

    if len(entries) > 100000:
        logger.warning(f"The file: {file_id} is a large datase. Performance may be slow due to excessive log count:({len(entries)})")

    rules = _fetch_rules(org_id)
    detections = []

    for rule in rules:
        if len(entries) > 50000:
            batch_size = 50000
            for i in range(0, len(entries), batch_size):
                batch = entries[i:i+batch_size]
                result = _evaluate_rule(rule, batch)
                if result is not None:
                    # Adjust indices to account for batching
                    result["matched_indices"] = [idx + i for idx in result["matched_indices"]]
                    detection_id = _save_detection(
                        org_id=org_id,
                        file_id=file_id,
                        rule=rule,
                        matched_indices=result["matched_indices"],
                        confidence=result["confidence"],
                        description=result["description"],
                    )
                    detections.append({
                        "detection_id": detection_id,
                        "rule_name": rule["name"],
                        "mitre_technique": rule.get("mitre_technique", ""),
                        "severity": rule.get("severity", "medium"),
                        "confidence": result["confidence"],
                        "matched_event_indices": result["matched_indices"],
                        "description": result["description"],
                    })
        
    return detections

_rule_cache = {}

def _fetch_rules(org_id: str) -> list[dict]:

    if org_id in _rule_cache:
        return _rule_cache[org_id]
    
    org_rules = (
        supabase_client.table("correlation_rules")
        .select("*")
        .eq("org_id", org_id)
        .execute()
    )
    default_rules = (
        supabase_client.table("correlation_rules")
        .select("*")
        .is_("org_id", "null")
        .execute()
    )
    rules = (default_rules.data or []) + (org_rules.data or [])
    _rule_cache[org_id] = rules
    return rules

_EVALUATORS = {}

def _validate_rule_logic(rule: dict) -> bool: 
    logic = rule.get("rule_logic", {})
    rule_type = logic.get("type")

    if rule_type not in _EVALUATORS:
        return False
    
    if rule_type == "threshold":
        return "filter" in logic and "threshold" in logic
    elif rule_type == "sequence":
        return "steps" in logic and isinstance(logic["steps"], list) and len(logic["steps"]) > 0
    elif rule_type == "distinct_value":
        return "distinct_field" in logic and "distinct_threshold" in logic
    elif rule_type == "existence":
        return "filter" in logic and isinstance(logic["filter"], list) and len(logic["filter"]) > 0
    elif rule_type == "time_rate":
        return "rate_per_minute" in logic
    return False

def _evaluate_rule(rule: dict, entries: list[dict]) -> Optional[dict]:
    
    logger = logging.getLogger(__name__)

    try: 
        logic = rule.get("rule_logic", {})
        rule_type = logic.get("type")

        if not _validate_rule_logic(rule):
            logger.warning(f"Invalid logic for rule {rule['id']}: {logic}")
            return None
        evaluator = _EVALUATORS.get(rule_type)
        if evaluator is None:
            logger.warning(f"No evaluator found for rule type '{rule_type}' in rule {rule['id']}")
            return None
        return evaluator(logic, entries)
    except Exception as e:
        logger.error(f"Error evaluating rule {rule['id']}: {e}")
        return None

def _entry_matches_filter(entry: dict, filters: list[dict]) -> bool:
    for condition in filters:
        field = condition.get("field", "")
        op = condition.get("op", "eq")
        rule_val = condition.get("value")
        entry_val = entry.get(field)
        negate = condition.get("negate", False)

        op_fn = _OPS.get(op)
        if op_fn is None:
            return False
        
        matches = op_fn(entry_val, rule_val)
        if negate:
            matches = not matches
        if not matches:
            return False
        
    return True


def _filter_entries(
    entries: list[dict], filters: list[dict]
) -> list[tuple[int, dict]]:
    return [
        (i, e) for i, e in enumerate(entries) if _entry_matches_filter(e, filters)
    ]

def _group_entries(
    indexed_entries: list[tuple[int, dict]],
    group_by: list[str],
) -> dict[tuple, list[tuple[int, dict]]]:
    groups = defaultdict(list)
    for idx, entry in indexed_entries:
        key = tuple(entry.get(f, "") for f in group_by)
        groups[key].append((idx, entry))
    return dict(groups)

def _entries_within_window(
    indexed_entries: list[tuple[int, dict]], window_seconds: Optional[int]
) -> bool:

    if window_seconds is None:
        return True
    timestamps = [_parse_timestamp(e) for _, e in indexed_entries]
    timestamps = [t for t in timestamps if t is not None]
    if len(timestamps) < 2:
        return True 
    span = (max(timestamps) - min(timestamps)).total_seconds()
    return span <= window_seconds

def _compute_confidence(base: float, actual: int, threshold: int, severity: str = "medium") -> float:
    
    if threshold <= 0:
        return min(base, 1.0)
    
    ratio = actual / threshold
    severity_multiplier = {"critical": 1.2, "high": 1.1, "medium": 1.0, "low":0.8}.get(severity, 1.0)

    if ratio >= 2.0:
        adjusted = base * 0.8 + 0.2
    elif ratio >= 1.0:
        adjusted = base * (0.5 + 0.5 * ratio)
    else:
        adjusted = base * ratio

    return min(adjusted * severity_multiplier, 1.0) 

def _evaluate_threshold(logic: dict, entries: list[dict]) -> Optional[dict]:
    filters = logic.get("filter", [])
    group_by = logic.get("group_by", [])
    threshold = logic.get("threshold", 1)
    window = logic.get("window_seconds")
    base_conf = logic.get("base_confidence", 0.7)

    matched = _filter_entries(entries, filters)
    if not matched:
        return None

    if group_by:
        groups = _group_entries(matched, group_by)
    else:
        groups = {"_all": matched}

    for group_key, group_entries in groups.items():
        if not _entries_within_window(group_entries, window):
            continue
        count = len(group_entries)
        if count >= threshold:
            indices = [i for i, _ in group_entries]
            return {
                "matched_indices": indices,
                "confidence": _compute_confidence(base_conf, count, threshold),
                "description": (
                    f"Threshold rule triggered: {count} events "
                    f"(threshold: {threshold}) for group {group_key}"
                ),
            }
    return None


def _evaluate_sequence(logic: dict, entries: list[dict]) -> Optional[dict]:
    steps = logic.get("steps", [])
    group_by = logic.get("group_by", [])
    window = logic.get("window_seconds")
    base_conf = logic.get("base_confidence", 0.8)

    if not steps:
        return None

    step_matches = []
    for step_filter in steps:
        step_matches.append(_filter_entries(entries, step_filter))

    if any(len(sm) == 0 for sm in step_matches):
        return None

    if group_by:
        all_groups = defaultdict(lambda: [[] for _ in steps])
        for step_idx, matches in enumerate(step_matches):
            for idx, entry in matches:
                key = tuple(entry.get(f, "") for f in group_by)
                all_groups[key][step_idx].append((idx, entry))
    else:
        all_groups = {"_all": step_matches}

    for group_key, group_step_matches in all_groups.items():
        if any(len(sm) == 0 for sm in group_step_matches):
            continue

        sequence_indices = []
        last_ts = None
        valid = True

        for step_entries in group_step_matches:
            sorted_entries = sorted(step_entries, key=lambda x: x[0])
            found = False
            for idx, entry in sorted_entries:
                ts = _parse_timestamp(entry)
                if last_ts is None or ts is None or ts >= last_ts:
                    sequence_indices.append(idx)
                    last_ts = ts
                    found = True
                    break
            if not found:
                valid = False
                break

        if not valid:
            continue

        if window is not None and len(sequence_indices) >= 2:
            first_entries = [(i, entries[i]) for i in sequence_indices]
            if not _entries_within_window(first_entries, window):
                continue

        return {
            "matched_indices": sequence_indices,
            "confidence": base_conf,
            "description": (
                f"Sequence rule triggered: {len(steps)}-step chain "
                f"detected for group {group_key}"
            ),
        }
    return None


def _evaluate_distinct_value(logic: dict, entries: list[dict]) -> Optional[dict]:
    filters = logic.get("filter", [])
    group_by = logic.get("group_by", [])
    distinct_field = logic.get("distinct_field", "")
    distinct_threshold = logic.get("distinct_threshold", 2)
    window = logic.get("window_seconds")
    base_conf = logic.get("base_confidence", 0.7)

    matched = _filter_entries(entries, filters)
    if not matched:
        return None

    if group_by:
        groups = _group_entries(matched, group_by)
    else:
        groups = {"_all": matched}

    for group_key, group_entries in groups.items():
        if not _entries_within_window(group_entries, window):
            continue
        distinct_values = {e.get(distinct_field) for _, e in group_entries}
        distinct_values.discard(None)
        count = len(distinct_values)
        if count >= distinct_threshold:
            indices = [i for i, _ in group_entries]
            return {
                "matched_indices": indices,
                "confidence": _compute_confidence(base_conf, count, distinct_threshold),
                "description": (
                    f"Distinct value rule triggered: {count} distinct "
                    f"'{distinct_field}' values (threshold: {distinct_threshold}) "
                    f"for group {group_key}"
                ),
            }
    return None

def _evaluate_existence(logic: dict, entries: list[dict]) -> Optional[dict]:
    filters = logic.get("filter", [])
    base_conf = logic.get("base_confidence", 0.7)

    matched = _filter_entries(entries, filters)
    if not matched:
        return None

    indices = [i for i, _ in matched]
    return {
        "matched_indices": indices,
        "confidence": base_conf,
        "description": f"Existence rule triggered: {len(matched)} matching events found",
    }


def _evaluate_time_rate(logic: dict, entries: list[dict]) -> Optional[dict]:
    filters = logic.get("filter", [])
    group_by = logic.get("group_by", [])
    rate_per_minute = logic.get("rate_per_minute", 10)
    base_conf = logic.get("base_confidence", 0.7)

    matched = _filter_entries(entries, filters)
    if not matched:
        return None

    if group_by:
        groups = _group_entries(matched, group_by)
    else:
        groups = {"_all": matched}

    for group_key, group_entries in groups.items():
        # Parse timestamps and sort
        timed = []
        for idx, entry in group_entries:
            ts = _parse_timestamp(entry)
            if ts is not None:
                timed.append((idx, entry, ts))

        if len(timed) < 2:
            continue

        timed.sort(key=lambda x: x[2])
        span_seconds = (timed[-1][2] - timed[0][2]).total_seconds()
        if span_seconds <= 0:
            continue

        rate = len(timed) / (span_seconds / 60.0)
        if rate >= rate_per_minute:
            indices = [i for i, _, _ in timed]
            return {
                "matched_indices": indices,
                "confidence": _compute_confidence(base_conf, int(rate), rate_per_minute),
                "description": (
                    f"Time rate rule triggered: {rate:.1f} events/min "
                    f"(threshold: {rate_per_minute}/min) for group {group_key}"
                ),
            }
    return None

def _evaluate_composite(logic: dict, entries: list[dict]) -> Optional[dict]:
    """Evaluate composite rules with AND/OR logic."""
    operator = logic.get("operator", "AND")  # AND or OR
    sub_rules = logic.get("rules", [])
    
    results = []
    for sub_rule in sub_rules:
        result = _evaluate_rule(sub_rule, entries)
        results.append(result)
    
    if operator == "AND":
        if all(r is not None for r in results):
            # Merge all matched indices
            all_indices = set()
            for r in results:
                all_indices.update(r["matched_indices"])
            return {
                "matched_indices": list(all_indices),
                "confidence": sum(r["confidence"] for r in results) / len(results),
                "description": f"Composite AND rule: all {len(sub_rules)} conditions matched"
            }
    elif operator == "OR":
        if any(r is not None for r in results):
            all_indices = set()
            for r in results:
                if r is not None:
                    all_indices.update(r["matched_indices"])
            return {
                "matched_indices": list(all_indices),
                "confidence": max(r["confidence"] for r in results if r is not None),
                "description": f"Composite OR rule: at least one of {len(sub_rules)} conditions matched"
            }
    return None

_EVALUATORS = {
    "threshold": _evaluate_threshold,
    "sequence": _evaluate_sequence,
    "distinct_value": _evaluate_distinct_value,
    "existence": _evaluate_existence,
    "time_rate": _evaluate_time_rate,
    "composite": _evaluate_composite,
}

def _save_detection(
    org_id: str,
    file_id: str,
    rule: dict,
    matched_indices: list[int],
    confidence: float,
    description: str,
) -> str:
    """Insert a detection record and return its UUID."""
    result = supabase_client.table("detections").insert({
        "org_id": org_id,
        "rule_id": rule["id"],
        "file_id": file_id,
        "matched_indices": matched_indices,
        "confidence": round(confidence, 4),
        "severity": rule.get("severity", "medium"),
        "description": description,
    }).execute()
    return result.data[0]["id"]
