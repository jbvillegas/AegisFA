"""Generate a correlation rule pack tailored to a sample raw_logs payload row.

Usage:
  python -m scripts.generate_rule_pack --sample-file sample_row.json --output tailored_rule_pack.json
  python -m scripts.generate_rule_pack --sample-json '{"payload": {...}}' --output tailored_rule_pack.json
  python -m scripts.generate_rule_pack --sample-file sample_row.json --apply --org-id <uuid> --name-prefix "Org A"

Notes:
- correlation_engine.py matches top-level fields only, so this generator maps against top-level keys.
- If the input is a raw_logs export row, the generator automatically unwraps the nested `payload` field.
- If the input is a CICIDS-style CSV, the generator scans the rows and emits flow-specific rules.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import math
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()

from supabase import create_client

from app.rf_training_mapping import get_mitre_for_class
from .seed_rules import DEFAULT_RULES

CANONICAL_FIELD_ALIASES: dict[str, list[str]] = {
    "action": [
        "action",
        "event_action",
        "event_type",
        "event",
        "operation",
        "operation_type",
        "activity",
        "command",
        "cmd",
        "type",
    ],
    "result": [
        "result",
        "status",
        "outcome",
        "response",
        "state",
    ],
    "source_ip": [
        "source_ip",
        "src_ip",
        "client_ip",
        "remote_ip",
        "ip",
        "ip_address",
        "source_address",
    ],
    "username": [
        "username",
        "user",
        "account",
        "principal",
        "actor",
        "identity",
        "login",
    ],
    "reason": [
        "reason",
        "message",
        "description",
        "details",
        "event_message",
        "log_message",
    ],
    "destination_ip": [
        "destination_ip",
        "dst_ip",
        "target_ip",
        "server_ip",
        "dest_ip",
    ],
    "source_port": [
        "source_port",
        "src_port",
        "client_port",
        "port",
        "srcport",
    ],
    "destination_port": [
        "destination_port",
        "dst_port",
        "target_port",
        "dest_port",
        "port",
    ],
    "protocol": [
        "protocol",
        "proto",
        "network_protocol",
    ],
    "timestamp": [
        "timestamp",
        "time",
        "event_time",
        "created_at",
        "date",
        "datetime",
    ],
    "label": [
        "label",
        "class",
        "attack_label",
    ],
}

FLOW_FIELD_HINTS = {
    "destination_port",
    "flow_duration",
    "flow_bytes_s",
    "flow_packets_s",
    "fwd_packets_s",
    "bwd_packets_s",
    "syn_flag_count",
    "ack_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "down_up_ratio",
    "average_packet_size",
    "packet_length_mean",
    "packet_length_std",
    "label",
}

FLOW_RULE_CANDIDATES = [
    {
        "field": "Destination Port",
        "name": "High Destination Port",
        "severity": "medium",
        "base_confidence": 0.72,
        "percentile": 0.95,
        "minimum": 1024,
    },
    {
        "field": "Flow Duration",
        "name": "Long Flow Duration",
        "severity": "medium",
        "base_confidence": 0.72,
        "percentile": 0.95,
    },
    {
        "field": "Flow Bytes/s",
        "name": "High Flow Throughput",
        "severity": "high",
        "base_confidence": 0.78,
        "percentile": 0.95,
    },
    {
        "field": "Flow Packets/s",
        "name": "High Packet Rate",
        "severity": "high",
        "base_confidence": 0.78,
        "percentile": 0.95,
    },
    {
        "field": "Fwd Packets/s",
        "name": "Forward Burst Rate",
        "severity": "high",
        "base_confidence": 0.78,
        "percentile": 0.95,
    },
    {
        "field": "Bwd Packets/s",
        "name": "Backward Burst Rate",
        "severity": "medium",
        "base_confidence": 0.74,
        "percentile": 0.95,
    },
    {
        "field": "SYN Flag Count",
        "name": "SYN Heavy Flow",
        "severity": "high",
        "base_confidence": 0.8,
        "percentile": 0.95,
        "minimum": 1,
    },
    {
        "field": "Down/Up Ratio",
        "name": "Asymmetric Flow",
        "severity": "medium",
        "base_confidence": 0.73,
        "percentile": 0.95,
    },
]

DDOS_FAMILY_TECHNIQUES = [
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
]

DDOS_FIELD_TECHNIQUE_BUNDLES: dict[str, list[dict[str, str]]] = {
    "destination_port": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[1]],
    "flow_duration": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[1]],
    "flow_bytes_s": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[2]],
    "flow_packets_s": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[2]],
    "fwd_packets_s": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[2]],
    "bwd_packets_s": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[2]],
    "syn_flag_count": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[1]],
    "down_up_ratio": [DDOS_FAMILY_TECHNIQUES[0], DDOS_FAMILY_TECHNIQUES[1]],
}

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")
SUCCESS_VALUES = {"success", "successful", "allow", "allowed", "ok", "passed"}
FAILURE_VALUES = {"failure", "failed", "deny", "denied", "error", "blocked"}


def _normalize_key(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    for char in ("-", "/", " "):
        normalized = normalized.replace(char, "_")
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized.strip("_")


def _normalize_csv_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in row.items():
        cleaned_key = str(key or "").strip()
        if not cleaned_key:
            continue
        normalized[cleaned_key] = value
    return normalized


def _is_header_like_row(row: dict[str, Any]) -> bool:
    compared = 0
    matched = 0
    for key, value in row.items():
        cleaned_key = str(key or "").strip()
        cleaned_value = str(value or "").strip()
        if not cleaned_key and not cleaned_value:
            continue
        compared += 1
        if cleaned_key == cleaned_value:
            matched += 1
    return compared > 0 and compared == matched


def _load_sample_csv_rows(sample_path: Path) -> list[dict[str, Any]]:
    with sample_path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        rows: list[dict[str, Any]] = []
        for raw_row in reader:
            normalized_row = _normalize_csv_row(raw_row)
            if not normalized_row or _is_header_like_row(normalized_row):
                continue
            rows.append(normalized_row)

    if not rows:
        raise ValueError(
            f"Sample CSV file {sample_path} did not produce any usable data rows."
        )

    return rows


def _load_sample_row(sample_file: str | None, sample_json: str | None) -> dict[str, Any]:
    if sample_file and sample_json:
        raise ValueError("Provide only one of --sample-file or --sample-json")

    if sample_file:
        sample_path = Path(sample_file)
        if not sample_path.exists():
            raise FileNotFoundError(
                f"Sample file not found: {sample_file}. "
                "Pass a real raw_logs export file path, or use --sample-json with a pasted row."
            )

        if sample_path.suffix.lower() == ".csv":
            with sample_path.open("r", encoding="utf-8", newline="") as csv_file:
                reader = csv.DictReader(csv_file)
                try:
                    first_row = next(reader)
                except StopIteration as exc:
                    raise ValueError(
                        f"Sample CSV file {sample_file} is empty. Add at least one data row."
                    ) from exc

            if not first_row:
                raise ValueError(
                    f"Sample CSV file {sample_file} did not produce a usable row."
                )

            return first_row

        raw_text = sample_path.read_text(encoding="utf-8")
        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            if not parsed:
                raise ValueError(
                    f"Sample file {sample_file} is an empty list. Provide one raw_logs row or a payload object."
                )
            first_item = parsed[0]
            if isinstance(first_item, dict):
                return first_item
            raise ValueError(
                f"Sample file {sample_file} contains a list, but the first item is not an object."
            )

        if not isinstance(parsed, dict):
            raise ValueError(
                f"Sample file {sample_file} must contain a JSON object or a list with one object."
            )

        return parsed

    if sample_json:
        parsed = json.loads(sample_json)
        if isinstance(parsed, list):
            if not parsed:
                raise ValueError("--sample-json cannot be an empty list")
            first_item = parsed[0]
            if isinstance(first_item, dict):
                return first_item
            raise ValueError("--sample-json list must contain a JSON object as the first item")

        if not isinstance(parsed, dict):
            raise ValueError("--sample-json must be a JSON object or a list containing one object")

        return parsed

    raise ValueError("A sample payload row is required via --sample-file or --sample-json")


def _unwrap_payload(sample_row: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sample_row, dict):
        return {}

    payload = sample_row.get("payload")
    if isinstance(payload, dict):
        return payload

    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    return sample_row


def _is_flow_dataset(sample_rows: list[dict[str, Any]]) -> bool:
    if not sample_rows:
        return False

    sample_keys = {_normalize_key(key) for key in sample_rows[0].keys()}
    flow_hits = len(sample_keys & FLOW_FIELD_HINTS)
    return flow_hits >= 4 or ({"label", "destination_port", "flow_duration"} <= sample_keys)


def _coerce_number(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return None
        return float(value)
    try:
        cleaned = str(value).strip()
        if not cleaned:
            return None
        return float(cleaned)
    except (TypeError, ValueError):
        return None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    if percentile <= 0:
        return min(values)
    if percentile >= 1:
        return max(values)

    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[int(position)]

    lower_weight = upper - position
    upper_weight = position - lower
    return ordered[lower] * lower_weight + ordered[upper] * upper_weight


def _build_existence_rule(
    name: str,
    field: str,
    op: str,
    value: float | int | str,
    severity: str,
    base_confidence: float,
    mitre_technique: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "severity": severity,
        "mitre_technique": mitre_technique,
        "rule_logic": {
            "type": "existence",
            "base_confidence": base_confidence,
            "filter": [
                {
                    "field": field,
                    "op": op,
                    "value": value,
                }
            ],
        },
    }


def _build_ddos_family_mitre_techniques(primary_only: bool = False) -> dict[str, Any]:
    techniques = DDOS_FAMILY_TECHNIQUES[:1] if primary_only else DDOS_FAMILY_TECHNIQUES[:3]
    return {
        "techniques": techniques,
        "summary": (
            "DNS/UDP reflected denial-of-service behavior aligned to flow-rate anomalies. "
            "Primary family: T1498 Network Denial of Service."
        ),
        "severity": "high",
    }


def _build_flow_family_mitre_techniques(actual_field: str, candidate_severity: str) -> dict[str, Any]:
    normalized_field = _normalize_key(actual_field)
    techniques = DDOS_FIELD_TECHNIQUE_BUNDLES.get(normalized_field, [DDOS_FAMILY_TECHNIQUES[0]])
    return {
        "techniques": techniques,
        "summary": (
            f"{actual_field} anomaly consistent with reflected denial-of-service flow behavior. "
            f"Primary family: {techniques[0]['id']} {techniques[0]['name']}."
        ),
        "severity": candidate_severity,
    }


def _build_flow_rule_pack(sample_rows: list[dict[str, Any]], name_prefix: str | None = None) -> dict[str, Any]:
    field_map = infer_field_map(sample_rows[0])
    numeric_values: dict[str, list[float]] = {}
    observed_labels: dict[str, int] = {}

    for row in sample_rows:
        for key, value in row.items():
            normalized_key = _normalize_key(key)
            if normalized_key == "label":
                label = str(value or "").strip()
                if label:
                    observed_labels[label] = observed_labels.get(label, 0) + 1
                continue

            number = _coerce_number(value)
            if number is None:
                continue
            numeric_values.setdefault(key, []).append(number)

    tailored_rules: list[dict[str, Any]] = []
    for candidate in FLOW_RULE_CANDIDATES:
        actual_field = field_map.get(_normalize_key(candidate["field"]), candidate["field"])
        values = numeric_values.get(actual_field, [])
        if not values:
            continue

        threshold = _percentile(values, candidate["percentile"])
        if threshold is None:
            continue

        minimum = candidate.get("minimum")
        if minimum is not None:
            threshold = max(threshold, float(minimum))

        threshold_value: float | int
        threshold_value = int(threshold) if float(threshold).is_integer() else round(float(threshold), 4)
        rule = _build_existence_rule(
            name=candidate["name"],
            field=actual_field,
            op="gte",
            value=threshold_value,
            severity=candidate["severity"],
            base_confidence=candidate["base_confidence"],
            mitre_technique={
                **_build_flow_family_mitre_techniques(actual_field, candidate["severity"]),
                "summary": f"High {actual_field} values relative to the dataset baseline.",
            },
        )
        if name_prefix:
            rule["name"] = f"{name_prefix} - {rule['name']}"
        tailored_rules.append(rule)

    if observed_labels:
        for label, count in sorted(observed_labels.items(), key=lambda item: (-item[1], item[0])):
            if _normalize_key(label) in {"benign", "label"}:
                continue
            mitre = get_mitre_for_class(label)
            rule = _build_existence_rule(
                name=f"Observed label: {label}",
                field="Label",
                op="eq",
                value=label,
                severity=mitre.get("severity", "medium"),
                base_confidence=0.9,
                mitre_technique={
                    "techniques": mitre.get("techniques", []) or DDOS_FAMILY_TECHNIQUES[:1],
                    "summary": mitre.get("summary", f"Observed attack label {label}"),
                    "severity": mitre.get("severity", "medium"),
                },
            )
            if name_prefix:
                rule["name"] = f"{name_prefix} - {rule['name']}"
            tailored_rules.append(rule)

    missing_fields = [
        field for field in CANONICAL_FIELD_ALIASES.keys()
        if field not in field_map
    ]

    return {
        "dataset_type": "flow",
        "sample_keys": sorted(list(sample_rows[0].keys())),
        "field_map": field_map,
        "missing_canonical_fields": missing_fields,
        "observed_labels": observed_labels,
        "tailored_rules": tailored_rules,
    }


def _looks_like_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    return bool(IP_RE.match(text))


def _looks_like_username(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or _looks_like_ip(text):
        return False
    return len(text) <= 128 and any(char.isalpha() for char in text)


def _looks_like_result(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return _normalize_key(value) in SUCCESS_VALUES | FAILURE_VALUES


def _score_candidate(canonical: str, sample_key: str, sample_value: Any) -> int:
    normalized_key = _normalize_key(sample_key)
    aliases = [_normalize_key(alias) for alias in CANONICAL_FIELD_ALIASES.get(canonical, [])]
    score = 0

    if normalized_key == canonical:
        score += 100
    if normalized_key in aliases:
        score += 95
    if any(alias and alias in normalized_key for alias in aliases):
        score += 70

    if canonical in {"source_ip", "destination_ip"} and _looks_like_ip(sample_value):
        score += 60
    elif canonical == "username" and _looks_like_username(sample_value):
        score += 35
    elif canonical == "result" and _looks_like_result(sample_value):
        score += 45
    elif canonical == "action" and isinstance(sample_value, str) and any(char.isalpha() for char in sample_value):
        score += 30
    elif canonical in {"source_port", "destination_port"} and isinstance(sample_value, (int, float)):
        score += 35
    elif canonical == "protocol" and isinstance(sample_value, str):
        score += 25
    elif canonical == "timestamp" and isinstance(sample_value, (str, int, float)):
        score += 20

    return score


def infer_field_map(sample_event: dict[str, Any]) -> dict[str, str]:
    field_map: dict[str, str] = {}

    for canonical_field in CANONICAL_FIELD_ALIASES:
        best_key = None
        best_score = 0
        for sample_key, sample_value in sample_event.items():
            score = _score_candidate(canonical_field, sample_key, sample_value)
            if score > best_score:
                best_score = score
                best_key = sample_key
        if best_key and best_score >= 80:
            field_map[canonical_field] = best_key

    return field_map


def _remap_condition(condition: dict[str, Any], field_map: dict[str, str]) -> dict[str, Any]:
    updated = deepcopy(condition)
    canonical_field = updated.get("field")
    if canonical_field in field_map:
        updated["field"] = field_map[canonical_field]
    return updated


def _remap_logic(logic: Any, field_map: dict[str, str]) -> Any:
    if isinstance(logic, list):
        return [_remap_logic(item, field_map) for item in logic]

    if not isinstance(logic, dict):
        return logic

    remapped: dict[str, Any] = {}
    for key, value in logic.items():
        if key == "filter" and isinstance(value, list):
            remapped[key] = [
                _remap_condition(condition, field_map)
                if isinstance(condition, dict)
                else condition
                for condition in value
            ]
        elif key == "steps" and isinstance(value, list):
            remapped[key] = [
                [
                    _remap_condition(condition, field_map)
                    if isinstance(condition, dict)
                    else condition
                    for condition in step
                ]
                if isinstance(step, list)
                else step
                for step in value
            ]
        elif key == "rules" and isinstance(value, list):
            remapped[key] = [_remap_logic(rule, field_map) for rule in value]
        elif key == "group_by" and isinstance(value, list):
            remapped[key] = [field_map.get(item, item) for item in value]
        elif key == "distinct_field" and isinstance(value, str):
            remapped[key] = field_map.get(value, value)
        else:
            remapped[key] = _remap_logic(value, field_map)

    return remapped


def _tailor_rule(rule: dict[str, Any], field_map: dict[str, str], name_prefix: str | None = None) -> dict[str, Any]:
    tailored = deepcopy(rule)
    if name_prefix:
        tailored["name"] = f"{name_prefix} - {tailored['name']}"
    tailored["rule_logic"] = _remap_logic(tailored.get("rule_logic", {}), field_map)
    return tailored


def _collect_required_fields_from_logic(logic: Any) -> set[str]:
    required: set[str] = set()
    if isinstance(logic, list):
        for item in logic:
            required.update(_collect_required_fields_from_logic(item))
        return required

    if not isinstance(logic, dict):
        return required

    field_value = logic.get("field")
    if isinstance(field_value, str):
        required.add(field_value)

    distinct_field = logic.get("distinct_field")
    if isinstance(distinct_field, str):
        required.add(distinct_field)

    group_by = logic.get("group_by")
    if isinstance(group_by, list):
        for field in group_by:
            if isinstance(field, str):
                required.add(field)

    filter_block = logic.get("filter")
    if isinstance(filter_block, list):
        required.update(_collect_required_fields_from_logic(filter_block))

    steps = logic.get("steps")
    if isinstance(steps, list):
        required.update(_collect_required_fields_from_logic(steps))

    rules = logic.get("rules")
    if isinstance(rules, list):
        required.update(_collect_required_fields_from_logic(rules))

    return required


def _rule_is_applicable(rule: dict[str, Any], available_canonical_fields: set[str]) -> bool:
    logic = rule.get("rule_logic") or {}
    required_fields = _collect_required_fields_from_logic(logic)
    if not required_fields:
        return True
    return required_fields.issubset(available_canonical_fields)


def build_rule_pack(sample_input: dict[str, Any] | list[dict[str, Any]], name_prefix: str | None = None) -> dict[str, Any]:
    if isinstance(sample_input, list):
        rows = [_unwrap_payload(row) for row in sample_input if isinstance(row, dict)]
        rows = [row for row in rows if isinstance(row, dict) and row]
        if rows and _is_flow_dataset(rows):
            return _build_flow_rule_pack(rows, name_prefix=name_prefix)

        sample_input = rows[0] if rows else {}

    event = _unwrap_payload(sample_input)
    if event and _is_flow_dataset([event]):
        return _build_flow_rule_pack([event], name_prefix=name_prefix)

    field_map = infer_field_map(event)
    available_fields = set(field_map.keys())
    applicable_defaults = [
        rule for rule in DEFAULT_RULES if _rule_is_applicable(rule, available_fields)
    ]
    tailored_rules = [_tailor_rule(rule, field_map, name_prefix=name_prefix) for rule in applicable_defaults]

    missing_fields = [
        field for field in CANONICAL_FIELD_ALIASES.keys()
        if field not in field_map
    ]

    return {
        "dataset_type": "raw_logs",
        "sample_keys": sorted(list(event.keys())),
        "field_map": field_map,
        "missing_canonical_fields": missing_fields,
        "tailored_rules": tailored_rules,
    }


def _apply_pack(org_id: str, pack: dict[str, Any]) -> list[dict[str, Any]]:
    supabase = create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_SERVICE_ROLE_KEY"],
    )

    applied_rules = []
    for rule in pack["tailored_rules"]:
        response = supabase.table("correlation_rules").upsert(
            {
                "org_id": org_id,
                "name": rule["name"],
                "mitre_technique": rule["mitre_technique"],
                "severity": rule["severity"],
                "rule_logic": rule["rule_logic"],
            },
            on_conflict="name",
        ).execute()
        applied_rules.append({
            "name": rule["name"],
            "mitre_technique": rule["mitre_technique"],
            "status": "applied" if response.data is not None else "unknown",
        })

    return applied_rules


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a correlation rule pack from a sample raw_logs payload row.")
    parser.add_argument("--sample-file", help="Path to a JSON file containing one raw_logs row or payload dict.")
    parser.add_argument("--sample-json", help="Inline JSON string containing one raw_logs row or payload dict.")
    parser.add_argument("--output", help="Write the generated rule pack JSON to this path.")
    parser.add_argument("--apply", action="store_true", help="Upsert the tailored rules into Supabase.")
    parser.add_argument("--org-id", help="Org UUID for --apply mode.")
    parser.add_argument("--name-prefix", help="Prefix added to tailored rule names when generating or applying.")

    args = parser.parse_args()

    if args.sample_file and args.sample_file.lower().endswith(".csv"):
        sample_row = _load_sample_csv_rows(Path(args.sample_file))
    else:
        sample_row = _load_sample_row(args.sample_file, args.sample_json)
    name_prefix = args.name_prefix or (args.org_id[:8] if args.org_id else None)
    pack = build_rule_pack(sample_row, name_prefix=name_prefix)

    if args.output:
        Path(args.output).write_text(json.dumps(pack, indent=2, sort_keys=True), encoding="utf-8")

    if args.apply:
        if not args.org_id:
            raise SystemExit("--org-id is required when using --apply")
        applied_rules = _apply_pack(args.org_id, pack)
        pack["applied_rules"] = applied_rules

    print(json.dumps(pack, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
