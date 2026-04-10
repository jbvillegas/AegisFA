from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional
from uuid import UUID

from . import supabase_client
from .timestamp_utils import parse_timestamp, parse_iso_string

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500

def get_file_timeline(
    file_id: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    """Build a unified timeline for a single uploaded file."""
    page_size = min(page_size, MAX_PAGE_SIZE)

    items = []
    items.extend(_fetch_raw_events(file_id=file_id))
    items.extend(_fetch_detection_events(file_id=file_id))
    items.extend(_fetch_analysis_detection_events(file_id=file_id))
    items.extend(_fetch_ai_narrative_events(file_id=file_id))

    items = _apply_filters(items, start=start, end=end,
                           severity=severity, event_type=event_type)
    items = _sort_chronologically(items)

    total = len(items)
    paginated = _paginate(items, page, page_size)

    return {
        "items": [_to_json_safe(item) for item in paginated],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        },
        "meta": {
            "file_id": file_id,
            "event_count": sum(1 for i in items if i["type"] == "event"),
            "detection_count": sum(1 for i in items if i["type"] == "detection"),
            "ai_narrative_count": sum(
                1 for i in items if i["type"] == "ai_narrative"
            ),
        },
    }


def get_org_timeline(
    org_id: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    """Build a cross-file timeline for an entire organization."""
    page_size = min(page_size, MAX_PAGE_SIZE)

    file_ids = _get_org_file_ids(org_id)

    items = []
    items.extend(_fetch_raw_events(org_id=org_id))
    items.extend(_fetch_detection_events(org_id=org_id))
    for fid in file_ids:
        items.extend(_fetch_analysis_detection_events(file_id=fid))
        items.extend(_fetch_ai_narrative_events(file_id=fid))

    items = _apply_filters(items, start=start, end=end,
                           severity=severity, event_type=event_type)
    items = _sort_chronologically(items)

    total = len(items)
    paginated = _paginate(items, page, page_size)

    return {
        "items": [_to_json_safe(item) for item in paginated],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        },
        "meta": {
            "org_id": org_id,
            "file_count": len(file_ids),
            "event_count": sum(1 for i in items if i["type"] == "event"),
            "detection_count": sum(1 for i in items if i["type"] == "detection"),
            "ai_narrative_count": sum(
                1 for i in items if i["type"] == "ai_narrative"
            ),
        },
    }


def get_file_timeline_graph(
    file_id: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    max_nodes: int = 120,
) -> dict:
    items = []
    items.extend(_fetch_raw_events(file_id=file_id))
    items.extend(_fetch_detection_events(file_id=file_id))
    items.extend(_fetch_analysis_detection_events(file_id=file_id))
    items.extend(_fetch_ai_narrative_events(file_id=file_id))

    items = _apply_filters(items, start=start, end=end,
                           severity=severity, event_type=event_type)
    items = _sort_chronologically(items)

    graph = _build_timeline_graph(items, max_nodes=max_nodes)
    return {
        "graph": graph,
        "meta": {
            "file_id": file_id,
            "items_considered": len(items),
            "nodes_returned": len(graph["nodes"]),
            "edges_returned": len(graph["edges"]),
        },
    }


def get_org_timeline_graph(
    org_id: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    max_nodes: int = 160,
) -> dict:
    file_ids = _get_org_file_ids(org_id)

    items = []
    items.extend(_fetch_raw_events(org_id=org_id))
    items.extend(_fetch_detection_events(org_id=org_id))
    for fid in file_ids:
        items.extend(_fetch_analysis_detection_events(file_id=fid))
        items.extend(_fetch_ai_narrative_events(file_id=fid))

    items = _apply_filters(items, start=start, end=end,
                           severity=severity, event_type=event_type)
    items = _sort_chronologically(items)

    graph = _build_timeline_graph(items, max_nodes=max_nodes)
    return {
        "graph": graph,
        "meta": {
            "org_id": org_id,
            "file_count": len(file_ids),
            "items_considered": len(items),
            "nodes_returned": len(graph["nodes"]),
            "edges_returned": len(graph["edges"]),
        },
    }

def _get_org_file_ids(org_id: str) -> list[str]:
    """Get all completed file IDs for an organization."""
    select_candidates = [
        "id",
        "id, status",
    ]

    for select_expr in select_candidates:
        try:
            query = supabase_client.table("log_files").select(select_expr).eq("org_id", org_id)
            if "status" in select_expr:
                query = query.eq("status", "completed")
            result = query.execute()
            rows = result.data or []
            if rows and "status" not in select_expr:
                return [str(r["id"]) for r in rows if r.get("id")]

            if rows:
                return [str(r["id"]) for r in rows if r.get("status") == "completed" and r.get("id")]
        except Exception:
            continue

    return []


def _fetch_raw_events(
    file_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> list[dict]:
    """Fetch raw_logs and convert each to a timeline item."""
    if not file_id and not org_id:
        return []

    select_candidates = [
        "id, payload, file_id, received_at",
        "id, payload, received_at",
        "id, payload, file_id",
        "id, payload",
    ]

    result = None
    for select_expr in select_candidates:
        try:
            query = supabase_client.table("raw_logs").select(select_expr)
            if file_id:
                if "file_id" not in select_expr:
                    continue
                query = query.eq("file_id", file_id)
            elif org_id:
                query = query.eq("org_id", org_id)
            result = query.execute()
            break
        except Exception:
            continue

    if result is None:
        return []

    items = []
    for row in (result.data or []):
        payload_raw = row.get("payload")
        payload = payload_raw if isinstance(payload_raw, dict) else {}

        # Parse timestamp from the payload fields
        ts = parse_timestamp(payload)
        # Fall back to the DB received_at column
        if ts is None and row.get("received_at"):
            ts = parse_iso_string(row["received_at"])

        ts_str = ts.isoformat() if ts else None
        summary = _build_event_summary(payload)

        items.append({
            "id": row["id"],
            "type": "event",
            "timestamp": ts_str,
            "timestamp_parsed": ts is not None,
            "summary": summary,
            "severity": None,
            "source": {
                "table": "raw_logs",
                "id": row["id"],
                "file_id": row.get("file_id"),
            },
            "details": payload if payload else {"raw": payload_raw},
        })
    return items


def _fetch_detection_events(
    file_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> list[dict]:
    """Fetch correlation detections and convert to timeline items."""
    if not file_id and not org_id:
        return []

    select_candidates = [
        "id, org_id, rule_id, file_id, matched_indices, confidence, severity, description, created_at",
        "id, org_id, rule_id, file_id, confidence, created_at",
        "id, org_id, rule_id, confidence",
        "id, org_id, rule_id, event_ids, confidence",
    ]

    result = None
    for select_expr in select_candidates:
        try:
            query = supabase_client.table("detections").select(select_expr)
            if file_id:
                if "file_id" not in select_expr:
                    continue
                query = query.eq("file_id", file_id)
            elif org_id:
                query = query.eq("org_id", org_id)
            result = query.execute()
            break
        except Exception:
            continue

    if result is None:
        return []

    items = []
    for row in (result.data or []):
        ts = parse_iso_string(row.get("created_at"))
        ts_str = ts.isoformat() if ts else None

        matched_indices = row.get("matched_indices")
        if matched_indices is None and row.get("event_ids"):
            matched_indices = []

        items.append({
            "id": row["id"],
            "type": "detection",
            "timestamp": ts_str,
            "timestamp_parsed": ts is not None,
            "summary": row.get("description", "Correlation detection"),
            "severity": row.get("severity"),
            "source": {
                "table": "detections",
                "id": row["id"],
                "file_id": row.get("file_id"),
            },
            "details": {
                "rule_id": row.get("rule_id"),
                "confidence": row.get("confidence"),
                "matched_indices": matched_indices or [],
            },
        })
    return items


def _fetch_ai_narrative_events(file_id: str) -> list[dict]:
    """
    Fetch the AI-generated timeline from analysis_results.
    Each entry in the JSONB array becomes a separate timeline item.
    """
    result = None
    for select_expr in ("id, file_id, timeline", "id, file_id"):
        try:
            result = (
                supabase_client.table("analysis_results")
                .select(select_expr)
                .eq("file_id", file_id)
                .execute()
            )
            break
        except Exception:
            continue

    if result is None:
        return []

    items = []
    for row in (result.data or []):
        timeline_entries = row.get("timeline") or []
        if not isinstance(timeline_entries, list):
            continue
        analysis_id = row["id"]

        for idx, entry in enumerate(timeline_entries):
            if not isinstance(entry, dict):
                continue
            raw_ts = entry.get("timestamp", "")
            ts = parse_iso_string(raw_ts) if raw_ts else None
            # Preserve relative timestamps (e.g. "shortly after") as-is
            ts_str = ts.isoformat() if ts else raw_ts if raw_ts else None

            items.append({
                "id": f"{analysis_id}__narrative_{idx}",
                "type": "ai_narrative",
                "timestamp": ts_str,
                "timestamp_parsed": ts is not None,
                "summary": entry.get("event", ""),
                "severity": None,
                "source": {
                    "table": "analysis_results",
                    "id": analysis_id,
                    "file_id": row.get("file_id"),
                },
                "details": entry,
            })
    return items


def _fetch_analysis_detection_events(file_id: str) -> list[dict]:
    """Fallback detection timeline from analysis_results.correlation_detections JSON."""
    result = None
    for select_expr in (
        "id, file_id, correlation_detections, created_at",
        "id, file_id, correlation_detections",
    ):
        try:
            result = (
                supabase_client.table("analysis_results")
                .select(select_expr)
                .eq("file_id", file_id)
                .execute()
            )
            break
        except Exception:
            continue

    if result is None:
        return []

    items = []
    for row in (result.data or []):
        analysis_id = row.get("id")
        analysis_created_at = row.get("created_at")
        detections = row.get("correlation_detections") or []
        if not isinstance(detections, list):
            continue

        for idx, detection in enumerate(detections):
            if not isinstance(detection, dict):
                continue

            raw_ts = detection.get("detected_at") or detection.get("created_at") or analysis_created_at
            parsed_ts = parse_iso_string(raw_ts) if raw_ts else None
            ts_str = parsed_ts.isoformat() if parsed_ts else (raw_ts if raw_ts else None)

            detection_id = detection.get("detection_id") or f"{analysis_id}__corr_{idx}"
            items.append({
                "id": detection_id,
                "type": "detection",
                "timestamp": ts_str,
                "timestamp_parsed": parsed_ts is not None,
                "summary": detection.get("description") or detection.get("rule_name") or "Correlation detection",
                "severity": detection.get("severity"),
                "source": {
                    "table": "analysis_results.correlation_detections",
                    "id": analysis_id,
                    "file_id": row.get("file_id"),
                },
                "details": {
                    "rule_name": detection.get("rule_name"),
                    "rule_id": detection.get("rule_id"),
                    "mitre_technique": detection.get("mitre_technique"),
                    "confidence": detection.get("confidence"),
                    "matched_indices": detection.get("matched_event_indices") or detection.get("matched_indices") or [],
                },
            })

    return items

def _build_event_summary(payload: dict) -> str:
    """Build a human-readable one-liner from raw log payload fields."""
    parts = []

    user = (payload.get("username") or payload.get("User")
            or payload.get("user"))
    action = (payload.get("action") or payload.get("EventType")
              or payload.get("event_type"))
    result = (payload.get("result") or payload.get("Status")
              or payload.get("status"))
    ip = (payload.get("source_ip") or payload.get("src_ip")
          or payload.get("IpAddress"))

    if user:
        parts.append(str(user))
    if action:
        parts.append(str(action))
    if result:
        parts.append(f"({result})")
    if ip:
        parts.append(f"from {ip}")

    return " ".join(parts) if parts else "Log event"


def _apply_filters(
    items: list[dict],
    start: Optional[str] = None,
    end: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
) -> list[dict]:
    """Apply query parameter filters to the merged timeline."""
    start_dt = parse_iso_string(start) if start else None
    end_dt = parse_iso_string(end) if end else None

    filtered = []
    for item in items:
        # Time range filter
        if start_dt or end_dt:
            item_ts = (parse_iso_string(item["timestamp"])
                       if item.get("timestamp") else None)
            if item_ts is not None:
                if start_dt and item_ts < start_dt:
                    continue
                if end_dt and item_ts > end_dt:
                    continue
            # Items without parseable timestamps are kept (conservative)

        # Severity filter
        if severity:
            if item.get("severity") != severity:
                continue

        # Type filter
        if event_type:
            if item["type"] != event_type:
                continue

        filtered.append(item)
    return filtered


def _sort_chronologically(items: list[dict]) -> list[dict]:
    """Sort items by timestamp. Unparseable timestamps go last."""
    def sort_key(item):
        parsed = _parse_sortable_timestamp(item.get("timestamp"))
        if parsed is not None:
            return (0, parsed)
        return (1, "")

    return sorted(items, key=sort_key)


def _paginate(items: list[dict], page: int, page_size: int) -> list[dict]:
    """Return a page slice of items."""
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    return items[start_idx:end_idx]


def _parse_sortable_timestamp(raw_ts: Optional[str]) -> Optional[str]:
    """Return a normalized UTC ISO timestamp suitable for ordering/comparison."""
    dt = parse_iso_string(raw_ts) if raw_ts else None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def _to_json_safe(value):
    """Recursively normalize values to Flask-JSON-safe primitives."""
    if isinstance(value, dict):
        return {str(key): _to_json_safe(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_to_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_to_json_safe(item) for item in value]
    if isinstance(value, set):
        return [_to_json_safe(item) for item in sorted(value, key=lambda item: str(item))]
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, UUID):
        return str(value)
    return value


def _node_id(item: dict) -> str:
    return f"{item.get('type', 'event')}::{item.get('id', 'unknown')}"


def _node_label(item: dict) -> str:
    summary = str(item.get("summary") or item.get("type") or "timeline item").strip()
    return summary[:96]


def _sample_evenly(items: list[dict], count: int) -> list[dict]:
    """Pick up to count items evenly distributed across the source order."""
    if count <= 0 or not items:
        return []
    if count >= len(items):
        return list(items)
    if count == 1:
        return [items[-1]]

    step = (len(items) - 1) / (count - 1)
    picked = []
    used = set()
    for idx in range(count):
        src_index = int(round(idx * step))
        src_index = min(max(src_index, 0), len(items) - 1)
        if src_index in used:
            continue
        used.add(src_index)
        picked.append(items[src_index])

    if len(picked) < count:
        for src_index, item in enumerate(items):
            if src_index in used:
                continue
            picked.append(item)
            used.add(src_index)
            if len(picked) >= count:
                break

    return picked


def _select_graph_items(items: list[dict], max_nodes: int) -> list[dict]:
    """Select graph items with type balancing to avoid narrative-only graphs."""
    limit = max(1, max_nodes)
    if len(items) <= limit:
        return list(items)

    groups = {
        "event": [item for item in items if item.get("type") == "event"],
        "detection": [item for item in items if item.get("type") == "detection"],
        "ai_narrative": [item for item in items if item.get("type") == "ai_narrative"],
    }
    other_items = [
        item for item in items
        if item.get("type") not in {"event", "detection", "ai_narrative"}
    ]

    present_kinds = [kind for kind in ("event", "detection", "ai_narrative") if groups[kind]]
    base_allocations = {
        "event": int(limit * 0.40),
        "detection": int(limit * 0.35),
        "ai_narrative": int(limit * 0.25),
    }

    allocations = {"event": 0, "detection": 0, "ai_narrative": 0, "other": 0}

    for kind in present_kinds:
        # Reserve at least one node for each present core kind when possible.
        allocations[kind] = 1

    remaining = limit - sum(allocations.values())
    for kind in ("event", "detection", "ai_narrative"):
        if remaining <= 0:
            break
        target = max(base_allocations[kind], allocations[kind])
        cap = len(groups[kind])
        add = min(max(target - allocations[kind], 0), cap - allocations[kind], remaining)
        allocations[kind] += add
        remaining -= add

    if remaining > 0 and other_items:
        add_other = min(len(other_items), remaining)
        allocations["other"] = add_other
        remaining -= add_other

    priority = ["event", "detection", "ai_narrative", "other"]
    while remaining > 0:
        consumed = False
        for kind in priority:
            pool_size = len(other_items) if kind == "other" else len(groups[kind])
            if allocations[kind] >= pool_size:
                continue
            allocations[kind] += 1
            remaining -= 1
            consumed = True
            if remaining <= 0:
                break
        if not consumed:
            break

    selected = []
    selected.extend(_sample_evenly(groups["event"], allocations["event"]))
    selected.extend(_sample_evenly(groups["detection"], allocations["detection"]))
    selected.extend(_sample_evenly(groups["ai_narrative"], allocations["ai_narrative"]))
    selected.extend(_sample_evenly(other_items, allocations["other"]))

    selected_ids = {id(item) for item in selected}
    ordered = [item for item in items if id(item) in selected_ids]
    if len(ordered) > limit:
        ordered = ordered[:limit]
    return ordered


def _build_timeline_graph(items: list[dict], max_nodes: int = 120) -> dict:
    selected_items = _select_graph_items(items, max_nodes)

    # Prevent duplicate node ids when the same detection/event is present from multiple sources.
    seen_node_ids = set()
    limited_items = []
    for item in selected_items:
        node_id = _node_id(item)
        if node_id in seen_node_ids:
            continue
        seen_node_ids.add(node_id)
        limited_items.append(item)

    nodes = []
    edges = []

    for item in limited_items:
        nodes.append({
            "id": _node_id(item),
            "kind": item.get("type"),
            "label": _node_label(item),
            "severity": item.get("severity"),
            "timestamp": item.get("timestamp"),
            "file_id": (item.get("source") or {}).get("file_id"),
        })

    # Link timeline nodes chronologically when timestamps are parseable.
    timestamped_nodes = []
    for item in limited_items:
        sortable_ts = _parse_sortable_timestamp(item.get("timestamp"))
        if sortable_ts:
            timestamped_nodes.append((item, sortable_ts))

    timestamped_nodes.sort(key=lambda pair: pair[1])
    for idx in range(1, len(timestamped_nodes)):
        prev_item = timestamped_nodes[idx - 1][0]
        curr_item = timestamped_nodes[idx][0]
        edges.append({
            "id": f"chronological::{idx}",
            "source": _node_id(prev_item),
            "target": _node_id(curr_item),
            "relation": "chronological",
        })

    # Link correlation detections to matched raw event nodes when indices are available.
    event_items = [item for item in limited_items if item.get("type") == "event"]
    event_by_index = {idx: item for idx, item in enumerate(event_items)}
    edge_counter = len(edges)

    for detection_item in (item for item in limited_items if item.get("type") == "detection"):
        details = detection_item.get("details") or {}
        matched_indices = details.get("matched_indices") or []
        for matched_idx in matched_indices[:20]:
            linked_event = event_by_index.get(matched_idx)
            if not linked_event:
                continue
            edge_counter += 1
            edges.append({
                "id": f"evidence::{edge_counter}",
                "source": _node_id(detection_item),
                "target": _node_id(linked_event),
                "relation": "matched_event",
            })

    # Link AI narrative nodes to nearest prior event/detection by time.
    narrative_items = [item for item in limited_items if item.get("type") == "ai_narrative"]
    evidence_items = [item for item in limited_items if item.get("type") in {"event", "detection"}]
    evidence_with_time = []
    for item in evidence_items:
        sortable_ts = _parse_sortable_timestamp(item.get("timestamp"))
        if sortable_ts:
            evidence_with_time.append((item, sortable_ts))
    evidence_with_time.sort(key=lambda pair: pair[1])

    for narrative in narrative_items:
        narrative_ts = _parse_sortable_timestamp(narrative.get("timestamp") or "")
        if not narrative_ts:
            continue
        previous = [pair for pair in evidence_with_time if pair[1] <= narrative_ts]
        if not previous:
            continue
        source_item = previous[-1][0]
        edge_counter += 1
        edges.append({
            "id": f"narrative::{edge_counter}",
            "source": _node_id(source_item),
            "target": _node_id(narrative),
            "relation": "narrative_context",
        })

    return {
        "nodes": nodes,
        "edges": edges,
    }
