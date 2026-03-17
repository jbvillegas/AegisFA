from typing import Optional

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
    items.extend(_fetch_ai_narrative_events(file_id=file_id))

    items = _apply_filters(items, start=start, end=end,
                           severity=severity, event_type=event_type)
    items = _sort_chronologically(items)

    total = len(items)
    paginated = _paginate(items, page, page_size)

    return {
        "items": paginated,
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
        items.extend(_fetch_ai_narrative_events(file_id=fid))

    items = _apply_filters(items, start=start, end=end,
                           severity=severity, event_type=event_type)
    items = _sort_chronologically(items)

    total = len(items)
    paginated = _paginate(items, page, page_size)

    return {
        "items": paginated,
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

def _get_org_file_ids(org_id: str) -> list[str]:
    """Get all completed file IDs for an organization."""
    result = (
        supabase_client.table("log_files")
        .select("id")
        .eq("org_id", org_id)
        .eq("status", "completed")
        .execute()
    )
    return [r["id"] for r in (result.data or [])]


def _fetch_raw_events(
    file_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> list[dict]:
    """Fetch raw_logs and convert each to a timeline item."""
    query = supabase_client.table("raw_logs").select(
        "id, payload, file_id, received_at"
    )

    if file_id:
        query = query.eq("file_id", file_id)
    elif org_id:
        query = query.eq("org_id", org_id)
    else:
        return []

    result = query.execute()
    items = []
    for row in (result.data or []):
        payload = row.get("payload") or {}

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
            "details": payload,
        })
    return items


def _fetch_detection_events(
    file_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> list[dict]:
    """Fetch correlation detections and convert to timeline items."""
    query = supabase_client.table("detections").select(
        "id, org_id, rule_id, file_id, matched_indices, "
        "confidence, severity, description, created_at"
    )

    if file_id:
        query = query.eq("file_id", file_id)
    elif org_id:
        query = query.eq("org_id", org_id)
    else:
        return []

    result = query.execute()
    items = []
    for row in (result.data or []):
        ts = parse_iso_string(row.get("created_at"))
        ts_str = ts.isoformat() if ts else None

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
                "matched_indices": row.get("matched_indices"),
            },
        })
    return items


def _fetch_ai_narrative_events(file_id: str) -> list[dict]:
    """
    Fetch the AI-generated timeline from analysis_results.
    Each entry in the JSONB array becomes a separate timeline item.
    """
    result = (
        supabase_client.table("analysis_results")
        .select("id, file_id, timeline")
        .eq("file_id", file_id)
        .execute()
    )

    items = []
    for row in (result.data or []):
        timeline_entries = row.get("timeline") or []
        analysis_id = row["id"]

        for idx, entry in enumerate(timeline_entries):
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
        ts = item.get("timestamp")
        if ts:
            dt = parse_iso_string(ts)
            if dt:
                return (0, dt.isoformat())
        return (1, "")

    return sorted(items, key=sort_key)


def _paginate(items: list[dict], page: int, page_size: int) -> list[dict]:
    """Return a page slice of items."""
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    return items[start_idx:end_idx]
