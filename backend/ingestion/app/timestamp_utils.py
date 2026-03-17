"""
Shared timestamp parsing utilities for AegisFA.
Used by: correlation_engine, timeline_service
"""

from datetime import datetime
from typing import Optional

TS_FIELDS = (
    "timestamp", "Timestamp", "time", "Time",
    "datetime", "received_at",
)

TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
)


def parse_timestamp(entry: dict) -> Optional[datetime]:
    """
    Extract and parse a timestamp from a log entry dict.
    Tries common field names and multiple datetime formats.
    """
    raw = None
    for field in TS_FIELDS:
        if field in entry and entry[field]:
            raw = str(entry[field])
            break
    if raw is None:
        return None

    return parse_iso_string(raw)


def parse_iso_string(iso_str: str) -> Optional[datetime]:
    """
    Parse an ISO 8601 or common datetime string directly.
    Used for query param parsing and database timestamp fields.
    """
    if not iso_str:
        return None

    try:
        return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        pass

    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(iso_str, fmt)
        except (ValueError, TypeError):
            continue

    return None
