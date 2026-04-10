from datetime import datetime
from typing import Optional

_TS_FIELDS = ("timestamp", "Timestamp", "time", "Time", "datetime", "received_at")
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
)

def parse_iso_string(raw: str) -> Optional[datetime]: #ISO 8601 only parser for strict timestamp fields
    if not raw:
        return None

    if isinstance(raw, datetime):
        return raw

    raw_text = str(raw)
    try:
        return datetime.fromisoformat(raw_text.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        pass
    return None


def parse_timestamp(entry: dict) -> Optional[datetime]:
    raw = None
    for field in _TS_FIELDS:
        if field in entry and entry[field]:
            raw = str(entry[field])
            break
    if raw is None:
        return None

    #ISO 8601
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt
    except (ValueError, TypeError):
        pass

    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except (ValueError, TypeError):
            continue
    return None
