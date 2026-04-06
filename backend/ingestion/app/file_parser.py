import csv
import io
import json
import os
from typing import Any

ENCODINGS_TO_TRY = ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1")
MAX_BYTES = 10 * 1024 * 1024
MAX_ROWS = 200_000

def _decode_bytes(file_bytes: bytes) -> tuple[str, str]:
    if len(file_bytes) > MAX_BYTES:
        raise ValueError(f"File too large ({len(file_bytes)} bytes). Max is {MAX_BYTES}.")
    
    for enc in ENCODINGS_TO_TRY:
        try:
            return file_bytes.decode(enc), enc
        except UnicodeDecodeError:
            continue

    raise ValueError("Unable to decode file with supported encodings.")

def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    try:
        json.loads(text[:4096])
        return True
    except json.JSONDecodeError:
        # Could be NDJSON — check first line
        first_line = stripped.splitlines()[0]
        try:
            json.loads(first_line)
            return True
        except json.JSONDecodeError:
            return False

def _looks_like_csv(text: str) -> tuple[bool, Any]:
    sample = text[:16384] 
    try:
        dialect = csv.Sniffer().sniff(sample)
        if dialect.delimiter not in {",", ";", "\t", "|"}:
            return False, None
       
        reader = csv.reader(io.StringIO(sample), dialect=dialect)
        row_lengths = [len(row) for _, row in zip(range(10), reader)]
        if len(set(row_lengths)) == 1 and row_lengths[0] > 1:
            return True, dialect
        return False, None
    except csv.Error:
        return False, None
    
def _looks_like_ndjson(text: str) -> bool:
    lines = [l.strip() for l in text.splitlines() if l.strip()][:20]
    if len(lines) < 2:
        return False
    valid = sum(1 for l in lines if _is_json_object_or_array(l))
    return valid / len(lines) >= 0.8 

def _is_json_object_or_array(line: str) -> bool:
    try:
        parsed = json.loads(line)
        return isinstance(parsed, (dict, list))
    except json.JSONDecodeError:
        return False

def detect_format(filename: str, content: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    scores = {"json": 0, "csv": 0, "text": 0}

    ext_hints = {".json": "json", ".csv": "csv", ".txt": "text", ".log": "text", ".tsv": "csv", ".ndjson": "json"}
    if ext in ext_hints:
        scores[ext_hints[ext]] += 1

    if _looks_like_json(content):
        scores["json"] += 2
    
    looks_csv, dialect = _looks_like_csv(content)
    if looks_csv:
        scores["csv"] += 2

    if _looks_like_ndjson(content):
        scores["json"] += 2

    # Extension contradicts content — warn but trust content
    winner = max(scores, key=lambda k: scores[k])
    if ext in ext_hints and ext_hints[ext] != winner:
        # caller can receive this via warnings if you pass a list in
        pass

    return winner


def _coerce_to_dict_entries(items: list[Any]) -> list[dict]:
    out = []
    for i, item in enumerate(items, start=1):
        if isinstance(item, dict):
            out.append(item)
        else:
            out.append({"value": item, "line_number": i})
    return out


def _parse_csv(content: str) -> tuple[list[dict], list[str]]:
    sample = content[:4096]
    warnings = []

    try:
        dialect = csv.Sniffer().sniff(sample)
        if dialect.delimiter not in {",", ";", "\t", "|"}:
            warnings.append(f"Unusual CSV delimiter detected: {repr(dialect.delimiter)}")
    except csv.Error:
        dialect = csv.excel
        warnings.append("Could not detect CSV dialect, falling back to comma-delimited.")

    reader = csv.DictReader(io.StringIO(content), dialect=dialect)
    rows = []

    for i, row in enumerate(reader, start=1):
        if i >= MAX_ROWS:
            raise ValueError(f"CSV row limit exceeded ({MAX_ROWS}).")
        rows.append(dict(row))

    if not reader.fieldnames:
        warnings.append("CSV detected but no header row found.")

    return rows, warnings


def _parse_json_or_ndjson(content: str) -> tuple[list[dict], list[str]]:
    warnings = []
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            if len(parsed) > MAX_ROWS:
                raise ValueError(f"JSON array row limit exceeded ({MAX_ROWS}).")
            return _coerce_to_dict_entries(parsed), warnings
        if isinstance(parsed, dict):
            return [parsed], warnings
        return [{"value": parsed}], ["Top-level JSON was not an object/array."]
    except json.JSONDecodeError:
        entries = []
        bad_lines = []

        for i, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                parsed_line = json.loads(line)
                if isinstance(parsed_line, dict):
                    entries.append(parsed_line)
                else:
                    entries.append({"value": parsed_line, "line_number": i})
            except json.JSONDecodeError:
                bad_lines.append(i)

            if len(entries) > MAX_ROWS:
                raise ValueError(f"NDJSON row limit exceeded ({MAX_ROWS}).")

        if not entries:
            raise ValueError("File is not valid JSON or NDJSON.")

        if bad_lines:
            warnings.append(
                f"Skipped {len(bad_lines)} invalid NDJSON lines. "
                f"Sample line numbers: {bad_lines[:10]}"
            )

        return entries, warnings

def _parse_text(content: str) -> tuple[list[dict], list[str]]:
    rows = []
    for i, line in enumerate(content.splitlines(), start=1):
        cleaned = line.strip()
        if not cleaned:
            continue
        if len(rows) >= MAX_ROWS:
            raise ValueError(f"Text line limit exceeded ({MAX_ROWS}).")
        rows.append({"line_number": i, "raw_line": cleaned})
    return rows, []


def parse_file_with_metadata(file_bytes: bytes, filename: str) -> dict:
    """
    Returns:
    {
      "entries": [...],
      "metadata": {
        "filename": str,
        "detected_format": "json|csv|text",
        "detected_encoding": str,
        "entry_count": int,
        "warnings": [str, ...]
      }
    }
    """
    content, encoding = _decode_bytes(file_bytes)
    file_format = detect_format(filename, content)

    if file_format == "csv":
        entries, warnings = _parse_csv(content)
    elif file_format == "json":
        entries, warnings = _parse_json_or_ndjson(content)
    else:
        entries, warnings = _parse_text(content)

    return {
        "entries": entries,
        "metadata": {
            "filename": filename,
            "detected_format": file_format,
            "detected_encoding": encoding,
            "entry_count": len(entries),
            "warnings": warnings,
        },
    }

def parse_file(file_bytes: bytes, filename: str) -> list[dict]:
    return parse_file_with_metadata(file_bytes, filename)["entries"]