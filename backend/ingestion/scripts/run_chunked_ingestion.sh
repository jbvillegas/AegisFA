#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <file_path> <org_id> [source_type] [chunk_size_bytes]"
  echo "Example: $0 assets/DrDoS_DNS_data_1_per.csv 21332a8b-8f9e-4551-a51d-f356df34863d custom 8388608"
  exit 1
fi

FILE_PATH="$1"
ORG_ID="$2"
SOURCE_TYPE="${3:-custom}"
CHUNK_SIZE_BYTES="${4:-8388608}"
API_BASE_URL="${API_BASE_URL:-http://localhost:5007}"

if [[ ! -f "$FILE_PATH" ]]; then
  echo "File not found: $FILE_PATH"
  exit 1
fi

FILE_NAME="$(basename "$FILE_PATH")"
WORK_DIR="$(mktemp -d)"
CHUNK_PREFIX="$WORK_DIR/part_"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

json_get() {
  local file_path="$1"
  local json_path="$2"
  python3 - "$file_path" "$json_path" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
json_path = sys.argv[2]
value = json.loads(path.read_text(encoding='utf-8'))
for part in json_path.split('.'):
    value = value[part]
print(value)
PY
}

echo "Splitting $FILE_NAME into $CHUNK_SIZE_BYTES byte chunks..."
split -b "$CHUNK_SIZE_BYTES" -d -a 5 "$FILE_PATH" "$CHUNK_PREFIX"

mapfile -t PART_FILES < <(find "$WORK_DIR" -maxdepth 1 -type f -name 'part_*' | sort)
TOTAL_PARTS="${#PART_FILES[@]}"

if [[ "$TOTAL_PARTS" -eq 0 ]]; then
  echo "No chunk files were created."
  exit 1
fi

echo "Created $TOTAL_PARTS parts. Initializing upload session..."
INIT_RESPONSE="$WORK_DIR/init.json"
curl -sS -X POST "$API_BASE_URL/upload-sessions/init" \
  -H "Content-Type: application/json" \
  -d "$(python3 - <<PY
import json
print(json.dumps({
    'org_id': '$ORG_ID',
    'filename': '$FILE_NAME',
    'source_type': '$SOURCE_TYPE',
    'total_parts': $TOTAL_PARTS,
}))
PY
)" > "$INIT_RESPONSE"

SESSION_ID="$(json_get "$INIT_RESPONSE" session_id)"

echo "Session: $SESSION_ID"
echo "Uploading parts..."

for idx in "${!PART_FILES[@]}"; do
  part_number=$((idx + 1))
  part_file="${PART_FILES[$idx]}"
  curl -sS -X POST "$API_BASE_URL/upload-sessions/upload-part" \
    -F "session_id=$SESSION_ID" \
    -F "part_number=$part_number" \
    -F "file=@$part_file" >/dev/null
  echo "Uploaded part $part_number/$TOTAL_PARTS"
done

echo "Completing session..."
COMPLETE_RESPONSE="$WORK_DIR/complete.json"
curl -sS -X POST "$API_BASE_URL/upload-sessions/complete" \
  -H "Content-Type: application/json" \
  -d "$(python3 - <<PY
import json
print(json.dumps({
    'session_id': '$SESSION_ID',
}))
PY
)" > "$COMPLETE_RESPONSE"

JOB_ID="$(json_get "$COMPLETE_RESPONSE" job_id)"

echo "Job queued: $JOB_ID"
echo "Polling job status..."

while true; do
  JOB_RESPONSE_FILE="$WORK_DIR/job.json"
  curl -sS "$API_BASE_URL/analysis-jobs/$JOB_ID" > "$JOB_RESPONSE_FILE"
  STATUS="$(json_get "$JOB_RESPONSE_FILE" job.status)"
  PROGRESS="$(json_get "$JOB_RESPONSE_FILE" job.progress_pct)"

  echo "Status: $STATUS ($PROGRESS%)"

  if [[ "$STATUS" == "completed" ]]; then
    python3 -m json.tool "$JOB_RESPONSE_FILE"
    break
  fi

  if [[ "$STATUS" == "failed" ]]; then
    python3 -m json.tool "$JOB_RESPONSE_FILE"
    exit 1
  fi

  sleep 10
done