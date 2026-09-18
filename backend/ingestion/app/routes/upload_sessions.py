"""Route implementations for the ingestion service."""

import time
from contextlib import suppress
from datetime import datetime, timezone
from uuid import uuid4

from flask import jsonify, request

from . import main, supabase_client
from .constants import (
    BUCKET_NAME,
    MAX_UPLOAD_PART_BYTES,
    MAX_UPLOAD_SESSIONS,
    MAX_UPLOAD_SESSION_ASSEMBLY_BYTES,
)
from .utils import (
    _auth_user_id,
    _create_background_analysis_job_internal,
    _enforce_org_scope,
    _error_response,
    _evict_expired_sessions,
    _get_request_id,
    _persist_upload_manifest,
    _request_logger,
    _require_roles,
    _upload_sessions,
    _upload_sessions_lock,
    upload_binary,
)

@main.route("/upload-sessions/init", methods=["POST"])
def init_upload_session():
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get("org_id"))
    if org_scope_error:
        return org_scope_error
    filename = payload.get("filename")
    source_type = payload.get("source_type")
    total_parts = payload.get("total_parts")

    if not filename or not source_type:
        return _error_response(
            "filename and source_type are required", 400, "VALIDATION_ERROR"
        )

    if source_type not in {"windows", "firewall", "auth", "syslog", "custom"}:
        return _error_response(
            "source_type must be one of: windows, firewall, auth, syslog, custom",
            400,
            "VALIDATION_ERROR",
        )

    if total_parts is not None:
        try:
            total_parts = int(total_parts)
        except (TypeError, ValueError):
            return _error_response(
                "total_parts must be an integer when provided", 400, "VALIDATION_ERROR"
            )
        if total_parts <= 0:
            return _error_response(
                "total_parts must be greater than 0", 400, "VALIDATION_ERROR"
            )

    session_id = str(uuid4())
    session_prefix = f"{org_id}/upload_sessions/{session_id}"

    session = {
        "session_id": session_id,
        "session_prefix": session_prefix,
        "org_id": org_id,
        "filename": filename,
        "source_type": source_type,
        "status": "initiated",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_at_ts": time.time(),
        "total_parts": total_parts,
        "parts": {},
        "part_sizes": {},
        "received_parts": set(),
        "assembled_path": None,
        "job_id": None,
        "manifest_path": None,
    }

    with _upload_sessions_lock:
        _evict_expired_sessions()
        if len(_upload_sessions) >= MAX_UPLOAD_SESSIONS:
            return _error_response(
                "Too many active upload sessions. Please try again later.",
                429,
                "RATE_LIMIT",
                retryable=True,
            )
        _upload_sessions[session_id] = session

    try:
        _persist_upload_manifest(session)
    except Exception:
        log = _request_logger(
            route="init_upload_session", org_id=org_id, filename=filename
        )
        log.exception("Failed to initialize upload session manifest")
        return _error_response(
            "Failed to initialize upload session manifest",
            500,
            "STORAGE_ERROR",
            retryable=True,
            details={
                "storage_error": "Internal storage error",
                "session_prefix": session_prefix,
            },
        )

    return jsonify(
        {
            "session_id": session_id,
            "status": session["status"],
            "manifest_path": session["manifest_path"],
            "request_id": _get_request_id(),
        }
    ), 201


@main.route("/upload-sessions/upload-part", methods=["POST"])
def upload_session_part():
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error
    session_id = request.form.get("session_id")
    part_number_raw = request.form.get("part_number")
    log = _request_logger(route="upload_session_part", session_id=session_id)

    if not session_id or not part_number_raw:
        return _error_response(
            "session_id and part_number are required", 400, "VALIDATION_ERROR"
        )

    try:
        part_number = int(part_number_raw)
    except ValueError:
        return _error_response(
            "part_number must be an integer", 400, "VALIDATION_ERROR"
        )
    if part_number <= 0:
        return _error_response(
            "part_number must be greater than 0", 400, "VALIDATION_ERROR"
        )

    if "file" not in request.files:
        return _error_response("file part is required", 400, "VALIDATION_ERROR")
    part_file = request.files["file"]
    part_bytes = part_file.read()
    if not part_bytes:
        return _error_response("part payload is empty", 400, "VALIDATION_ERROR")

    if len(part_bytes) > MAX_UPLOAD_PART_BYTES:
        return _error_response(
            f"Part exceeds max size of {MAX_UPLOAD_PART_BYTES} bytes",
            413,
            "PAYLOAD_TOO_LARGE",
            retryable=False,
        )

    with _upload_sessions_lock:
        _evict_expired_sessions()
        session = _upload_sessions.get(session_id)
        if not session:
            return _error_response("Upload session expired or not found", 410, "GONE")
        _, org_scope_error = _enforce_org_scope(session.get("org_id"))
        if org_scope_error:
            return org_scope_error
        if session.get("status") == "completed":
            return _error_response("Upload session already completed", 409, "CONFLICT")

        part_path = f"{session['session_prefix']}/parts/{part_number:08d}.part"
        try:
            upload_binary(
                path=part_path,
                file_bytes=part_bytes,
                bucket_name=BUCKET_NAME,
                content_type="application/octet-stream",
            )
        except Exception:
            log.exception(
                "Failed to store upload part",
                part_path=part_path,
                part_number=part_number,
                session_id=session_id,
            )
            return _error_response(
                "Failed to store upload part",
                500,
                "STORAGE_ERROR",
                retryable=True,
                details={
                    "storage_error": "Internal storage error",
                    "part_path": part_path,
                    "part_number": part_number,
                },
            )

        session["parts"][part_number] = part_path
        session["part_sizes"][part_number] = len(part_bytes)
        session["received_parts"].add(part_number)
        session["status"] = "uploading"

        try:
            _persist_upload_manifest(session)
        except Exception:
            log.exception("Failed to update upload manifest", session_id=session_id)
            return _error_response(
                "Failed to update upload manifest",
                500,
                "STORAGE_ERROR",
                retryable=True,
                details={
                    "storage_error": "Internal storage error",
                    "session_id": session_id,
                },
            )

        total_parts = session.get("total_parts")
        received_count = len(session["received_parts"])
        progress_pct = None
        if total_parts:
            progress_pct = round((received_count / total_parts) * 100, 2)

    return jsonify(
        {
            "session_id": session_id,
            "part_number": part_number,
            "received_parts": received_count,
            "total_parts": total_parts,
            "progress_pct": progress_pct,
            "request_id": _get_request_id(),
        }
    ), 201


@main.route("/upload-sessions/complete", methods=["POST"])
def complete_upload_session():
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}
    session_id = payload.get("session_id")
    requested_by = _auth_user_id() or payload.get("requested_by")
    log = _request_logger(route="complete_upload_session", session_id=session_id)

    if not session_id:
        return _error_response("session_id is required", 400, "VALIDATION_ERROR")

    with _upload_sessions_lock:
        _evict_expired_sessions()
        session = _upload_sessions.get(session_id)
        if not session:
            return _error_response("Upload session expired or not found", 410, "GONE")
        _, org_scope_error = _enforce_org_scope(session.get("org_id"))
        if org_scope_error:
            return org_scope_error
        if session.get("status") == "completed":
            return jsonify(
                {
                    "session_id": session_id,
                    "status": "completed",
                    "assembled_path": session.get("assembled_path"),
                    "job_id": session.get("job_id"),
                    "request_id": _get_request_id(),
                }
            ), 200

        total_parts = session.get("total_parts")
        received_parts = session.get("received_parts", set())
        if total_parts and len(received_parts) != total_parts:
            return _error_response(
                f"Upload incomplete: expected {total_parts} parts, received {len(received_parts)}",
                409,
                "UPLOAD_INCOMPLETE",
            )

        ordered_parts = sorted(session["parts"].keys())
        if not ordered_parts:
            return _error_response(
                "No parts uploaded for this session", 409, "UPLOAD_INCOMPLETE"
            )

        expected = list(range(1, len(ordered_parts) + 1))
        if ordered_parts != expected:
            return _error_response(
                "Missing part numbers; parts must be contiguous starting at 1",
                409,
                "UPLOAD_INCOMPLETE",
            )

        total_bytes = sum(session["part_sizes"].get(pn, 0) for pn in ordered_parts)
        if total_bytes > MAX_UPLOAD_SESSION_ASSEMBLY_BYTES:
            return _error_response(
                f"Combined upload size exceeds assembly limit of {MAX_UPLOAD_SESSION_ASSEMBLY_BYTES} bytes",
                413,
                "PAYLOAD_TOO_LARGE",
                retryable=False,
            )

        org_id = session["org_id"]
        filename = session["filename"]
        source_type = session["source_type"]
        manifest_path = session.get("manifest_path")

    if not manifest_path:
        return _error_response(
            "Upload manifest path missing for session",
            500,
            "STORAGE_ERROR",
            retryable=True,
        )

    try:
        job_id, item_id = _create_background_analysis_job_internal(
            org_id=org_id,
            filename=filename,
            source_type=source_type,
            requested_by=requested_by,
            output_path=manifest_path,
        )
    except ValueError:
        log.exception("Validation error creating analysis job after assembly")
        return _error_response("Invalid request parameters", 400, "VALIDATION_ERROR")
    except Exception:
        return _error_response(
            "File assembled, but failed to create analysis job",
            500,
            "DATABASE_ERROR",
            retryable=True,
        )

    with _upload_sessions_lock:
        session["assembled_path"] = manifest_path
        session["job_id"] = job_id
        session["status"] = "completed"
        with suppress(Exception):
            _persist_upload_manifest(session)

    return jsonify(
        {
            "session_id": session_id,
            "status": "completed",
            "assembled_path": manifest_path,
            "job_id": job_id,
            "item_id": item_id,
            "request_id": _get_request_id(),
        }
    ), 202


