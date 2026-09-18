"""Route implementations for the ingestion service."""

import json
from datetime import datetime, timezone
from flask import Response, jsonify, request, stream_with_context
from . import main, supabase_client
from .utils import *  # noqa: F401,F403

def _to_sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _progress_event(step: str, message: str, progress_pct: int, **extra):
    payload = {
        "step": step,
        "message": message,
        "progress_pct": progress_pct,
        "request_id": _get_request_id(),
    }
    payload.update(extra)
    return payload


@main.route("/ingest", methods=["POST"])
def ingest():
    log = _request_logger(route="ingest")
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error
    data = request.get_json()
    if not data:
        return _error_response("JSON body required", 400, "VALIDATION_ERROR")

    source = data.get("source")
    raw_data = data.get("raw_data")
    timestamp = data.get("timestamp", datetime.now(timezone.utc).isoformat())
    org_id, org_scope_error = _enforce_org_scope(data.get("org_id"))
    if org_scope_error:
        return org_scope_error

    if not source or raw_data is None:
        return _error_response(
            "source and raw_data are required", 400, "VALIDATION_ERROR"
        )

    try:
        raw_result = (
            supabase_client.table("raw_logs")
            .insert(
                {
                    "org_id": org_id,
                    "source_id": data.get("source_id"),
                    "payload": raw_data,
                    "received_at": timestamp,
                }
            )
            .execute()
        )
    except Exception:
        log.exception("Failed to store raw log")
        return _error_response(
            "Failed to store raw log", 500, "DATABASE_ERROR", retryable=True
        )

    if not raw_result.data:
        return _error_response(
            "Failed to store raw log", 500, "DATABASE_ERROR", retryable=True
        )

    raw_log_id = raw_result.data[0]["id"]

    normalized = normalize_log(source, raw_data)
    try:
        norm_result = (
            supabase_client.table("normalized_events")
            .insert(
                {
                    "org_id": org_id,
                    "raw_log_id": raw_log_id,
                    "source_id": data.get("source_id"),
                    "event_type": normalized.get("action"),
                    "severity": normalized.get("status"),
                }
            )
            .execute()
        )
    except Exception:
        log.exception("Failed to store normalized event", raw_log_id=raw_log_id)
        return _error_response(
            "Failed to store normalized event", 500, "DATABASE_ERROR", retryable=True
        )

    if not norm_result.data:
        return _error_response(
            "Failed to store normalized event", 500, "DATABASE_ERROR", retryable=True
        )

    return jsonify(
        {
            "raw_log_id": raw_log_id,
            "normalized_event_id": norm_result.data[0]["id"],
            "normalized_data": normalized,
            "request_id": _get_request_id(),
        }
    ), 201


@main.route("/upload", methods=["POST"])
def upload_log_file():
    log = _request_logger(route="upload_log_file")
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error

    if "file" not in request.files:
        return _error_response("No file provided", 400, "VALIDATION_ERROR")

    file = request.files["file"]
    source_type = request.form.get("source_type")
    org_id, org_scope_error = _enforce_org_scope(request.form.get("org_id"))
    if org_scope_error:
        return org_scope_error
    log = log.bind(org_id=org_id, filename=file.filename)

    if not source_type or source_type not in {
        "windows",
        "firewall",
        "auth",
        "syslog",
        "custom",
    }:
        return _error_response(
            "source_type must be one of: windows, firewall, auth, syslog, custom",
            400,
            "VALIDATION_ERROR",
        )

    file_bytes = file.read()

    try:
        entries = parse_file(file_bytes, file.filename)
    except Exception:
        log.exception("Failed to parse file")
        return _error_response("Failed to parse file", 400, "PARSING_ERROR")

    try:
        storage_path = upload_file(file_bytes, file.filename, org_id)
    except Exception:
        log.exception("Failed to upload file to storage")
        return _error_response(
            "Failed to upload file to storage", 500, "STORAGE_ERROR", retryable=True
        )

    try:
        file_record = (
            supabase_client.table("log_files")
            .insert(
                {
                    "filename": file.filename,
                    "org_id": org_id,
                    "source_type": source_type,
                    "storage_path": storage_path,
                    "status": "analyzing",
                    "entry_count": len(entries),
                }
            )
            .execute()
        )

        file_id = file_record.data[0]["id"]
        log = log.bind(file_id=file_id)
    except Exception:
        log.exception("Failed to save file record")
        return _error_response(
            "Failed to save file record", 500, "DATABASE_ERROR", retryable=True
        )

    try:
        _insert_raw_logs_in_batches(entries, org_id, file_id)
    except Exception:
        supabase_client.table("log_files").update({"status": "failed"}).eq(
            "id", file_id
        ).execute()
        log.exception("Failed to store log entries")
        return _error_response(
            "Failed to store log entries", 500, "DATABASE_ERROR", retryable=True
        )

    try:
        pipeline_result = run_analysis_pipeline(
            entries,
            org_id,
            file_id,
            source_type,
            request_id=_get_request_id(),
            log=log,
        )
        detections = pipeline_result["detections"]
        rf_results = pipeline_result["rf_results"]
        analysis = pipeline_result["analysis"]
    except Exception:
        supabase_client.table("log_files").update({"status": "failed"}).eq(
            "id", file_id
        ).execute()
        log.exception("Threat analysis failed")
        return _error_response(
            "Threat analysis failed", 500, "ANALYSIS_ERROR", retryable=True
        )

    try:
        _store_analysis_result(
            file_id=file_id,
            org_id=org_id,
            analysis=analysis,
            detections=detections,
        )
    except Exception:
        supabase_client.table("log_files").update({"status": "failed"}).eq(
            "id", file_id
        ).execute()
        log.exception("Failed to store analysis")
        return _error_response(
            "Failed to store analysis", 500, "DATABASE_ERROR", retryable=True
        )

    supabase_client.table("log_files").update({"status": "completed"}).eq(
        "id", file_id
    ).execute()

    try:
        actionable_insights = _build_actionable_insights_payload(
            threats=analysis.get("detailed_findings", []),
            detections=detections,
            logs=entries,
            source_type=source_type,
            rf_results=rf_results,
        )
    except Exception:
        log.exception("Failed to generate actionable insights")
        actionable_insights = {
            "status": "error",
            "message": "Failed to generate actionable insights",
        }

    return jsonify(
        {
            "file_id": file_id,
            "filename": file.filename,
            "entry_count": len(entries),
            "detections": detections,
            "detection_count": len(detections),
            "analysis": {
                "threat_level": analysis["threat_level"],
                "threats_found": analysis["threats_found"],
                "summary": analysis["summary"],
                "mitre_techniques": analysis.get("mitre_techniques"),
                "attack_vector": analysis.get("attack_vector"),
                "confidence_score": analysis.get("confidence_score"),
            },
            "actionable_insights": actionable_insights,
            "request_id": _get_request_id(),
        }
    ), 201


@main.route("/upload/stream", methods=["POST"])
def upload_log_file_stream():
    """Upload and analyze a file while streaming progress updates via SSE."""

    def _stream():
        log = _request_logger(route="upload_log_file_stream")
        file_id = None

        role_error = _require_roles("admin", "analyst")
        if role_error:
            yield _to_sse(
                "error",
                _progress_event(
                    "forbidden",
                    "Insufficient role permissions for this endpoint",
                    0,
                    error_code="FORBIDDEN",
                ),
            )
            return

        if "file" not in request.files:
            yield _to_sse(
                "error",
                _progress_event(
                    "validation_failed",
                    "No file provided",
                    0,
                    error_code="VALIDATION_ERROR",
                ),
            )
            return

        file = request.files["file"]
        source_type = request.form.get("source_type")
        org_id, org_scope_error = _enforce_org_scope(request.form.get("org_id"))
        if org_scope_error:
            yield _to_sse(
                "error",
                _progress_event(
                    "forbidden",
                    "Cross-organization access denied",
                    0,
                    error_code="FORBIDDEN",
                ),
            )
            return
        log = log.bind(org_id=org_id, filename=file.filename)

        if not source_type or source_type not in {
            "windows",
            "firewall",
            "auth",
            "syslog",
            "custom",
        }:
            yield _to_sse(
                "error",
                _progress_event(
                    "validation_failed",
                    "source_type must be one of: windows, firewall, auth, syslog, custom",
                    0,
                    error_code="VALIDATION_ERROR",
                ),
            )
            return

        file_bytes = file.read()
        yield _to_sse(
            "progress",
            _progress_event("file_received", "File received. Parsing log entries.", 5),
        )

        try:
            entries = parse_file(file_bytes, file.filename)
            yield _to_sse(
                "progress",
                _progress_event(
                    "parsed", "File parsed successfully.", 15, entry_count=len(entries)
                ),
            )
        except Exception:
            log.exception("Failed to parse file")
            yield _to_sse(
                "error",
                _progress_event(
                    "parsing_failed",
                    "Failed to parse file",
                    15,
                    error_code="PARSING_ERROR",
                ),
            )
            return

        try:
            storage_path = upload_file(file_bytes, file.filename, org_id)
            yield _to_sse(
                "progress",
                _progress_event(
                    "uploaded",
                    "Uploaded file to storage.",
                    25,
                    storage_path=storage_path,
                ),
            )
        except Exception:
            log.exception("Failed to upload file to storage")
            yield _to_sse(
                "error",
                _progress_event(
                    "storage_failed",
                    "Failed to upload file to storage",
                    25,
                    error_code="STORAGE_ERROR",
                ),
            )
            return

        try:
            file_record = (
                supabase_client.table("log_files")
                .insert(
                    {
                        "filename": file.filename,
                        "org_id": org_id,
                        "source_type": source_type,
                        "storage_path": storage_path,
                        "status": "analyzing",
                        "entry_count": len(entries),
                    }
                )
                .execute()
            )
            file_id = file_record.data[0]["id"]
            log = log.bind(file_id=file_id)
            yield _to_sse(
                "progress",
                _progress_event(
                    "file_record_created", "Created file record.", 35, file_id=file_id
                ),
            )
        except Exception:
            log.exception("Failed to save file record")
            yield _to_sse(
                "error",
                _progress_event(
                    "database_failed",
                    "Failed to save file record",
                    35,
                    error_code="DATABASE_ERROR",
                ),
            )
            return

        try:
            _insert_raw_logs_in_batches(entries, org_id, file_id)
            yield _to_sse(
                "progress",
                _progress_event("entries_stored", "Stored parsed entries.", 50),
            )
        except Exception:
            if file_id:
                supabase_client.table("log_files").update({"status": "failed"}).eq(
                    "id", file_id
                ).execute()
            log.exception("Failed to store log entries")
            yield _to_sse(
                "error",
                _progress_event(
                    "database_failed",
                    "Failed to store log entries",
                    50,
                    error_code="DATABASE_ERROR",
                ),
            )
            return

        try:
            pipeline_result = run_analysis_pipeline(
                entries,
                org_id,
                file_id,
                source_type,
                request_id=_get_request_id(),
                log=log,
            )
            detections = pipeline_result["detections"]
            rf_results = pipeline_result["rf_results"]
            analysis = pipeline_result["analysis"]
        except Exception:
            log.exception("Threat analysis pipeline failed")
            yield _to_sse(
                "error",
                _progress_event(
                    "analysis_failed",
                    "Threat analysis failed",
                    85,
                    error_code="ANALYSIS_ERROR",
                ),
            )
            return
        yield _to_sse(
            "progress",
            _progress_event(
                "correlation_complete",
                "Correlation checks completed.",
                62,
                detection_count=len(detections),
            ),
        )

        yield _to_sse(
            "progress",
            _progress_event(
                "classification_complete", "RF classification completed.", 72
            ),
        )

        yield _to_sse(
            "progress",
            _progress_event("analysis_complete", "Threat analysis completed.", 85),
        )

        try:
            _store_analysis_result(
                file_id=file_id,
                org_id=org_id,
                analysis=analysis,
                detections=detections,
            )
            yield _to_sse(
                "progress",
                _progress_event("result_stored", "Stored analysis result.", 92),
            )
        except Exception:
            if file_id:
                supabase_client.table("log_files").update({"status": "failed"}).eq(
                    "id", file_id
                ).execute()
            log.exception("Failed to store analysis")
            yield _to_sse(
                "error",
                _progress_event(
                    "database_failed",
                    "Failed to store analysis",
                    92,
                    error_code="DATABASE_ERROR",
                ),
            )
            return

        supabase_client.table("log_files").update({"status": "completed"}).eq(
            "id", file_id
        ).execute()

        try:
            actionable_insights = _build_actionable_insights_payload(
                threats=analysis.get("detailed_findings", []),
                detections=detections,
                logs=entries,
                source_type=source_type,
                rf_results=rf_results,
            )
        except Exception:
            log.exception("Failed to generate actionable insights")
            actionable_insights = {
                "status": "error",
                "message": "Failed to generate actionable insights",
            }

        final_payload = {
            "file_id": file_id,
            "filename": file.filename,
            "entry_count": len(entries),
            "detections": detections,
            "detection_count": len(detections),
            "analysis": {
                "threat_level": analysis["threat_level"],
                "threats_found": analysis["threats_found"],
                "summary": analysis["summary"],
                "mitre_techniques": analysis.get("mitre_techniques"),
                "attack_vector": analysis.get("attack_vector"),
                "confidence_score": analysis.get("confidence_score"),
            },
            "actionable_insights": actionable_insights,
            "request_id": _get_request_id(),
        }
        yield _to_sse(
            "progress", _progress_event("finalizing", "Finalizing response.", 98)
        )
        yield _to_sse(
            "completed",
            _progress_event(
                "completed", "Analysis completed.", 100, result=final_payload
            ),
        )

    return Response(
        stream_with_context(_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


