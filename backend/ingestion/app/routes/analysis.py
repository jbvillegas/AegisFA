"""Route implementations for the ingestion service."""

from flask import jsonify, request
from . import main, supabase_client
from .utils import *  # noqa: F401,F403

@main.route("/analysis/<file_id>", methods=["GET"])
def get_analysis(file_id):
    log = _request_logger(route="get_analysis", file_id=file_id)
    role_error = _require_roles("admin", "analyst", "viewer")
    if role_error:
        return role_error
    include_mitre_links = (
        request.args.get("include_mitre_links", "true").strip().lower() != "false"
    )

    if not _is_uuid(file_id):
        return _error_response("file_id must be a UUID", 400, "VALIDATION_ERROR")

    _, file_scope_error = _enforce_file_scope(file_id)
    if file_scope_error:
        return file_scope_error

    try:
        result = (
            supabase_client.table("analysis_results")
            .select("*")
            .eq("file_id", file_id)
            .order(
                "created_at",
                desc=True,
            )
            .limit(1)
            .execute()
        )
    except Exception:
        # Some environments still have the older analysis_results schema without created_at.
        log.exception(
            "Failed to order analysis results by created_at; retrying without ordering"
        )
        result = (
            supabase_client.table("analysis_results")
            .select("*")
            .eq("file_id", file_id)
            .limit(1)
            .execute()
        )

    if not result.data:
        return _error_response("No analysis found for this file", 404, "NOT_FOUND")

    response_payload = result.data[0]
    if include_mitre_links:
        try:
            response_payload["mitre_links"] = _get_mitre_links_for_analysis(
                response_payload["id"]
            )
        except Exception:
            log.exception("Failed to fetch normalized MITRE links")
            response_payload["mitre_links"] = []

    log.info("Retrieved analysis result")
    return jsonify(response_payload), 200


@main.route("/analyze/<file_id>", methods=["POST"])
def analyze_stored_file(file_id):
    """Re-analyze a previously uploaded file using raw_logs already in the DB."""
    log = _request_logger(route="analyze_stored_file", file_id=file_id)
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error

    file_result = (
        supabase_client.table("log_files")
        .select("id, org_id, source_type")
        .eq("id", file_id)
        .execute()
    )
    if not file_result.data:
        return _error_response("File not found", 404, "NOT_FOUND")

    file_record = file_result.data[0]
    _, org_scope_error = _enforce_org_scope(file_record.get("org_id"))
    if org_scope_error:
        return org_scope_error
    org_id = file_record["org_id"]
    source_type = file_record["source_type"]
    log = log.bind(org_id=org_id, source_type=source_type)

    logs_result = (
        supabase_client.table("raw_logs")
        .select("payload")
        .eq("file_id", file_id)
        .execute()
    )
    entries = [r["payload"] for r in (logs_result.data or []) if r.get("payload")]

    if not entries:
        return _error_response("No log entries found for this file", 404, "NOT_FOUND")

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


@main.route("/analyze-from-storage", methods=["POST"])
def analyze_from_storage():
    """Download a file from Supabase Storage by path and run full analysis."""
    log = _request_logger(route="analyze_from_storage")
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error

    data = request.get_json()
    if not data:
        return _error_response("JSON body required", 400, "VALIDATION_ERROR")

    org_id, org_scope_error = _enforce_org_scope(data.get("org_id"))
    if org_scope_error:
        return org_scope_error
    filename = data.get("filename")
    source_type = data.get("source_type")
    log = log.bind(org_id=org_id, filename=filename, source_type=source_type)

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

    storage_path = f"{org_id}/{filename}"

    try:
        file_bytes = download_file(storage_path)
    except Exception:
        log.exception("Failed to download file from storage")
        return _error_response(
            "Failed to download file from storage", 404, "STORAGE_ERROR"
        )

    try:
        entries = parse_file(file_bytes, filename)
    except Exception:
        log.exception("Failed to parse file")
        return _error_response("Failed to parse file", 400, "PARSING_ERROR")

    try:
        file_record = (
            supabase_client.table("log_files")
            .insert(
                {
                    "filename": filename,
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
        log.exception("Failed to create file record")
        return _error_response(
            "Failed to create file record", 500, "DATABASE_ERROR", retryable=True
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
            "filename": filename,
            "storage_path": storage_path,
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
