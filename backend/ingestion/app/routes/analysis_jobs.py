"""Route implementations for the ingestion service."""

from flask import jsonify, request
from . import main, supabase_client
from .utils import *
from .utils import _request_logger
from .utils import _require_roles
from .utils import _enforce_org_scope
from .utils import _get_request_id
from .utils import _error_response
from .utils import _is_uuid
from .utils import _auth_user_id
from .utils import _create_background_analysis_job_internal
from .utils import _select_with_fallback  # noqa: F401,F403

@main.route("/analysis-jobs", methods=["GET"])
def list_analysis_jobs():
    """Return a list of analysis jobs filtered by org_id and limited by 'limit' query param."""
    log = _request_logger(route="list_analysis_jobs")
    role_error = _require_roles("admin", "analyst", "viewer")
    if role_error:
        return role_error

    org_id = request.args.get("org_id")
    limit = request.args.get("limit", 10)
    try:
        limit = int(limit)
        if limit <= 0 or limit > 100:
            limit = 10
    except Exception:
        limit = 10

    if not org_id or not _is_uuid(org_id):
        return _error_response(
            "org_id is required and must be a valid UUID", 400, "VALIDATION_ERROR"
        )

    try:
        jobs_result = (
            supabase_client.table("analysis_jobs")
            .select("*")
            .eq("org_id", org_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        jobs = jobs_result.data or []
    except Exception:
        log.exception("Failed to fetch analysis jobs")
        return _error_response(
            "Failed to fetch analysis jobs", 500, "DATABASE_ERROR", retryable=True
        )

    return jsonify(
        {
            "jobs": _serialize_timestamps(jobs),
            "request_id": _get_request_id(),
        }
    ), 200


@main.route("/analysis-jobs/from-storage", methods=["POST"])
def create_background_analysis_job():
    """Create an asynchronous analysis job for a file that already exists in storage."""
    log = _request_logger(route="create_background_analysis_job")
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}

    org_id, org_scope_error = _enforce_org_scope(payload.get("org_id"))
    if org_scope_error:
        return org_scope_error
    filename = payload.get("filename")
    source_type = payload.get("source_type")
    requested_by = _auth_user_id() or payload.get("requested_by")

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

    try:
        job_id, item_id = _create_background_analysis_job_internal(
            org_id=org_id,
            filename=filename,
            source_type=source_type,
            requested_by=requested_by,
        )
    except ValueError:
        log.exception("Validation error creating background analysis job")
        return _error_response("Invalid request parameters", 400, "VALIDATION_ERROR")
    except Exception:
        log.exception("Failed to create background analysis job")
        return _error_response(
            "Failed to create analysis job", 500, "DATABASE_ERROR", retryable=True
        )

    return jsonify(
        {
            "job_id": job_id,
            "item_id": item_id,
            "status": "queued",
            "request_id": _get_request_id(),
        }
    ), 202


def _serialize_timestamps(obj):
    """Convert datetime objects to ISO format strings and numeric types to float for JSON serialization."""
    from decimal import Decimal

    if isinstance(obj, dict):
        return {k: _serialize_timestamps(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize_timestamps(item) for item in obj]
    elif isinstance(obj, Decimal):
        # Convert Decimal to float to preserve numeric precision
        return float(obj)
    elif obj is not None and hasattr(obj, "isoformat") and callable(obj.isoformat):
        # Only convert if it's actually a datetime-like object (has working isoformat method)
        try:
            return obj.isoformat()
        except (TypeError, AttributeError):
            return obj
    else:
        return obj


@main.route("/analysis-jobs/<job_id>", methods=["GET"])
def get_background_analysis_job(job_id):
    """Poll background job status and retrieve output when available."""
    log = _request_logger(route="get_background_analysis_job", job_id=job_id)
    role_error = _require_roles("admin", "analyst", "viewer")
    if role_error:
        return role_error

    if not _is_uuid(job_id):
        return _error_response("job_id must be a UUID", 400, "VALIDATION_ERROR")

    try:
        job_result, _job_select_expr = _select_with_fallback(
            "analysis_jobs",
            [
                "id, org_id, requested_by, status, source_type, total_files, processed_files, failed_files, progress_pct, created_at, started_at, completed_at, error_message, output_path",
                "id, org_id, status, source_type, total_files, processed_files, failed_files, progress_pct, created_at, started_at, completed_at, error_message, output_path",
                "id, org_id, status, source_type, total_files, processed_files, failed_files, progress_pct, created_at, started_at, completed_at, error_message",
                "id, org_id, status, source_type, total_files, processed_files, failed_files, progress_pct",
                "id, org_id, status",
            ],
            lambda query: query.eq("id", job_id).limit(1),
        )
    except Exception:
        log.exception("Failed to fetch analysis job")
        return _error_response(
            "Failed to fetch analysis job", 500, "DATABASE_ERROR", retryable=True
        )

    if not job_result.data:
        return _error_response("Analysis job not found", 404, "NOT_FOUND")

    job = job_result.data[0]
    job.setdefault("requested_by", None)
    job.setdefault("source_type", None)
    job.setdefault("total_files", 0)
    job.setdefault("processed_files", 0)
    job.setdefault("failed_files", 0)
    job.setdefault("progress_pct", 0)
    job.setdefault("created_at", None)
    job.setdefault("started_at", None)
    job.setdefault("completed_at", None)
    job.setdefault("error_message", None)
    job.setdefault("output_path", None)
    _, org_scope_error = _enforce_org_scope(job.get("org_id"))
    if org_scope_error:
        return org_scope_error
    items = []
    try:
        items_result, _items_select_expr = _select_with_fallback(
            "analysis_job_items",
            [
                "id, job_id, file_name, file_id, status, entry_count, result_id, progress_pct, created_at, started_at, completed_at, error_message",
                "id, job_id, file_name, file_id, status, entry_count, result_id, progress_pct, created_at, started_at, completed_at",
                "id, job_id, file_name, file_id, status, entry_count, result_id, progress_pct",
                "id, job_id, file_name, status",
            ],
            lambda query: query.eq("job_id", job_id),
        )
        items = items_result.data or []
    except Exception:
        log.exception("Failed to fetch analysis job items")

    result_payload = None
    completed_item = next(
        (
            item
            for item in items
            if item.get("status") == "completed" and item.get("result_id")
        ),
        None,
    )
    if completed_item:
        result_id = completed_item["result_id"]
        try:
            analysis_result = (
                supabase_client.table("analysis_results")
                .select("*")
                .eq("id", result_id)
                .limit(1)
                .execute()
            )
            result_payload = analysis_result.data[0] if analysis_result.data else None
        except Exception:
            log.exception("Failed to fetch analysis result for completed job item")

    return jsonify(
        {
            "job": _serialize_timestamps(job),
            "items": _serialize_timestamps(items),
            "result": _serialize_timestamps(result_payload),
            "request_id": _get_request_id(),
        }
    ), 200


