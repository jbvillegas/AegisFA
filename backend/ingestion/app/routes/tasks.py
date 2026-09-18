"""Route implementations for the ingestion service."""

from flask import jsonify, request
from . import main, supabase_client
from .utils import *
from .utils import _request_logger
from .utils import _require_roles
from .utils import _enforce_org_scope
from .utils import _error_response
from .utils import _select_with_fallback
from .utils import _get_request_id
from .utils import _is_uuid
from .utils import _incident_org_id
from .utils import _task_org_id  # noqa: F401,F403

@main.route("/tasks", methods=["GET"])
def list_tasks():
    log = _request_logger(route="list_tasks")
    role_error = _require_roles("admin", "analyst", "viewer")
    if role_error:
        return role_error

    org_id, org_scope_error = _enforce_org_scope(request.args.get("org_id"))
    if org_scope_error:
        return org_scope_error

    incident_id = request.args.get("incident_id")
    status_filter = request.args.get("status")
    limit_raw = request.args.get("limit", "50")
    try:
        max(1, min(200, int(limit_raw)))
    except (TypeError, ValueError):
        return _error_response("limit must be an integer", 400, "VALIDATION_ERROR")

    try:
        result, _select_expr = _select_with_fallback(
            "tasks",
            [
                "id, org_id, incident_id, assignee_id, title, status",
                "id, org_id, incident_id, title, status",
                "id, org_id, incident_id, title",
                "id, org_id, title",
            ],
            lambda query: (
                (
                    query.eq("org_id", org_id).eq("incident_id", incident_id)
                    if incident_id
                    else query.eq("org_id", org_id)
                ).eq("status", status_filter)
                if status_filter
                else (
                    query.eq("org_id", org_id).eq("incident_id", incident_id)
                    if incident_id
                    else query.eq("org_id", org_id)
                )
            ),
        )
        if result is None:
            return jsonify({"items": [], "request_id": _get_request_id()}), 200
        return jsonify(
            {"items": result.data or [], "request_id": _get_request_id()}
        ), 200
    except Exception:
        log.exception("Failed to load tasks")
        return _error_response(
            "Failed to load tasks", 500, "DATABASE_ERROR", retryable=True
        )


@main.route("/tasks", methods=["POST"])
def create_task():
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error

    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get("org_id"))
    if org_scope_error:
        return org_scope_error

    title = str(payload.get("title") or "").strip()
    incident_id = payload.get("incident_id")
    assignee_id = payload.get("assignee_id")
    status = str(payload.get("status") or "pending").strip().lower()

    if not title:
        return _error_response("title is required", 400, "VALIDATION_ERROR")
    if not _is_uuid(incident_id):
        return _error_response("incident_id must be a UUID", 400, "VALIDATION_ERROR")
    if assignee_id and not _is_uuid(assignee_id):
        return _error_response(
            "assignee_id must be a UUID when provided", 400, "VALIDATION_ERROR"
        )
    if status not in {"pending", "in_progress", "done"}:
        return _error_response(
            "status must be one of: pending, in_progress, done", 400, "VALIDATION_ERROR"
        )

    incident_org_id = _incident_org_id(incident_id)
    if not incident_org_id:
        return _error_response("Incident not found", 404, "NOT_FOUND")
    if incident_org_id != org_id:
        return _error_response("Cross-organization access denied", 403, "FORBIDDEN")

    result = (
        supabase_client.table("tasks")
        .insert(
            {
                "org_id": org_id,
                "incident_id": incident_id,
                "assignee_id": assignee_id,
                "title": title,
                "status": status,
            }
        )
        .execute()
    )

    return jsonify(
        {"task": (result.data or [None])[0], "request_id": _get_request_id()}
    ), 201


@main.route("/tasks/<task_id>", methods=["PATCH"])
def update_task(task_id):
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error

    org_id = _task_org_id(task_id)
    if not org_id:
        return _error_response("Task not found", 404, "NOT_FOUND")

    _, org_scope_error = _enforce_org_scope(org_id)
    if org_scope_error:
        return org_scope_error

    payload = request.get_json(silent=True) or {}
    updates = {}

    if "title" in payload:
        title = str(payload.get("title") or "").strip()
        if not title:
            return _error_response("title cannot be empty", 400, "VALIDATION_ERROR")
        updates["title"] = title

    if "status" in payload:
        status = str(payload.get("status") or "").strip().lower()
        if status not in {"pending", "in_progress", "done"}:
            return _error_response(
                "status must be one of: pending, in_progress, done",
                400,
                "VALIDATION_ERROR",
            )
        updates["status"] = status

    if "assignee_id" in payload:
        assignee_id = payload.get("assignee_id")
        if assignee_id and not _is_uuid(assignee_id):
            return _error_response(
                "assignee_id must be a UUID when provided", 400, "VALIDATION_ERROR"
            )
        updates["assignee_id"] = assignee_id

    if not updates:
        return _error_response(
            "No valid fields supplied to update", 400, "VALIDATION_ERROR"
        )

    result = supabase_client.table("tasks").update(updates).eq("id", task_id).execute()
    return jsonify(
        {"task": (result.data or [None])[0], "request_id": _get_request_id()}
    ), 200


