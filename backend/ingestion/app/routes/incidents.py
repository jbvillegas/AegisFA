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
from .utils import _incident_org_id  # noqa: F401,F403

@main.route("/incidents", methods=["GET"])
def list_incidents():
    log = _request_logger(route="list_incidents")
    role_error = _require_roles("admin", "analyst", "viewer")
    if role_error:
        return role_error

    org_id, org_scope_error = _enforce_org_scope(request.args.get("org_id"))
    if org_scope_error:
        return org_scope_error

    status_filter = request.args.get("status")
    limit_raw = request.args.get("limit", "50")
    try:
        max(1, min(200, int(limit_raw)))
    except (TypeError, ValueError):
        return _error_response("limit must be an integer", 400, "VALIDATION_ERROR")

    try:
        result, _select_expr = _select_with_fallback(
            "incidents",
            [
                "id, org_id, title, status, severity",
                "id, org_id, title, status",
                "id, org_id, title",
                "id, title",
            ],
            lambda query: (
                query.eq("org_id", org_id).eq("status", status_filter)
                if status_filter
                else query.eq("org_id", org_id)
            ),
        )
        if result is None:
            return jsonify({"items": [], "request_id": _get_request_id()}), 200
        return jsonify(
            {"items": result.data or [], "request_id": _get_request_id()}
        ), 200
    except Exception:
        log.exception("Failed to load incidents")
        return _error_response(
            "Failed to load incidents", 500, "DATABASE_ERROR", retryable=True
        )


@main.route("/incidents", methods=["POST"])
def create_incident():
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error

    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get("org_id"))
    if org_scope_error:
        return org_scope_error

    title = str(payload.get("title") or "").strip()
    status = str(payload.get("status") or "open").strip().lower()
    severity = str(payload.get("severity") or "medium").strip().lower()

    if not title:
        return _error_response("title is required", 400, "VALIDATION_ERROR")

    if status not in {"open", "in_progress", "resolved", "closed"}:
        return _error_response(
            "status must be one of: open, in_progress, resolved, closed",
            400,
            "VALIDATION_ERROR",
        )

    if severity not in {"low", "medium", "high", "critical"}:
        return _error_response(
            "severity must be one of: low, medium, high, critical",
            400,
            "VALIDATION_ERROR",
        )

    result = (
        supabase_client.table("incidents")
        .insert(
            {
                "org_id": org_id,
                "title": title,
                "status": status,
                "severity": severity,
            }
        )
        .execute()
    )

    return jsonify(
        {"incident": (result.data or [None])[0], "request_id": _get_request_id()}
    ), 201


@main.route("/incidents/<incident_id>", methods=["PATCH"])
def update_incident(incident_id):
    role_error = _require_roles("admin", "analyst")
    if role_error:
        return role_error

    org_id = _incident_org_id(incident_id)
    if not org_id:
        return _error_response("Incident not found", 404, "NOT_FOUND")

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
        if status not in {"open", "in_progress", "resolved", "closed"}:
            return _error_response(
                "status must be one of: open, in_progress, resolved, closed",
                400,
                "VALIDATION_ERROR",
            )
        updates["status"] = status

    if "severity" in payload:
        severity = str(payload.get("severity") or "").strip().lower()
        if severity not in {"low", "medium", "high", "critical"}:
            return _error_response(
                "severity must be one of: low, medium, high, critical",
                400,
                "VALIDATION_ERROR",
            )
        updates["severity"] = severity

    if not updates:
        return _error_response(
            "No valid fields supplied to update", 400, "VALIDATION_ERROR"
        )

    result = (
        supabase_client.table("incidents")
        .update(updates)
        .eq("id", incident_id)
        .execute()
    )
    return jsonify(
        {"incident": (result.data or [None])[0], "request_id": _get_request_id()}
    ), 200


