"""Route implementations for the ingestion service."""

from flask import jsonify, request
from . import main, supabase_client
from .utils import *
from .utils import _request_logger
from .utils import _require_roles
from .utils import _enforce_org_scope
from .utils import _select_with_fallback
from .utils import _get_request_id
from .utils import _error_response
from .utils import _auth_user_id
from .utils import _is_uuid  # noqa: F401,F403

@main.route("/feedback", methods=["GET"])
def list_feedback():
    log = _request_logger(route="list_feedback")
    role_error = _require_roles("admin", "analyst", "viewer")
    if role_error:
        return role_error

    org_id, org_scope_error = _enforce_org_scope(request.args.get("org_id"))
    if org_scope_error:
        return org_scope_error

    try:
        result, _select_expr = _select_with_fallback(
            "feedback",
            [
                "id, org_id, summary_id, user_id, rating, suggestion_text, created_at",
                "id, org_id, summary_id, user_id, rating, created_at",
                "id, org_id, summary_id, user_id, rating",
                "id, org_id, rating",
            ],
            lambda query: query.eq("org_id", org_id).limit(100),
        )
        if result is None:
            return jsonify({"items": [], "request_id": _get_request_id()}), 200
        return jsonify(
            {"items": result.data or [], "request_id": _get_request_id()}
        ), 200
    except Exception:
        log.exception("Failed to load feedback")
        return _error_response(
            "Failed to load feedback", 500, "DATABASE_ERROR", retryable=True
        )


@main.route("/feedback", methods=["POST"])
def create_feedback():
    role_error = _require_roles("admin", "analyst", "viewer")
    if role_error:
        return role_error

    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get("org_id"))
    if org_scope_error:
        return org_scope_error

    summary_id = payload.get("summary_id")
    rating = payload.get("rating")
    suggestion_text = str(payload.get("suggestion_text") or "").strip()

    try:
        rating = int(rating)
    except (TypeError, ValueError):
        return _error_response(
            "rating must be an integer between 1 and 5", 400, "VALIDATION_ERROR"
        )

    if rating < 1 or rating > 5:
        return _error_response(
            "rating must be between 1 and 5", 400, "VALIDATION_ERROR"
        )

    if summary_id and not _is_uuid(summary_id):
        return _error_response(
            "summary_id must be a UUID when provided", 400, "VALIDATION_ERROR"
        )

    payload_to_store = {
        "org_id": org_id,
        "summary_id": summary_id,
        "user_id": _auth_user_id() or None,
        "rating": rating,
        "suggestion_text": suggestion_text or None,
    }

    try:
        result = supabase_client.table("feedback").insert(payload_to_store).execute()
    except Exception as exc:
        if "suggestion_text" not in str(exc):
            raise
        payload_to_store.pop("suggestion_text", None)
        result = supabase_client.table("feedback").insert(payload_to_store).execute()

    return jsonify(
        {"feedback": (result.data or [None])[0], "request_id": _get_request_id()}
    ), 201


