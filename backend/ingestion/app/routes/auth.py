"""Route implementations for the ingestion service."""

from flask import g, request
from time import perf_counter
from . import main, supabase_client
from .utils import *  # noqa: F401,F403

def _set_request_id():
    request_id = request.headers.get("X-Request-ID")
    g.request_id = request_id or str(uuid4())
    g.request_started_at = perf_counter()


@main.before_request
def _authenticate_request():
    endpoint = request.endpoint or ""
    if request.method == "OPTIONS" or endpoint in _PUBLIC_ENDPOINTS:
        return None

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return _error_response(
            "Missing Authorization bearer token", 401, "UNAUTHORIZED"
        )

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return _error_response(
            "Missing Authorization bearer token", 401, "UNAUTHORIZED"
        )

    try:
        auth_result = supabase_client.auth.get_user(token)
    except Exception:
        return _error_response("Invalid access token", 401, "UNAUTHORIZED")

    auth_user = getattr(auth_result, "user", None)
    if auth_user is None and isinstance(auth_result, dict):
        auth_user = auth_result.get("user")

    user_id = None
    if isinstance(auth_user, dict):
        user_id = auth_user.get("id")
    else:
        user_id = getattr(auth_user, "id", None)

    if not _is_uuid(user_id):
        return _error_response(
            "Unable to resolve authenticated user", 401, "UNAUTHORIZED"
        )

    try:
        user_result, _user_select_expr = _select_with_fallback(
            "users",
            [
                "id, org_id, role",
                "id, org_id",
                "id",
            ],
            lambda query: query.eq("id", user_id).limit(1),
        )
    except Exception:
        return _error_response(
            "Failed to resolve user context", 500, "DATABASE_ERROR", retryable=True
        )

    user_row = (user_result.data or [None])[0]
    if not user_row:
        if isinstance(auth_user, dict):
            email = auth_user.get("email")
            app_metadata = auth_user.get("app_metadata") or {}
            user_metadata = auth_user.get("user_metadata") or {}
        else:
            email = getattr(auth_user, "email", None)
            app_metadata = getattr(auth_user, "app_metadata", {}) or {}
            user_metadata = getattr(auth_user, "user_metadata", {}) or {}

        claim_org_id = (
            app_metadata.get("org_id")
            or user_metadata.get("org_id")
            or _resolve_bootstrap_org_id()
        )
        claim_role = (
            str(app_metadata.get("role") or user_metadata.get("role") or "viewer")
            .strip()
            .lower()
        )
        if claim_role not in {"admin", "analyst", "viewer"}:
            claim_role = "viewer"

        if not _is_uuid(claim_org_id) or not _org_exists(claim_org_id):
            return _error_response(
                "Authenticated user is not provisioned",
                403,
                "FORBIDDEN",
                details={
                    "hint": "Create a users row with id, org_id, email, and role, or include org_id in auth metadata.",
                },
            )

        provisioned = False
        upsert_payload_candidates = [
            {
                "id": user_id,
                "org_id": str(claim_org_id),
                "email": email or "",
                "role": claim_role,
            },
            {
                "id": user_id,
                "org_id": str(claim_org_id),
                "role": claim_role,
            },
            {
                "id": user_id,
                "org_id": str(claim_org_id),
                "email": email or "",
            },
            {
                "id": user_id,
                "org_id": str(claim_org_id),
            },
        ]

        for upsert_payload in upsert_payload_candidates:
            try:
                supabase_client.table("users").upsert(
                    upsert_payload, on_conflict="id"
                ).execute()
                provisioned = True
                break
            except Exception:
                continue

        if not provisioned:
            return _error_response(
                "Failed to provision authenticated user context",
                500,
                "DATABASE_ERROR",
                retryable=True,
            )

        try:
            user_result, _user_select_expr = _select_with_fallback(
                "users",
                [
                    "id, org_id, role",
                    "id, org_id",
                    "id",
                ],
                lambda query: query.eq("id", user_id).limit(1),
            )
            user_row = (user_result.data or [None])[0]
        except Exception:
            return _error_response(
                "Failed to provision authenticated user context",
                500,
                "DATABASE_ERROR",
                retryable=True,
            )

        if not user_row:
            return _error_response(
                "Authenticated user is not provisioned", 403, "FORBIDDEN"
            )

    org_id = user_row.get("org_id")
    role = user_row.get("role") or "viewer"
    if not _is_uuid(org_id):
        bootstrap_org_id = _resolve_bootstrap_org_id()
        if not bootstrap_org_id:
            return _error_response(
                "Authenticated user has no org context", 403, "FORBIDDEN"
            )
        try:
            supabase_client.table("users").update({"org_id": bootstrap_org_id}).eq(
                "id", user_id
            ).execute()
            org_id = bootstrap_org_id
        except Exception:
            return _error_response(
                "Failed to provision authenticated user context",
                500,
                "DATABASE_ERROR",
                retryable=True,
            )

    g.auth_user_id = str(user_row["id"])
    g.auth_org_id = str(org_id)
    g.auth_role = str(role or "viewer")
    return None


@main.after_request
def _log_request_timing(response):
    started_at = getattr(g, "request_started_at", None)
    elapsed_ms = None
    if started_at is not None:
        elapsed_ms = round((perf_counter() - started_at) * 1000, 2)

    _request_logger(
        route=(request.url_rule.rule if request.url_rule else request.path),
        method=request.method,
        status_code=response.status_code,
        elapsed_ms=elapsed_ms,
    ).info("Request completed")
    return response


