from flask import jsonify, request

from .timeline_service import (
    get_file_timeline,
    get_file_timeline_graph,
    get_org_timeline,
    get_org_timeline_graph,
)


def register_timeline_routes(
    blueprint,
    *,
    request_logger,
    require_roles,
    is_uuid,
    error_response,
    enforce_file_scope,
    enforce_org_scope,
    get_request_id,
):
    @blueprint.route("/timeline/file/<file_id>", methods=["GET"])
    def get_file_timeline_route(file_id):
        log = request_logger(route="get_file_timeline", file_id=file_id)
        role_error = require_roles("admin", "analyst", "viewer")
        if role_error:
            return role_error

        if not is_uuid(file_id):
            return error_response("file_id must be a UUID", 400, "VALIDATION_ERROR")

        _, file_scope_error = enforce_file_scope(file_id)
        if file_scope_error:
            return file_scope_error

        start = request.args.get("start")
        end = request.args.get("end")
        severity = request.args.get("severity")
        event_type = request.args.get("event_type")

        try:
            page = int(request.args.get("page", "1"))
            page_size = int(request.args.get("page_size", "100"))
        except (TypeError, ValueError):
            return error_response(
                "page and page_size must be integers", 400, "VALIDATION_ERROR"
            )

        if page <= 0 or page_size <= 0:
            return error_response(
                "page and page_size must be greater than 0", 400, "VALIDATION_ERROR"
            )

        try:
            timeline = get_file_timeline(
                file_id=file_id,
                start=start,
                end=end,
                severity=severity,
                event_type=event_type,
                page=page,
                page_size=page_size,
            )
        except Exception:
            log.exception("Failed to fetch file timeline")
            return error_response(
                "Failed to fetch file timeline",
                500,
                "DATABASE_ERROR",
                retryable=True,
            )

        timeline["request_id"] = get_request_id()
        return jsonify(timeline), 200

    @blueprint.route("/timeline/org/<org_id>", methods=["GET"])
    def get_org_timeline_route(org_id):
        log = request_logger(route="get_org_timeline", org_id=org_id)
        role_error = require_roles("admin", "analyst", "viewer")
        if role_error:
            return role_error

        if not is_uuid(org_id):
            return error_response("org_id must be a UUID", 400, "VALIDATION_ERROR")

        _, org_scope_error = enforce_org_scope(org_id)
        if org_scope_error:
            return org_scope_error

        start = request.args.get("start")
        end = request.args.get("end")
        severity = request.args.get("severity")
        event_type = request.args.get("event_type")

        try:
            page = int(request.args.get("page", "1"))
            page_size = int(request.args.get("page_size", "100"))
        except (TypeError, ValueError):
            return error_response(
                "page and page_size must be integers", 400, "VALIDATION_ERROR"
            )

        if page <= 0 or page_size <= 0:
            return error_response(
                "page and page_size must be greater than 0", 400, "VALIDATION_ERROR"
            )

        try:
            timeline = get_org_timeline(
                org_id=org_id,
                start=start,
                end=end,
                severity=severity,
                event_type=event_type,
                page=page,
                page_size=page_size,
            )
        except Exception:
            log.exception("Failed to fetch org timeline")
            return error_response(
                "Failed to fetch org timeline",
                500,
                "DATABASE_ERROR",
                retryable=True,
            )

        timeline["request_id"] = get_request_id()
        return jsonify(timeline), 200

    @blueprint.route("/timeline/file/<file_id>/graph", methods=["GET"])
    def get_file_timeline_graph_route(file_id):
        log = request_logger(route="get_file_timeline_graph", file_id=file_id)
        role_error = require_roles("admin", "analyst", "viewer")
        if role_error:
            return role_error

        if not is_uuid(file_id):
            return error_response("file_id must be a UUID", 400, "VALIDATION_ERROR")

        _, file_scope_error = enforce_file_scope(file_id)
        if file_scope_error:
            return file_scope_error

        start = request.args.get("start")
        end = request.args.get("end")
        severity = request.args.get("severity")
        event_type = request.args.get("event_type")
        max_nodes_raw = request.args.get("max_nodes", "120")

        try:
            max_nodes = int(max_nodes_raw)
        except (TypeError, ValueError):
            return error_response(
                "max_nodes must be an integer", 400, "VALIDATION_ERROR"
            )

        if max_nodes <= 0:
            return error_response(
                "max_nodes must be greater than 0", 400, "VALIDATION_ERROR"
            )

        try:
            graph_payload = get_file_timeline_graph(
                file_id=file_id,
                start=start,
                end=end,
                severity=severity,
                event_type=event_type,
                max_nodes=min(max_nodes, 300),
            )
        except Exception:
            log.exception("Failed to fetch file timeline graph")
            return error_response(
                "Failed to fetch file timeline graph",
                500,
                "DATABASE_ERROR",
                retryable=True,
            )

        graph_payload["request_id"] = get_request_id()
        return jsonify(graph_payload), 200

    @blueprint.route("/timeline/org/<org_id>/graph", methods=["GET"])
    def get_org_timeline_graph_route(org_id):
        log = request_logger(route="get_org_timeline_graph", org_id=org_id)
        role_error = require_roles("admin", "analyst", "viewer")
        if role_error:
            return role_error

        if not is_uuid(org_id):
            return error_response("org_id must be a UUID", 400, "VALIDATION_ERROR")

        _, org_scope_error = enforce_org_scope(org_id)
        if org_scope_error:
            return org_scope_error

        start = request.args.get("start")
        end = request.args.get("end")
        severity = request.args.get("severity")
        event_type = request.args.get("event_type")
        max_nodes_raw = request.args.get("max_nodes", "160")

        try:
            max_nodes = int(max_nodes_raw)
        except (TypeError, ValueError):
            return error_response(
                "max_nodes must be an integer", 400, "VALIDATION_ERROR"
            )

        if max_nodes <= 0:
            return error_response(
                "max_nodes must be greater than 0", 400, "VALIDATION_ERROR"
            )

        try:
            graph_payload = get_org_timeline_graph(
                org_id=org_id,
                start=start,
                end=end,
                severity=severity,
                event_type=event_type,
                max_nodes=min(max_nodes, 400),
            )
        except Exception:
            log.exception("Failed to fetch org timeline graph")
            return error_response(
                "Failed to fetch org timeline graph",
                500,
                "DATABASE_ERROR",
                retryable=True,
            )

        graph_payload["request_id"] = get_request_id()
        return jsonify(graph_payload), 200
