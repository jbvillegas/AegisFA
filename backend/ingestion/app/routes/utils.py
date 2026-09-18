"""Shared route helpers and background processing."""

import json
import os
import re
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock, Thread
from time import perf_counter
from uuid import UUID, uuid4

import structlog
from flask import Blueprint, Response, g, jsonify, request, stream_with_context

from .. import supabase_client
from ..analysis_pipeline import run_analysis_pipeline
from ..file_parser import parse_file, parse_file_with_metadata
from ..kaggle import prepare_cicids2019_training_bundle
from ..log_classifier import get_classifier
from ..normalization import normalize_log
from ..storage import (
    BUCKET_NAME,
    download_binary,
    download_file,
    upload_binary,
    upload_file,
)

from .constants import (
    BACKGROUND_PARSE_MAX_ROWS,
    MAX_UPLOAD_PART_BYTES,
    MAX_UPLOAD_SESSIONS,
    MAX_UPLOAD_SESSION_ASSEMBLY_BYTES,
    RAW_LOG_INSERT_BATCH_SIZE,
    SUPABASE_RETRY_ATTEMPTS,
    SUPABASE_RETRY_BASE_DELAY_SECONDS,
    UPLOAD_SESSION_TTL_SECONDS,
    _PUBLIC_ENDPOINTS,
    _VALID_SEVERITIES,
)

from . import logger

_upload_sessions: dict[str, dict] = {}
_upload_sessions_lock = Lock()

def _evict_expired_sessions():
    """Remove expired sessions. Must be called while holding _upload_sessions_lock."""
    now = time.time()
    expired = [
        sid
        for sid, session in _upload_sessions.items()
        if now - session.get("created_at_ts", 0) > UPLOAD_SESSION_TTL_SECONDS
    ]
    for sid in expired:
        del _upload_sessions[sid]


_PUBLIC_ENDPOINTS = {"main.root", "main.health"}


def _request_json_dict() -> dict:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def _org_exists(org_id: str | None) -> bool:
    if not _is_uuid(org_id):
        return False
    try:
        org_result = (
            supabase_client.table("organizations")
            .select("id")
            .eq("id", org_id)
            .limit(1)
            .execute()
        )
    except Exception:
        return False
    return bool(org_result.data)


def _resolve_org_from_file_id(file_id: str | None) -> str | None:
    if not _is_uuid(file_id):
        return None
    try:
        file_result = (
            supabase_client.table("log_files")
            .select("org_id")
            .eq("id", file_id)
            .limit(1)
            .execute()
        )
    except Exception:
        return None
    file_row = (file_result.data or [None])[0]
    org_id = file_row.get("org_id") if file_row else None
    return str(org_id) if _is_uuid(org_id) else None


def _resolve_bootstrap_org_id() -> str | None:
    payload = _request_json_dict()
    candidates = [
        payload.get("org_id"),
        request.form.get("org_id"),
        request.args.get("org_id"),
        (request.view_args or {}).get("org_id"),
    ]

    for candidate in candidates:
        if _org_exists(candidate):
            return str(candidate)

    file_candidates = [
        payload.get("file_id"),
        request.form.get("file_id"),
        request.args.get("file_id"),
        (request.view_args or {}).get("file_id"),
    ]

    for file_id in file_candidates:
        resolved = _resolve_org_from_file_id(file_id)
        if resolved:
            return resolved

    return None


# New endpoint: GET /analysis-jobs
def _get_request_id() -> str:
    request_id = getattr(g, "request_id", None)
    if request_id:
        return request_id
    generated = str(uuid4())
    g.request_id = generated
    return generated


def _request_logger(**fields):
    return logger.bind(request_id=_get_request_id(), **fields)


def _error_response(
    message: str,
    status: int,
    error_code: str,
    retryable: bool = False,
    details: dict | None = None,
):
    payload = {
        "error": {
            "code": error_code,
            "message": message,
            "retryable": retryable,
            "request_id": _get_request_id(),
        }
    }
    if details:
        payload["error"]["details"] = details
    return jsonify(payload), status


def _auth_org_id() -> str:
    return str(getattr(g, "auth_org_id", "") or "")


def _auth_user_id() -> str:
    return str(getattr(g, "auth_user_id", "") or "")


def _auth_role() -> str:
    return str(getattr(g, "auth_role", "viewer") or "viewer").strip().lower()


def _require_roles(*allowed_roles: str):
    normalized_allowed = {str(role).strip().lower() for role in allowed_roles if role}
    current_role = _auth_role()
    if current_role not in normalized_allowed:
        return _error_response(
            "Insufficient role permissions for this endpoint",
            403,
            "FORBIDDEN",
            details={
                "required_roles": sorted(normalized_allowed),
                "current_role": current_role,
            },
        )
    return None


def _enforce_org_scope(requested_org_id: str | None) -> tuple[str | None, tuple | None]:
    auth_org_id = _auth_org_id()
    if not auth_org_id:
        return None, _error_response(
            "Missing authenticated organization context", 403, "FORBIDDEN"
        )

    if requested_org_id and str(requested_org_id) != auth_org_id:
        return None, _error_response(
            "Cross-organization access denied", 403, "FORBIDDEN"
        )

    return auth_org_id, None


def _file_org_id(file_id: str) -> str | None:
    file_result = (
        supabase_client.table("log_files")
        .select("org_id")
        .eq("id", file_id)
        .limit(1)
        .execute()
    )
    file_row = (file_result.data or [None])[0]
    if not file_row:
        return None
    org_id = file_row.get("org_id")
    return str(org_id) if _is_uuid(org_id) else None


def _enforce_file_scope(file_id: str) -> tuple[str | None, tuple | None]:
    org_id = _file_org_id(file_id)
    if not org_id:
        return None, _error_response("File not found", 404, "NOT_FOUND")
    _, scope_error = _enforce_org_scope(org_id)
    if scope_error:
        return None, scope_error
    return org_id, None


def _incident_org_id(incident_id: str) -> str | None:
    if not _is_uuid(incident_id):
        return None
    result = (
        supabase_client.table("incidents")
        .select("org_id")
        .eq("id", incident_id)
        .limit(1)
        .execute()
    )
    row = (result.data or [None])[0]
    org_id = row.get("org_id") if row else None
    return str(org_id) if _is_uuid(org_id) else None


def _task_org_id(task_id: str) -> str | None:
    if not _is_uuid(task_id):
        return None
    result = (
        supabase_client.table("tasks")
        .select("org_id")
        .eq("id", task_id)
        .limit(1)
        .execute()
    )
    row = (result.data or [None])[0]
    org_id = row.get("org_id") if row else None
    return str(org_id) if _is_uuid(org_id) else None


def _select_with_fallback(table_name: str, select_candidates: list[str], query_builder):
    last_error = None
    for select_expr in select_candidates:
        try:
            query = supabase_client.table(table_name).select(select_expr)
            query = query_builder(query)
            return query.execute(), select_expr
        except Exception as exc:
            last_error = exc
            continue

    if last_error is not None:
        raise last_error

    return None, None


def _is_uuid(value: str | None) -> bool:
    if not value:
        return False
    try:
        UUID(str(value))
        return True
    except (TypeError, ValueError):
        return False


def _normalize_severity(value: str) -> str:
    if not value:
        return "medium"
    normalized = str(value).strip().lower()
    return normalized if normalized in _VALID_SEVERITIES else "medium"


def _detections_to_threats(detections):
    threats = []
    for detection in detections or []:
        rule_name = detection.get("rule_name") or "correlation_rule"
        description = (
            detection.get("description") or f"Correlation rule '{rule_name}' triggered"
        )
        threats.append(
            {
                "threat_type": rule_name,
                "severity": _normalize_severity(detection.get("severity")),
                "description": description,
                "timestamp": detection.get("detected_at")
                or detection.get("created_at"),
                "affected_entries": detection.get("matched_event_indices", []),
                "indicators": [
                    f"MITRE: {detection.get('mitre_technique')}"
                    if detection.get("mitre_technique")
                    else "",
                    f"confidence={detection.get('confidence')}"
                    if detection.get("confidence") is not None
                    else "",
                ],
            }
        )

    for threat in threats:
        threat["indicators"] = [i for i in threat.get("indicators", []) if i]
    return threats


def _execute_with_retry(
    operation, attempts: int | None = None, base_delay_seconds: float | None = None
):
    retry_attempts = max(1, int(attempts or SUPABASE_RETRY_ATTEMPTS))
    retry_base_delay = float(base_delay_seconds or SUPABASE_RETRY_BASE_DELAY_SECONDS)
    last_error = None

    for attempt in range(1, retry_attempts + 1):
        try:
            return operation()
        except Exception as exc:
            last_error = exc
            if attempt < retry_attempts:
                time.sleep(min(retry_base_delay * attempt, 4.0))

    raise last_error


def _insert_raw_logs_in_batches(entries, org_id, file_id):
    rows = [
        {
            "org_id": org_id,
            "payload": entry,
            "file_id": file_id,
        }
        for entry in entries
    ]

    for i in range(0, len(rows), RAW_LOG_INSERT_BATCH_SIZE):
        batch = rows[i : i + RAW_LOG_INSERT_BATCH_SIZE]
        _execute_with_retry(
            lambda payload=batch: (
                supabase_client.table("raw_logs").insert(payload).execute()
            )
        )


def _build_mitre_link_rows(
    analysis_result_id: str, org_id: str, file_id: str, mitre_techniques
) -> list[dict]:
    rows = []
    for idx, technique in enumerate(mitre_techniques or [], start=1):
        if not isinstance(technique, dict):
            continue

        technique_id = technique.get("technique_id") or technique.get("id")
        if not technique_id:
            continue

        rows.append(
            {
                "analysis_result_id": analysis_result_id,
                "org_id": org_id,
                "file_id": file_id,
                "technique_id": str(technique_id).strip(),
                "technique_name": technique.get("name"),
                "tactic": technique.get("tactic"),
                "relevance": technique.get("relevance"),
                "similarity_score": technique.get("similarity"),
                "rank_position": idx,
            }
        )

    return rows


def _store_analysis_result(
    file_id: str,
    org_id: str,
    analysis: dict,
    detections: list[dict] | None = None,
) -> str | None:
    payload = {
        "file_id": file_id,
        "threat_level": analysis["threat_level"],
        "threats_found": analysis["threats_found"],
        "summary": analysis["summary"],
        "detailed_findings": analysis["detailed_findings"],
        "mitre_techniques": analysis.get("mitre_techniques"),
        "attack_vector": analysis.get("attack_vector"),
        "timeline": analysis.get("timeline"),
        "impacted_assets": analysis.get("impacted_assets"),
        "confidence_score": analysis.get("confidence_score"),
        "remediation_steps": analysis.get("remediation_steps"),
        "correlation_detections": detections or [],
        "verdict_sources": analysis.get("verdict_sources"),
    }

    try:
        insert_result = (
            supabase_client.table("analysis_results").insert(payload).execute()
        )
    except Exception as exc:
        # Keep compatibility with databases that have not yet applied verdict_sources migration.
        if "verdict_sources" not in str(exc):
            raise
        payload.pop("verdict_sources", None)
        insert_result = (
            supabase_client.table("analysis_results").insert(payload).execute()
        )

    analysis_result_id = None
    if insert_result.data:
        analysis_result_id = insert_result.data[0].get("id")

    if not analysis_result_id:
        fallback = (
            supabase_client.table("analysis_results")
            .select("id")
            .eq("file_id", file_id)
            .order(
                "created_at",
                desc=True,
            )
            .limit(1)
            .execute()
        )
        if fallback.data:
            analysis_result_id = fallback.data[0].get("id")

    if not analysis_result_id:
        return None

    mitre_rows = _build_mitre_link_rows(
        analysis_result_id=analysis_result_id,
        org_id=org_id,
        file_id=file_id,
        mitre_techniques=analysis.get("mitre_techniques") or [],
    )

    if mitre_rows:
        try:
            supabase_client.table("analysis_result_mitre_links").upsert(
                mitre_rows,
                on_conflict="analysis_result_id,technique_id",
            ).execute()
        except Exception:
            _request_logger(
                route="store_analysis_result", file_id=file_id, org_id=org_id
            ).exception("Failed to persist normalized MITRE links")

    return analysis_result_id


def _get_mitre_links_for_analysis(analysis_result_id: str) -> list[dict]:
    links_result = (
        supabase_client.table("analysis_result_mitre_links")
        .select(
            "technique_id, technique_name, tactic, relevance, similarity_score, rank_position, created_at"
        )
        .eq("analysis_result_id", analysis_result_id)
        .order("rank_position", desc=False)
        .execute()
    )
    return links_result.data or []


def _build_actionable_insights_payload(
    threats=None,
    detections=None,
    logs=None,
    source_type="custom",
    rf_results=None,
):

    threats = threats or []
    detections = detections or []
    logs = logs or []

    if not threats and detections:
        threats = _detections_to_threats(detections)

    if not threats:
        return {
            "status": "no_threats",
            "source_type": source_type,
            "threat_count": 0,
            "detection_count": len(detections),
            "classification_context": {
                "total": 0,
                "by_category": {},
                "average_confidence": 0.0,
            },
            "insights": [],
            "incident_summary": {
                "status": "no_threats",
                "summary": "No threats detected",
                "logs_analyzed": len(logs),
                "risk_level": "low",
            },
            "investigation_guide": {},
        }

    classification_context = {
        "total": 0,
        "by_category": {},
        "average_confidence": 0.0,
    }

    if logs:
        if rf_results is None:
            classifier = get_classifier()
            rf_results = classifier.classify_batch(logs)
        by_category = {}
        by_severity = {}
        confidences = []
        for result in rf_results:
            category = result.get("category", "unknown")
            by_category[category] = by_category.get(category, 0) + 1

            # Track severity distribution
            severity = result.get(
                "adjusted_severity", result.get("mitre_severity", "medium")
            )
            by_severity[severity] = by_severity.get(severity, 0) + 1

            confidences.append(result.get("confidence", 0.0))

        classification_context = {
            "total": len(rf_results),
            "by_category": by_category,
            "by_severity": by_severity,
            "average_confidence": (sum(confidences) / len(confidences))
            if confidences
            else 0.0,
            "details": rf_results[:50],
        }

    from .insights_generator import get_insights_generator

    insights_generator = get_insights_generator()
    insights = insights_generator.generate_threat_insights(threats)
    incident_summary = insights_generator.generate_incident_summary(
        threats,
        log_count=len(logs),
        correlation_data={"detection_count": len(detections)},
    )
    investigation_guide = insights_generator.generate_investigation_guide(
        classification_context,
        threats,
    )

    return {
        "status": "completed",
        "source_type": source_type,
        "threat_count": len(threats),
        "detection_count": len(detections),
        "classification_context": classification_context,
        "insights": insights,
        "incident_summary": incident_summary,
        "investigation_guide": investigation_guide,
    }


def _build_rf_context(rf_results=None) -> dict:
    rf_results = rf_results or []

    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    by_category = {}
    confidences = []

    high_confidence_threshold = 0.7
    high_conf_anomaly_count = 0
    high_conf_security_count = 0
    high_conf_error_count = 0

    for result in rf_results:
        if not isinstance(result, dict):
            continue

        confidence = float(result.get("confidence", 0.0) or 0.0)
        confidences.append(confidence)

        category = str(result.get("category", "unknown")).strip().lower()
        by_category[category] = by_category.get(category, 0) + 1

        severity = _normalize_severity(
            result.get("adjusted_severity") or result.get("mitre_severity") or "medium"
        )
        by_severity[severity] = by_severity.get(severity, 0) + 1

        if confidence >= high_confidence_threshold:
            if severity == "critical":
                high_conf_anomaly_count += 1
            elif severity == "high":
                high_conf_security_count += 1
            elif severity == "medium":
                high_conf_error_count += 1

    total = len(rf_results)
    average_confidence = (sum(confidences) / total) if total else 0.0

    return {
        "total": total,
        "average_confidence": average_confidence,
        "by_severity": by_severity,
        "by_category": by_category,
        "high_confidence_threshold": high_confidence_threshold,
        "high_conf_anomaly_count": high_conf_anomaly_count,
        "high_conf_security_count": high_conf_security_count,
        "high_conf_error_count": high_conf_error_count,
    }


def _get_activation_status(
    validation_metrics: dict | None, threshold: float
) -> tuple[str, float, str | None]:
    precision_weighted = float(
        (validation_metrics or {}).get("precision_weighted", 0.0) or 0.0
    )
    if precision_weighted >= threshold:
        return "active", precision_weighted, None

    return (
        "archived",
        precision_weighted,
        (
            f"Validation weighted precision {precision_weighted:.3f} is below "
            f"the activation threshold of {threshold:.3f}"
        ),
    )


def _safe_update_training_run(run_id: str | None, updates: dict):
    if not run_id:
        return
    try:
        supabase_client.table("training_runs").update(updates).eq(
            "id", run_id
        ).execute()
    except Exception:
        _request_logger(route="rf_train", run_id=run_id).exception(
            "Failed to update training run status"
        )


def _job_logger(**fields):
    return logger.bind(request_id=str(uuid4()), **fields)


def _resolve_analysis_org_id(
    org_id: str | None, requested_by: str | None = None
) -> str:
    if _is_uuid(org_id):
        return str(org_id)

    if requested_by and _is_uuid(requested_by):
        user_result = (
            supabase_client.table("users")
            .select("org_id")
            .eq("id", requested_by)
            .limit(1)
            .execute()
        )
        user_row = (user_result.data or [None])[0]
        resolved_org_id = user_row.get("org_id") if user_row else None
        if _is_uuid(resolved_org_id):
            return str(resolved_org_id)

    raise ValueError("org_id must be a UUID or resolvable from requested_by")


def _resolve_requested_by_id(requested_by: str | None) -> str | None:
    if not _is_uuid(requested_by):
        return None

    try:
        user_result = (
            supabase_client.table("users")
            .select("id")
            .eq("id", requested_by)
            .limit(1)
            .execute()
        )
    except Exception:
        return None

    user_row = (user_result.data or [None])[0]
    return str(user_row["id"]) if user_row and user_row.get("id") else None


def _update_analysis_job(job_id: str, updates: dict):
    try:
        _execute_with_retry(
            lambda: (
                supabase_client.table("analysis_jobs")
                .update(updates)
                .eq("id", job_id)
                .execute()
            )
        )
    except Exception:
        _job_logger(route="update_analysis_job", job_id=job_id).exception(
            "Failed to update analysis job status"
        )


def _update_analysis_job_item(item_id: str, updates: dict):
    try:
        _execute_with_retry(
            lambda: (
                supabase_client.table("analysis_job_items")
                .update(updates)
                .eq("id", item_id)
                .execute()
            )
        )
    except Exception:
        _job_logger(route="update_analysis_job_item", item_id=item_id).exception(
            "Failed to update analysis job item status"
        )


def _create_background_analysis_job_internal(
    org_id: str,
    filename: str,
    source_type: str,
    requested_by: str | None = None,
    output_path: str | None = None,
):
    resolved_org_id = _resolve_analysis_org_id(org_id, requested_by=requested_by)
    resolved_requested_by = _resolve_requested_by_id(requested_by)
    resolved_output_path = output_path or f"{resolved_org_id}/{filename}"
    job_result = (
        supabase_client.table("analysis_jobs")
        .insert(
            {
                "org_id": resolved_org_id,
                "requested_by": resolved_requested_by,
                "status": "queued",
                "source_type": source_type,
                "total_files": 1,
                "processed_files": 0,
                "failed_files": 0,
                "progress_pct": 0,
                "output_path": resolved_output_path,
            }
        )
        .execute()
    )
    job_id = job_result.data[0]["id"]

    item_result = (
        supabase_client.table("analysis_job_items")
        .insert(
            {
                "job_id": job_id,
                "file_name": filename,
                "status": "queued",
                "entry_count": 0,
                "progress_pct": 0,
            }
        )
        .execute()
    )
    item_id = item_result.data[0]["id"]

    worker = Thread(
        target=_run_background_analysis_job,
        args=(
            job_id,
            item_id,
            resolved_org_id,
            filename,
            source_type,
            resolved_output_path,
        ),
        daemon=True,
    )
    worker.start()

    return job_id, item_id


def _build_upload_manifest(session: dict):
    return {
        "session_id": session["session_id"],
        "org_id": session["org_id"],
        "filename": session["filename"],
        "source_type": session["source_type"],
        "status": session["status"],
        "created_at": session["created_at"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total_parts": session.get("total_parts"),
        "received_parts": sorted(session.get("received_parts", [])),
        "parts": [
            {
                "part_number": part_number,
                "path": path,
                "size_bytes": session["part_sizes"].get(part_number),
            }
            for part_number, path in sorted(session["parts"].items())
        ],
        "assembled_path": session.get("assembled_path"),
        "job_id": session.get("job_id"),
    }


def _persist_upload_manifest(session: dict):
    manifest_path = f"{session['session_prefix']}/manifest.json"
    manifest = _build_upload_manifest(session)
    try:
        upload_binary(
            path=manifest_path,
            file_bytes=json.dumps(manifest).encode("utf-8"),
            bucket_name=BUCKET_NAME,
            content_type="application/json",
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to store upload session manifest at {manifest_path}: {exc}"
        ) from exc
    session["manifest_path"] = manifest_path


def _download_file_with_retry(storage_path: str, attempts: int = 3) -> bytes:
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            return download_file(storage_path)
        except Exception as exc:
            last_error = exc
            if attempt < attempts:
                time.sleep(min(1.5 * attempt, 4.5))

    raise last_error


def _run_background_analysis_job(
    job_id: str,
    item_id: str,
    org_id: str,
    filename: str,
    source_type: str,
    storage_path: str,
):
    log = _job_logger(
        route="run_background_analysis_job",
        job_id=job_id,
        item_id=item_id,
        org_id=org_id,
        filename=filename,
    )
    file_id = None

    try:
        _update_analysis_job(
            job_id,
            {
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "progress_pct": 5,
            },
        )
        _update_analysis_job_item(
            item_id,
            {
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "progress_pct": 5,
            },
        )

        if storage_path.endswith("/manifest.json"):
            manifest_bytes = _download_file_with_retry(storage_path)
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            parts = manifest.get("parts") or []
            if not parts:
                raise ValueError("Upload manifest does not contain parts")

            assembled_chunks = []
            for part in parts:
                part_path = part.get("path")
                if not part_path:
                    continue
                assembled_chunks.append(_download_file_with_retry(part_path))

            if not assembled_chunks:
                raise ValueError("Failed to download upload parts from manifest")

            file_bytes = b"".join(assembled_chunks)
        else:
            file_bytes = _download_file_with_retry(storage_path)
        _update_analysis_job(job_id, {"progress_pct": 15})
        _update_analysis_job_item(item_id, {"progress_pct": 15})

        parsed = parse_file_with_metadata(file_bytes, filename)
        entries = parsed.get("entries", [])
        metadata = parsed.get("metadata", {})
        if len(entries) > BACKGROUND_PARSE_MAX_ROWS:
            entries = entries[:BACKGROUND_PARSE_MAX_ROWS]
            metadata_warnings = metadata.get("warnings", [])
            metadata_warnings.append(
                f"Capped parsed rows to {BACKGROUND_PARSE_MAX_ROWS} for background analysis."
            )
            metadata["warnings"] = metadata_warnings

        _update_analysis_job_item(
            item_id,
            {
                "entry_count": len(entries),
                "progress_pct": 30,
            },
        )
        _update_analysis_job(job_id, {"progress_pct": 30})

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
        _update_analysis_job_item(item_id, {"file_id": file_id, "progress_pct": 40})
        _update_analysis_job(job_id, {"progress_pct": 40})

        rows = [
            {
                "org_id": org_id,
                "payload": entry,
                "file_id": file_id,
            }
            for entry in entries
        ]
        total_batches = max(
            1, (len(rows) + RAW_LOG_INSERT_BATCH_SIZE - 1) // RAW_LOG_INSERT_BATCH_SIZE
        )
        for batch_index, start in enumerate(
            range(0, len(rows), RAW_LOG_INSERT_BATCH_SIZE), start=1
        ):
            batch = rows[start : start + RAW_LOG_INSERT_BATCH_SIZE]
            _execute_with_retry(
                lambda payload=batch: (
                    supabase_client.table("raw_logs").insert(payload).execute()
                )
            )

            # Keep UI responsive for large datasets by reporting intermediate insert progress.
            if batch_index == total_batches or batch_index % 10 == 0:
                insert_progress = 40 + round((batch_index / total_batches) * 15)
                _update_analysis_job_item(item_id, {"progress_pct": insert_progress})
                _update_analysis_job(job_id, {"progress_pct": insert_progress})

        _update_analysis_job_item(item_id, {"progress_pct": 55})
        _update_analysis_job(job_id, {"progress_pct": 55})

        pipeline_result = run_analysis_pipeline(
            entries,
            org_id,
            file_id,
            source_type,
            request_id=str(uuid4()),
            log=log,
        )
        detections = pipeline_result["detections"]
        rf_results = pipeline_result["rf_results"]
        analysis = pipeline_result["analysis"]
        _update_analysis_job_item(item_id, {"progress_pct": 68})
        _update_analysis_job(job_id, {"progress_pct": 68})
        _update_analysis_job_item(item_id, {"progress_pct": 82})
        _update_analysis_job(job_id, {"progress_pct": 82})

        analysis_result_id = _store_analysis_result(
            file_id=file_id,
            org_id=org_id,
            analysis=analysis,
            detections=detections,
        )
        _update_analysis_job_item(
            item_id,
            {
                "result_id": analysis_result_id,
                "progress_pct": 94,
            },
        )
        _update_analysis_job(job_id, {"progress_pct": 94})

        _build_actionable_insights_payload(
            threats=analysis.get("detailed_findings", []),
            detections=detections,
            logs=entries,
            source_type=source_type,
            rf_results=rf_results,
        )

        supabase_client.table("log_files").update({"status": "completed"}).eq(
            "id", file_id
        ).execute()

        _update_analysis_job_item(
            item_id,
            {
                "status": "completed",
                "progress_pct": 100,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        _update_analysis_job(
            job_id,
            {
                "status": "completed",
                "processed_files": 1,
                "failed_files": 0,
                "progress_pct": 100,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "output_path": storage_path,
            },
        )

    except Exception as exc:
        if file_id:
            try:
                supabase_client.table("log_files").update({"status": "failed"}).eq(
                    "id", file_id
                ).execute()
            except Exception:
                log.exception("Failed to set log file to failed")

        _update_analysis_job_item(
            item_id,
            {
                "status": "failed",
                "progress_pct": 100,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": str(exc),
            },
        )
        _update_analysis_job(
            job_id,
            {
                "status": "failed",
                "processed_files": 0,
                "failed_files": 1,
                "progress_pct": 100,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": str(exc),
            },
        )
        log.exception("Background analysis job failed")


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


