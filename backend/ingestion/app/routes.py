from flask import Blueprint, request, jsonify, g, Response, stream_with_context
from . import supabase_client
from .normalization import normalize_log
from .file_parser import parse_file, parse_file_with_metadata
from .rag_service import analyze_threats
from .correlation_engine import run_correlation
from .timeline_service import get_file_timeline, get_org_timeline, get_file_timeline_graph, get_org_timeline_graph
from .storage import upload_file, download_file, upload_binary, download_binary, BUCKET_NAME
from .log_classifier import get_classifier
from .insights_generator import get_insights_generator
from .kaggle import prepare_cicids2019_training_bundle
from datetime import datetime, timezone
from time import perf_counter
from uuid import UUID, uuid4
from pathlib import Path
from threading import Thread, Lock
import time
import json
import os
import re
import structlog 

main = Blueprint('main', __name__)
logger = structlog.get_logger(__name__)

RAW_LOG_INSERT_BATCH_SIZE = 200
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
BACKGROUND_PARSE_MAX_ROWS = int(os.getenv('BACKGROUND_PARSE_MAX_ROWS', '200000'))
SUPABASE_RETRY_ATTEMPTS = int(os.getenv('SUPABASE_RETRY_ATTEMPTS', '4'))
SUPABASE_RETRY_BASE_DELAY_SECONDS = float(os.getenv('SUPABASE_RETRY_BASE_DELAY_SECONDS', '0.8'))
MAX_UPLOAD_PART_BYTES = int(os.getenv('MAX_UPLOAD_PART_BYTES', str(16 * 1024 * 1024)))
MAX_UPLOAD_SESSION_ASSEMBLY_BYTES = int(os.getenv('MAX_UPLOAD_SESSION_ASSEMBLY_BYTES', str(2 * 1024 * 1024 * 1024)))
UPLOAD_SESSION_TTL_SECONDS = int(os.getenv('UPLOAD_SESSION_TTL_SECONDS', '3600'))
MAX_UPLOAD_SESSIONS = int(os.getenv('MAX_UPLOAD_SESSIONS', '100'))

_upload_sessions: dict[str, dict] = {}
_upload_sessions_lock = Lock()


def _evict_expired_sessions():
    """Remove expired sessions. Must be called while holding _upload_sessions_lock."""
    now = time.time()
    expired = [
        sid for sid, session in _upload_sessions.items()
        if now - session.get('created_at_ts', 0) > UPLOAD_SESSION_TTL_SECONDS
    ]
    for sid in expired:
        del _upload_sessions[sid]

_PUBLIC_ENDPOINTS = {'main.root'}


def _request_json_dict() -> dict:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def _org_exists(org_id: str | None) -> bool:
    if not _is_uuid(org_id):
        return False
    try:
        org_result = supabase_client.table('organizations').select('id').eq('id', org_id).limit(1).execute()
    except Exception:
        return False
    return bool(org_result.data)


def _resolve_org_from_file_id(file_id: str | None) -> str | None:
    if not _is_uuid(file_id):
        return None
    try:
        file_result = supabase_client.table('log_files').select('org_id').eq('id', file_id).limit(1).execute()
    except Exception:
        return None
    file_row = (file_result.data or [None])[0]
    org_id = file_row.get('org_id') if file_row else None
    return str(org_id) if _is_uuid(org_id) else None


def _resolve_bootstrap_org_id() -> str | None:
    payload = _request_json_dict()
    candidates = [
        payload.get('org_id'),
        request.form.get('org_id'),
        request.args.get('org_id'),
        (request.view_args or {}).get('org_id'),
    ]

    for candidate in candidates:
        if _org_exists(candidate):
            return str(candidate)

    file_candidates = [
        payload.get('file_id'),
        request.form.get('file_id'),
        request.args.get('file_id'),
        (request.view_args or {}).get('file_id'),
    ]

    for file_id in file_candidates:
        resolved = _resolve_org_from_file_id(file_id)
        if resolved:
            return resolved

    return None


# New endpoint: GET /analysis-jobs
@main.route('/analysis-jobs', methods=['GET'])
def list_analysis_jobs():
    """Return a list of analysis jobs filtered by org_id and limited by 'limit' query param."""
    log = _request_logger(route='list_analysis_jobs')
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    org_id = request.args.get('org_id')
    limit = request.args.get('limit', 10)
    try:
        limit = int(limit)
        if limit <= 0 or limit > 100:
            limit = 10
    except Exception:
        limit = 10

    if not org_id or not _is_uuid(org_id):
        return _error_response('org_id is required and must be a valid UUID', 400, 'VALIDATION_ERROR')

    try:
        jobs_result = supabase_client.table('analysis_jobs') \
            .select('*') \
            .eq('org_id', org_id) \
            .order('created_at', desc=True) \
            .limit(limit) \
            .execute()
        jobs = jobs_result.data or []
    except Exception:
        log.exception('Failed to fetch analysis jobs')
        return _error_response('Failed to fetch analysis jobs', 500, 'DATABASE_ERROR', retryable=True)

    return jsonify({
        'jobs': _serialize_timestamps(jobs),
        'request_id': _get_request_id(),
    }), 200


def _dataset_to_model_label(dataset_name: str | None) -> str:
    raw_value = str(dataset_name or '').strip().lower()
    if not raw_value:
        return 'cicids2019'

    normalized = re.sub(r'[^a-z0-9]+', '-', raw_value).strip('-')
    return normalized or 'cicids2019'


def _dataset_to_model_name(dataset_name: str | None) -> str:
    return f"rf-{_dataset_to_model_label(dataset_name)}"


def _load_latest_rf_model(org_id: str | None = None, model_name: str | None = None) -> dict:
    base_query = (
        supabase_client.table('model_versions')
        .select('id, org_id, version, artifact_bucket, artifact_path, status, created_at')
        .eq('status', 'active')
        .order('created_at', desc=True)
    )
    if org_id:
        base_query = base_query.eq('org_id', org_id)

    model_result = None
    if model_name:
        model_result = base_query.eq('name', model_name).limit(1).execute()

    if not model_result or not model_result.data:
        model_result = base_query.limit(1).execute()

    if not model_result.data:
        raise ValueError('No active RF model version found')

    model_row = model_result.data[0]
    artifact_path = model_row.get('artifact_path')
    artifact_bucket = model_row.get('artifact_bucket')
    if not artifact_path:
        raise ValueError('Active RF model version has no artifact_path')

    artifact_bytes = download_binary(artifact_path, bucket_name=artifact_bucket)
    local_path = Path(__file__).parent / '.models' / 'rf_classifier.pkl'
    local_path.parent.mkdir(parents=True, exist_ok=True)
    with open(local_path, 'wb') as model_file:
        model_file.write(artifact_bytes)

    classifier = get_classifier()
    load_result = classifier.load_model(str(local_path))
    if load_result.get('ERROR'):
        raise ValueError(load_result['ERROR'])

    return {
        'model_version_id': model_row.get('id'),
        'model_version': model_row.get('version'),
        'org_id': model_row.get('org_id'),
        'artifact_path': artifact_path,
        'artifact_bucket': artifact_bucket,
        'local_path': str(local_path),
    }

@main.before_request
def _set_request_id():
    request_id = request.headers.get('X-Request-ID')
    g.request_id = request_id or str(uuid4())
    g.request_started_at = perf_counter()


@main.before_request
def _authenticate_request():
    endpoint = request.endpoint or ''
    if request.method == 'OPTIONS' or endpoint in _PUBLIC_ENDPOINTS:
        return None

    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return _error_response('Missing Authorization bearer token', 401, 'UNAUTHORIZED')

    token = auth_header.split(' ', 1)[1].strip()
    if not token:
        return _error_response('Missing Authorization bearer token', 401, 'UNAUTHORIZED')

    try:
        auth_result = supabase_client.auth.get_user(token)
    except Exception:
        return _error_response('Invalid access token', 401, 'UNAUTHORIZED')

    auth_user = getattr(auth_result, 'user', None)
    if auth_user is None and isinstance(auth_result, dict):
        auth_user = auth_result.get('user')

    user_id = None
    if isinstance(auth_user, dict):
        user_id = auth_user.get('id')
    else:
        user_id = getattr(auth_user, 'id', None)

    if not _is_uuid(user_id):
        return _error_response('Unable to resolve authenticated user', 401, 'UNAUTHORIZED')

    try:
        user_result, _user_select_expr = _select_with_fallback(
            'users',
            [
                'id, org_id, role',
                'id, org_id',
                'id',
            ],
            lambda query: query.eq('id', user_id).limit(1),
        )
    except Exception:
        return _error_response('Failed to resolve user context', 500, 'DATABASE_ERROR', retryable=True)

    user_row = (user_result.data or [None])[0]
    if not user_row:
        if isinstance(auth_user, dict):
            email = auth_user.get('email')
            app_metadata = auth_user.get('app_metadata') or {}
            user_metadata = auth_user.get('user_metadata') or {}
        else:
            email = getattr(auth_user, 'email', None)
            app_metadata = getattr(auth_user, 'app_metadata', {}) or {}
            user_metadata = getattr(auth_user, 'user_metadata', {}) or {}

        claim_org_id = app_metadata.get('org_id') or user_metadata.get('org_id') or _resolve_bootstrap_org_id()
        claim_role = str(app_metadata.get('role') or user_metadata.get('role') or 'viewer').strip().lower()
        if claim_role not in {'admin', 'analyst', 'viewer'}:
            claim_role = 'viewer'

        if not _is_uuid(claim_org_id) or not _org_exists(claim_org_id):
            return _error_response(
                'Authenticated user is not provisioned',
                403,
                'FORBIDDEN',
                details={
                    'hint': 'Create a users row with id, org_id, email, and role, or include org_id in auth metadata.',
                },
            )

        provisioned = False
        upsert_payload_candidates = [
            {
                'id': user_id,
                'org_id': str(claim_org_id),
                'email': email or '',
                'role': claim_role,
            },
            {
                'id': user_id,
                'org_id': str(claim_org_id),
                'role': claim_role,
            },
            {
                'id': user_id,
                'org_id': str(claim_org_id),
                'email': email or '',
            },
            {
                'id': user_id,
                'org_id': str(claim_org_id),
            },
        ]

        for upsert_payload in upsert_payload_candidates:
            try:
                supabase_client.table('users').upsert(upsert_payload, on_conflict='id').execute()
                provisioned = True
                break
            except Exception:
                continue

        if not provisioned:
            return _error_response('Failed to provision authenticated user context', 500, 'DATABASE_ERROR', retryable=True)

        try:
            user_result, _user_select_expr = _select_with_fallback(
                'users',
                [
                    'id, org_id, role',
                    'id, org_id',
                    'id',
                ],
                lambda query: query.eq('id', user_id).limit(1),
            )
            user_row = (user_result.data or [None])[0]
        except Exception:
            return _error_response('Failed to provision authenticated user context', 500, 'DATABASE_ERROR', retryable=True)

        if not user_row:
            return _error_response('Authenticated user is not provisioned', 403, 'FORBIDDEN')

    org_id = user_row.get('org_id')
    role = user_row.get('role') or 'viewer'
    if not _is_uuid(org_id):
        bootstrap_org_id = _resolve_bootstrap_org_id()
        if not bootstrap_org_id:
            return _error_response('Authenticated user has no org context', 403, 'FORBIDDEN')
        try:
            supabase_client.table('users').update({'org_id': bootstrap_org_id}).eq('id', user_id).execute()
            org_id = bootstrap_org_id
        except Exception:
            return _error_response('Failed to provision authenticated user context', 500, 'DATABASE_ERROR', retryable=True)

    g.auth_user_id = str(user_row['id'])
    g.auth_org_id = str(org_id)
    g.auth_role = str(role or 'viewer')
    return None


@main.after_request
def _log_request_timing(response):
    started_at = getattr(g, 'request_started_at', None)
    elapsed_ms = None
    if started_at is not None:
        elapsed_ms = round((perf_counter() - started_at) * 1000, 2)

    _request_logger(
        route=(request.url_rule.rule if request.url_rule else request.path),
        method=request.method,
        status_code=response.status_code,
        elapsed_ms=elapsed_ms,
    ).info('Request completed')
    return response


def _get_request_id() -> str:
    request_id = getattr(g, 'request_id', None)
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
        'error': {
            'code': error_code,
            'message': message,
            'retryable': retryable,
            'request_id': _get_request_id(),
        }
    }
    if details:
        payload['error']['details'] = details
    return jsonify(payload), status


def _auth_org_id() -> str:
    return str(getattr(g, 'auth_org_id', '') or '')


def _auth_user_id() -> str:
    return str(getattr(g, 'auth_user_id', '') or '')


def _auth_role() -> str:
    return str(getattr(g, 'auth_role', 'viewer') or 'viewer').strip().lower()


def _require_roles(*allowed_roles: str):
    normalized_allowed = {str(role).strip().lower() for role in allowed_roles if role}
    current_role = _auth_role()
    if current_role not in normalized_allowed:
        return _error_response(
            'Insufficient role permissions for this endpoint',
            403,
            'FORBIDDEN',
            details={
                'required_roles': sorted(normalized_allowed),
                'current_role': current_role,
            },
        )
    return None


def _enforce_org_scope(requested_org_id: str | None) -> tuple[str | None, tuple | None]:
    auth_org_id = _auth_org_id()
    if not auth_org_id:
        return None, _error_response('Missing authenticated organization context', 403, 'FORBIDDEN')

    if requested_org_id and str(requested_org_id) != auth_org_id:
        return None, _error_response('Cross-organization access denied', 403, 'FORBIDDEN')

    return auth_org_id, None


def _file_org_id(file_id: str) -> str | None:
    file_result = supabase_client.table('log_files').select('org_id').eq('id', file_id).limit(1).execute()
    file_row = (file_result.data or [None])[0]
    if not file_row:
        return None
    org_id = file_row.get('org_id')
    return str(org_id) if _is_uuid(org_id) else None


def _enforce_file_scope(file_id: str) -> tuple[str | None, tuple | None]:
    org_id = _file_org_id(file_id)
    if not org_id:
        return None, _error_response('File not found', 404, 'NOT_FOUND')
    _, scope_error = _enforce_org_scope(org_id)
    if scope_error:
        return None, scope_error
    return org_id, None


def _incident_org_id(incident_id: str) -> str | None:
    if not _is_uuid(incident_id):
        return None
    result = supabase_client.table('incidents').select('org_id').eq('id', incident_id).limit(1).execute()
    row = (result.data or [None])[0]
    org_id = row.get('org_id') if row else None
    return str(org_id) if _is_uuid(org_id) else None


def _task_org_id(task_id: str) -> str | None:
    if not _is_uuid(task_id):
        return None
    result = supabase_client.table('tasks').select('org_id').eq('id', task_id).limit(1).execute()
    row = (result.data or [None])[0]
    org_id = row.get('org_id') if row else None
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
        rule_name = detection.get('rule_name') or 'correlation_rule'
        description = detection.get('description') or f"Correlation rule '{rule_name}' triggered"
        threats.append({
            'threat_type': rule_name,
            'severity': _normalize_severity(detection.get('severity')),
            'description': description,
            'timestamp': detection.get('detected_at') or detection.get('created_at'),
            'affected_entries': detection.get('matched_event_indices', []),
            'indicators': [
                f"MITRE: {detection.get('mitre_technique')}" if detection.get('mitre_technique') else "",
                f"confidence={detection.get('confidence')}" if detection.get('confidence') is not None else "",
            ],
        })

    for threat in threats:
        threat['indicators'] = [i for i in threat.get('indicators', []) if i]
    return threats


def _execute_with_retry(operation, attempts: int | None = None, base_delay_seconds: float | None = None):
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
            'org_id': org_id,
            'payload': entry,
            'file_id': file_id,
        }
        for entry in entries
    ]

    for i in range(0, len(rows), RAW_LOG_INSERT_BATCH_SIZE):
        batch = rows[i:i + RAW_LOG_INSERT_BATCH_SIZE]
        _execute_with_retry(
            lambda payload=batch: supabase_client.table('raw_logs').insert(payload).execute()
        )

def _build_mitre_link_rows(analysis_result_id: str, org_id: str, file_id: str, mitre_techniques) -> list[dict]:
    rows = []
    for idx, technique in enumerate(mitre_techniques or [], start=1):
        if not isinstance(technique, dict):
            continue

        technique_id = technique.get('technique_id') or technique.get('id')
        if not technique_id:
            continue

        rows.append({
            'analysis_result_id': analysis_result_id,
            'org_id': org_id,
            'file_id': file_id,
            'technique_id': str(technique_id).strip(),
            'technique_name': technique.get('name'),
            'tactic': technique.get('tactic'),
            'relevance': technique.get('relevance'),
            'similarity_score': technique.get('similarity'),
            'rank_position': idx,
        })

    return rows

def _store_analysis_result(
    file_id: str,
    org_id: str,
    analysis: dict,
    detections: list[dict] | None = None,
) -> str | None:
    payload = {
        'file_id': file_id,
        'threat_level': analysis['threat_level'],
        'threats_found': analysis['threats_found'],
        'summary': analysis['summary'],
        'detailed_findings': analysis['detailed_findings'],
        'mitre_techniques': analysis.get('mitre_techniques'),
        'attack_vector': analysis.get('attack_vector'),
        'timeline': analysis.get('timeline'),
        'impacted_assets': analysis.get('impacted_assets'),
        'confidence_score': analysis.get('confidence_score'),
        'remediation_steps': analysis.get('remediation_steps'),
        'correlation_detections': detections or [],
        'verdict_sources': analysis.get('verdict_sources'),
    }

    try:
        insert_result = supabase_client.table('analysis_results').insert(payload).execute()
    except Exception as exc:
        # Keep compatibility with databases that have not yet applied verdict_sources migration.
        if 'verdict_sources' not in str(exc):
            raise
        payload.pop('verdict_sources', None)
        insert_result = supabase_client.table('analysis_results').insert(payload).execute()

    analysis_result_id = None
    if insert_result.data:
        analysis_result_id = insert_result.data[0].get('id')

    if not analysis_result_id:
        fallback = supabase_client.table('analysis_results').select('id').eq('file_id', file_id).order(
            'created_at',
            desc=True,
        ).limit(1).execute()
        if fallback.data:
            analysis_result_id = fallback.data[0].get('id')

    if not analysis_result_id:
        return None

    mitre_rows = _build_mitre_link_rows(
        analysis_result_id=analysis_result_id,
        org_id=org_id,
        file_id=file_id,
        mitre_techniques=analysis.get('mitre_techniques') or [],
    )

    if mitre_rows:
        try:
            supabase_client.table('analysis_result_mitre_links').upsert(
                mitre_rows,
                on_conflict='analysis_result_id,technique_id',
            ).execute()
        except Exception:
            _request_logger(route='store_analysis_result', file_id=file_id, org_id=org_id).exception(
                'Failed to persist normalized MITRE links'
            )

    return analysis_result_id

def _get_mitre_links_for_analysis(analysis_result_id: str) -> list[dict]:
    links_result = supabase_client.table('analysis_result_mitre_links').select(
        'technique_id, technique_name, tactic, relevance, similarity_score, rank_position, created_at'
    ).eq('analysis_result_id', analysis_result_id).order('rank_position', desc=False).execute()
    return links_result.data or []

def _build_actionable_insights_payload(
    threats=None,
    detections=None,
    logs=None,
    source_type='custom',
    rf_results=None,
):
    
    threats = threats or []
    detections = detections or []
    logs = logs or []

    if not threats and detections:
        threats = _detections_to_threats(detections)

    if not threats:
        return {
            'status': 'no_threats',
            'source_type': source_type,
            'threat_count': 0,
            'detection_count': len(detections),
            'classification_context': {
                'total': 0,
                'by_category': {},
                'average_confidence': 0.0,
            },
            'insights': [],
            'incident_summary': {
                'status': 'no_threats',
                'summary': 'No threats detected',
                'logs_analyzed': len(logs),
                'risk_level': 'low',
            },
            'investigation_guide': {},
        }

    classification_context = {
        'total': 0,
        'by_category': {},
        'average_confidence': 0.0,
    }

    if logs:
        if rf_results is None:
            classifier = get_classifier()
            rf_results = classifier.classify_batch(logs)
        by_category = {}
        by_severity = {}
        confidences = []
        for result in rf_results:
            category = result.get('category', 'unknown')
            by_category[category] = by_category.get(category, 0) + 1
            
            # Track severity distribution
            severity = result.get('adjusted_severity', result.get('mitre_severity', 'medium'))
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            confidences.append(result.get('confidence', 0.0))

        classification_context = {
            'total': len(rf_results),
            'by_category': by_category,
            'by_severity': by_severity,
            'average_confidence': (sum(confidences) / len(confidences)) if confidences else 0.0,
            'details': rf_results[:50],
        }

    insights_generator = get_insights_generator()
    insights = insights_generator.generate_threat_insights(threats)
    incident_summary = insights_generator.generate_incident_summary(
        threats,
        log_count=len(logs),
        correlation_data={'detection_count': len(detections)},
    )
    investigation_guide = insights_generator.generate_investigation_guide(
        classification_context,
        threats,
    )

    return {
        'status': 'completed',
        'source_type': source_type,
        'threat_count': len(threats),
        'detection_count': len(detections),
        'classification_context': classification_context,
        'insights': insights,
        'incident_summary': incident_summary,
        'investigation_guide': investigation_guide,
    }


def _build_rf_context(rf_results=None) -> dict:
    rf_results = rf_results or []

    by_severity = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    by_category = {}
    confidences = []

    high_confidence_threshold = 0.7
    high_conf_anomaly_count = 0
    high_conf_security_count = 0
    high_conf_error_count = 0

    for result in rf_results:
        if not isinstance(result, dict):
            continue

        confidence = float(result.get('confidence', 0.0) or 0.0)
        confidences.append(confidence)

        category = str(result.get('category', 'unknown')).strip().lower()
        by_category[category] = by_category.get(category, 0) + 1

        severity = _normalize_severity(result.get('adjusted_severity') or result.get('mitre_severity') or 'medium')
        by_severity[severity] = by_severity.get(severity, 0) + 1

        if confidence >= high_confidence_threshold:
            if severity == 'critical':
                high_conf_anomaly_count += 1
            elif severity == 'high':
                high_conf_security_count += 1
            elif severity == 'medium':
                high_conf_error_count += 1

    total = len(rf_results)
    average_confidence = (sum(confidences) / total) if total else 0.0

    return {
        'total': total,
        'average_confidence': average_confidence,
        'by_severity': by_severity,
        'by_category': by_category,
        'high_confidence_threshold': high_confidence_threshold,
        'high_conf_anomaly_count': high_conf_anomaly_count,
        'high_conf_security_count': high_conf_security_count,
        'high_conf_error_count': high_conf_error_count,
    }


def _get_activation_status(validation_metrics: dict | None, threshold: float) -> tuple[str, float, str | None]:
    precision_weighted = float((validation_metrics or {}).get('precision_weighted', 0.0) or 0.0)
    if precision_weighted >= threshold:
        return 'active', precision_weighted, None

    return (
        'archived',
        precision_weighted,
        (
            f'Validation weighted precision {precision_weighted:.3f} is below '
            f'the activation threshold of {threshold:.3f}'
        ),
    )


def _safe_update_training_run(run_id: str | None, updates: dict):
    if not run_id:
        return
    try:
        supabase_client.table('training_runs').update(updates).eq('id', run_id).execute()
    except Exception:
        _request_logger(route='rf_train', run_id=run_id).exception('Failed to update training run status')


def _job_logger(**fields):
    return logger.bind(request_id=str(uuid4()), **fields)


def _resolve_analysis_org_id(org_id: str | None, requested_by: str | None = None) -> str:
    if _is_uuid(org_id):
        return str(org_id)

    if requested_by and _is_uuid(requested_by):
        user_result = supabase_client.table('users').select('org_id').eq('id', requested_by).limit(1).execute()
        user_row = (user_result.data or [None])[0]
        resolved_org_id = user_row.get('org_id') if user_row else None
        if _is_uuid(resolved_org_id):
            return str(resolved_org_id)

    raise ValueError('org_id must be a UUID or resolvable from requested_by')


def _resolve_requested_by_id(requested_by: str | None) -> str | None:
    if not _is_uuid(requested_by):
        return None

    try:
        user_result = supabase_client.table('users').select('id').eq('id', requested_by).limit(1).execute()
    except Exception:
        return None

    user_row = (user_result.data or [None])[0]
    return str(user_row['id']) if user_row and user_row.get('id') else None


def _update_analysis_job(job_id: str, updates: dict):
    try:
        _execute_with_retry(
            lambda: supabase_client.table('analysis_jobs').update(updates).eq('id', job_id).execute()
        )
    except Exception:
        _job_logger(route='update_analysis_job', job_id=job_id).exception('Failed to update analysis job status')


def _update_analysis_job_item(item_id: str, updates: dict):
    try:
        _execute_with_retry(
            lambda: supabase_client.table('analysis_job_items').update(updates).eq('id', item_id).execute()
        )
    except Exception:
        _job_logger(route='update_analysis_job_item', item_id=item_id).exception('Failed to update analysis job item status')


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
    job_result = supabase_client.table('analysis_jobs').insert({
        'org_id': resolved_org_id,
        'requested_by': resolved_requested_by,
        'status': 'queued',
        'source_type': source_type,
        'total_files': 1,
        'processed_files': 0,
        'failed_files': 0,
        'progress_pct': 0,
        'output_path': resolved_output_path,
    }).execute()
    job_id = job_result.data[0]['id']

    item_result = supabase_client.table('analysis_job_items').insert({
        'job_id': job_id,
        'file_name': filename,
        'status': 'queued',
        'entry_count': 0,
        'progress_pct': 0,
    }).execute()
    item_id = item_result.data[0]['id']

    worker = Thread(
        target=_run_background_analysis_job,
        args=(job_id, item_id, resolved_org_id, filename, source_type, resolved_output_path),
        daemon=True,
    )
    worker.start()

    return job_id, item_id


def _build_upload_manifest(session: dict):
    return {
        'session_id': session['session_id'],
        'org_id': session['org_id'],
        'filename': session['filename'],
        'source_type': session['source_type'],
        'status': session['status'],
        'created_at': session['created_at'],
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'total_parts': session.get('total_parts'),
        'received_parts': sorted(session.get('received_parts', [])),
        'parts': [
            {
                'part_number': part_number,
                'path': path,
                'size_bytes': session['part_sizes'].get(part_number),
            }
            for part_number, path in sorted(session['parts'].items())
        ],
        'assembled_path': session.get('assembled_path'),
        'job_id': session.get('job_id'),
    }


def _persist_upload_manifest(session: dict):
    manifest_path = f"{session['session_prefix']}/manifest.json"
    manifest = _build_upload_manifest(session)
    try:
        upload_binary(
            path=manifest_path,
            file_bytes=json.dumps(manifest).encode('utf-8'),
            bucket_name=BUCKET_NAME,
            content_type='application/json',
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to store upload session manifest at {manifest_path}: {exc}"
        ) from exc
    session['manifest_path'] = manifest_path


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
    log = _job_logger(route='run_background_analysis_job', job_id=job_id, item_id=item_id, org_id=org_id, filename=filename)
    file_id = None

    try:
        _update_analysis_job(job_id, {
            'status': 'running',
            'started_at': datetime.now(timezone.utc).isoformat(),
            'progress_pct': 5,
        })
        _update_analysis_job_item(item_id, {
            'status': 'running',
            'started_at': datetime.now(timezone.utc).isoformat(),
            'progress_pct': 5,
        })

        if storage_path.endswith('/manifest.json'):
            manifest_bytes = _download_file_with_retry(storage_path)
            manifest = json.loads(manifest_bytes.decode('utf-8'))
            parts = manifest.get('parts') or []
            if not parts:
                raise ValueError('Upload manifest does not contain parts')

            assembled_chunks = []
            for part in parts:
                part_path = part.get('path')
                if not part_path:
                    continue
                assembled_chunks.append(_download_file_with_retry(part_path))

            if not assembled_chunks:
                raise ValueError('Failed to download upload parts from manifest')

            file_bytes = b''.join(assembled_chunks)
        else:
            file_bytes = _download_file_with_retry(storage_path)
        _update_analysis_job(job_id, {'progress_pct': 15})
        _update_analysis_job_item(item_id, {'progress_pct': 15})

        parsed = parse_file_with_metadata(file_bytes, filename)
        entries = parsed.get('entries', [])
        metadata = parsed.get('metadata', {})
        if len(entries) > BACKGROUND_PARSE_MAX_ROWS:
            entries = entries[:BACKGROUND_PARSE_MAX_ROWS]
            metadata_warnings = metadata.get('warnings', [])
            metadata_warnings.append(
                f"Capped parsed rows to {BACKGROUND_PARSE_MAX_ROWS} for background analysis."
            )
            metadata['warnings'] = metadata_warnings

        _update_analysis_job_item(item_id, {
            'entry_count': len(entries),
            'progress_pct': 30,
        })
        _update_analysis_job(job_id, {'progress_pct': 30})

        file_record = supabase_client.table('log_files').insert({
            'filename': filename,
            'org_id': org_id,
            'source_type': source_type,
            'storage_path': storage_path,
            'status': 'analyzing',
            'entry_count': len(entries)
        }).execute()
        file_id = file_record.data[0]['id']
        _update_analysis_job_item(item_id, {'file_id': file_id, 'progress_pct': 40})
        _update_analysis_job(job_id, {'progress_pct': 40})

        rows = [
            {
                'org_id': org_id,
                'payload': entry,
                'file_id': file_id,
            }
            for entry in entries
        ]
        total_batches = max(1, (len(rows) + RAW_LOG_INSERT_BATCH_SIZE - 1) // RAW_LOG_INSERT_BATCH_SIZE)
        for batch_index, start in enumerate(range(0, len(rows), RAW_LOG_INSERT_BATCH_SIZE), start=1):
            batch = rows[start:start + RAW_LOG_INSERT_BATCH_SIZE]
            _execute_with_retry(
                lambda payload=batch: supabase_client.table('raw_logs').insert(payload).execute()
            )

            # Keep UI responsive for large datasets by reporting intermediate insert progress.
            if batch_index == total_batches or batch_index % 10 == 0:
                insert_progress = 40 + round((batch_index / total_batches) * 15)
                _update_analysis_job_item(item_id, {'progress_pct': insert_progress})
                _update_analysis_job(job_id, {'progress_pct': insert_progress})

        _update_analysis_job_item(item_id, {'progress_pct': 55})
        _update_analysis_job(job_id, {'progress_pct': 55})

        try:
            detections = run_correlation(entries, org_id, file_id, request_id=str(uuid4()))
        except Exception:
            detections = []
            log.exception('Correlation engine failed')
        _update_analysis_job_item(item_id, {'progress_pct': 68})
        _update_analysis_job(job_id, {'progress_pct': 68})

        rf_results = []
        rf_context = _build_rf_context([])
        try:
            classifier = get_classifier()
            rf_results = classifier.classify_batch(entries)
            rf_context = _build_rf_context(rf_results)
        except Exception:
            log.exception('RF classification failed')

        analysis = analyze_threats(
            entries,
            source_type,
            detections=detections,
            rf_context=rf_context,
        )
        _update_analysis_job_item(item_id, {'progress_pct': 82})
        _update_analysis_job(job_id, {'progress_pct': 82})

        analysis_result_id = _store_analysis_result(
            file_id=file_id,
            org_id=org_id,
            analysis=analysis,
            detections=detections,
        )
        _update_analysis_job_item(item_id, {
            'result_id': analysis_result_id,
            'progress_pct': 94,
        })
        _update_analysis_job(job_id, {'progress_pct': 94})

        actionable_insights = _build_actionable_insights_payload(
            threats=analysis.get('detailed_findings', []),
            detections=detections,
            logs=entries,
            source_type=source_type,
            rf_results=rf_results,
        )

        supabase_client.table('log_files').update({'status': 'completed'}).eq('id', file_id).execute()

        _update_analysis_job_item(item_id, {
            'status': 'completed',
            'progress_pct': 100,
            'completed_at': datetime.now(timezone.utc).isoformat(),
        })
        _update_analysis_job(job_id, {
            'status': 'completed',
            'processed_files': 1,
            'failed_files': 0,
            'progress_pct': 100,
            'completed_at': datetime.now(timezone.utc).isoformat(),
            'output_path': storage_path,
        })

    except Exception as exc:
        if file_id:
            try:
                supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
            except Exception:
                log.exception('Failed to set log file to failed')

        _update_analysis_job_item(item_id, {
            'status': 'failed',
            'progress_pct': 100,
            'completed_at': datetime.now(timezone.utc).isoformat(),
            'error_message': str(exc),
        })
        _update_analysis_job(job_id, {
            'status': 'failed',
            'processed_files': 0,
            'failed_files': 1,
            'progress_pct': 100,
            'completed_at': datetime.now(timezone.utc).isoformat(),
            'error_message': str(exc),
        })
        log.exception('Background analysis job failed')


def _to_sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _progress_event(step: str, message: str, progress_pct: int, **extra):
    payload = {
        'step': step,
        'message': message,
        'progress_pct': progress_pct,
        'request_id': _get_request_id(),
    }
    payload.update(extra)
    return payload


@main.route('/', methods=['GET'])
def root():
    return jsonify({
        'service': 'AegisFA ingestion API',
        'status': 'ok',
        'message': 'Use the API endpoints under /ingest, /upload, /analysis, or /timeline.',
        'request_id': _get_request_id(),
    })

@main.route('/ingest', methods=['POST'])
def ingest():
    log = _request_logger(route='ingest')
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error
    data = request.get_json()
    if not data:
        return _error_response('JSON body required', 400, 'VALIDATION_ERROR')

    source = data.get('source')
    raw_data = data.get('raw_data')
    timestamp = data.get('timestamp', datetime.now(timezone.utc).isoformat())
    org_id, org_scope_error = _enforce_org_scope(data.get('org_id'))
    if org_scope_error:
        return org_scope_error

    if not source or raw_data is None:
        return _error_response('source and raw_data are required', 400, 'VALIDATION_ERROR')

    try:
        raw_result = supabase_client.table('raw_logs').insert({
            'org_id': org_id,
            'source_id': data.get('source_id'),
            'payload': raw_data,
            'received_at': timestamp
        }).execute()
    except Exception:
        log.exception('Failed to store raw log')
        return _error_response('Failed to store raw log', 500, 'DATABASE_ERROR', retryable=True)

    if not raw_result.data:
        return _error_response('Failed to store raw log', 500, 'DATABASE_ERROR', retryable=True)

    raw_log_id = raw_result.data[0]['id']

    normalized = normalize_log(source, raw_data)
    try:
        norm_result = supabase_client.table('normalized_events').insert({
            'org_id': org_id,
            'raw_log_id': raw_log_id,
            'source_id': data.get('source_id'),
            'event_type': normalized.get('action'),
            'severity': normalized.get('status')
        }).execute()
    except Exception:
        log.exception('Failed to store normalized event', raw_log_id=raw_log_id)
        return _error_response('Failed to store normalized event', 500, 'DATABASE_ERROR', retryable=True)

    if not norm_result.data:
        return _error_response('Failed to store normalized event', 500, 'DATABASE_ERROR', retryable=True)

    return jsonify({
        'raw_log_id': raw_log_id,
        'normalized_event_id': norm_result.data[0]['id'],
        'normalized_data': normalized,
        'request_id': _get_request_id(),
    }), 201

@main.route('/upload', methods=['POST'])
def upload_log_file():
    log = _request_logger(route='upload_log_file')
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error

    if 'file' not in request.files:
        return _error_response('No file provided', 400, 'VALIDATION_ERROR')

    file = request.files['file']
    source_type = request.form.get('source_type')
    org_id, org_scope_error = _enforce_org_scope(request.form.get('org_id'))
    if org_scope_error:
        return org_scope_error
    log = log.bind(org_id=org_id, filename=file.filename)

    if not source_type or source_type not in {'windows', 'firewall', 'auth', 'syslog', 'custom'}:
        return _error_response('source_type must be one of: windows, firewall, auth, syslog, custom', 400, 'VALIDATION_ERROR')

    file_bytes = file.read()

    try:
        entries = parse_file(file_bytes, file.filename)
    except Exception:
        log.exception('Failed to parse file')
        return _error_response('Failed to parse file', 400, 'PARSING_ERROR')

    try:
        storage_path = upload_file(file_bytes, file.filename, org_id)
    except Exception:
        log.exception('Failed to upload file to storage')
        return _error_response('Failed to upload file to storage', 500, 'STORAGE_ERROR', retryable=True)

    try:
        file_record = supabase_client.table('log_files').insert({
            'filename': file.filename,
            'org_id': org_id,
            'source_type': source_type,
            'storage_path': storage_path,
            'status': 'analyzing',
            'entry_count': len(entries)
        }).execute()

        file_id = file_record.data[0]['id']
        log = log.bind(file_id=file_id)
    except Exception:
        log.exception('Failed to save file record')
        return _error_response('Failed to save file record', 500, 'DATABASE_ERROR', retryable=True)

    try:
        _insert_raw_logs_in_batches(entries, org_id, file_id)
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Failed to store log entries')
        return _error_response('Failed to store log entries', 500, 'DATABASE_ERROR', retryable=True)

    try:
        detections = run_correlation(entries, org_id, file_id, request_id=_get_request_id())
    except Exception:
        detections = []
        log.exception('Correlation engine failed')

    rf_results = []
    rf_context = _build_rf_context([])
    try:
        classifier = get_classifier()
        rf_results = classifier.classify_batch(entries)
        rf_context = _build_rf_context(rf_results)
    except Exception:
        log.exception('RF classification failed')

    try:
        analysis = analyze_threats(
            entries,
            source_type,
            detections=detections,
            rf_context=rf_context,
        )
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Threat analysis failed')
        return _error_response('Threat analysis failed', 500, 'ANALYSIS_ERROR', retryable=True)

    try:
        _store_analysis_result(
            file_id=file_id,
            org_id=org_id,
            analysis=analysis,
            detections=detections,
        )
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Failed to store analysis')
        return _error_response('Failed to store analysis', 500, 'DATABASE_ERROR', retryable=True)

    supabase_client.table('log_files').update({'status': 'completed'}).eq('id', file_id).execute()

    try:
        actionable_insights = _build_actionable_insights_payload(
            threats=analysis.get('detailed_findings', []),
            detections=detections,
            logs=entries,
            source_type=source_type,
            rf_results=rf_results,
        )
    except Exception:
        log.exception('Failed to generate actionable insights')
        actionable_insights = {
            'status': 'error',
            'message': 'Failed to generate actionable insights',
        }

    return jsonify({
        'file_id': file_id,
        'filename': file.filename,
        'entry_count': len(entries),
        'detections': detections,
        'detection_count': len(detections),
        'analysis': {
            'threat_level': analysis['threat_level'],
            'threats_found': analysis['threats_found'],
            'summary': analysis['summary'],
            'mitre_techniques': analysis.get('mitre_techniques'),
            'attack_vector': analysis.get('attack_vector'),
            'confidence_score': analysis.get('confidence_score'),
        },
        'actionable_insights': actionable_insights,
        'request_id': _get_request_id(),
    }), 201


@main.route('/upload/stream', methods=['POST'])
def upload_log_file_stream():
    """Upload and analyze a file while streaming progress updates via SSE."""

    def _stream():
        log = _request_logger(route='upload_log_file_stream')
        file_id = None

        role_error = _require_roles('admin', 'analyst')
        if role_error:
            yield _to_sse('error', _progress_event('forbidden', 'Insufficient role permissions for this endpoint', 0, error_code='FORBIDDEN'))
            return

        if 'file' not in request.files:
            yield _to_sse('error', _progress_event('validation_failed', 'No file provided', 0, error_code='VALIDATION_ERROR'))
            return

        file = request.files['file']
        source_type = request.form.get('source_type')
        org_id, org_scope_error = _enforce_org_scope(request.form.get('org_id'))
        if org_scope_error:
            yield _to_sse('error', _progress_event('forbidden', 'Cross-organization access denied', 0, error_code='FORBIDDEN'))
            return
        log = log.bind(org_id=org_id, filename=file.filename)

        if not source_type or source_type not in {'windows', 'firewall', 'auth', 'syslog', 'custom'}:
            yield _to_sse(
                'error',
                _progress_event(
                    'validation_failed',
                    'source_type must be one of: windows, firewall, auth, syslog, custom',
                    0,
                    error_code='VALIDATION_ERROR',
                ),
            )
            return

        file_bytes = file.read()
        yield _to_sse('progress', _progress_event('file_received', 'File received. Parsing log entries.', 5))

        try:
            entries = parse_file(file_bytes, file.filename)
            yield _to_sse(
                'progress',
                _progress_event('parsed', 'File parsed successfully.', 15, entry_count=len(entries)),
            )
        except Exception:
            log.exception('Failed to parse file')
            yield _to_sse('error', _progress_event('parsing_failed', 'Failed to parse file', 15, error_code='PARSING_ERROR'))
            return

        try:
            storage_path = upload_file(file_bytes, file.filename, org_id)
            yield _to_sse(
                'progress',
                _progress_event('uploaded', 'Uploaded file to storage.', 25, storage_path=storage_path),
            )
        except Exception:
            log.exception('Failed to upload file to storage')
            yield _to_sse('error', _progress_event('storage_failed', 'Failed to upload file to storage', 25, error_code='STORAGE_ERROR'))
            return

        try:
            file_record = supabase_client.table('log_files').insert({
                'filename': file.filename,
                'org_id': org_id,
                'source_type': source_type,
                'storage_path': storage_path,
                'status': 'analyzing',
                'entry_count': len(entries)
            }).execute()
            file_id = file_record.data[0]['id']
            log = log.bind(file_id=file_id)
            yield _to_sse('progress', _progress_event('file_record_created', 'Created file record.', 35, file_id=file_id))
        except Exception:
            log.exception('Failed to save file record')
            yield _to_sse('error', _progress_event('database_failed', 'Failed to save file record', 35, error_code='DATABASE_ERROR'))
            return

        try:
            _insert_raw_logs_in_batches(entries, org_id, file_id)
            yield _to_sse('progress', _progress_event('entries_stored', 'Stored parsed entries.', 50))
        except Exception:
            if file_id:
                supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
            log.exception('Failed to store log entries')
            yield _to_sse('error', _progress_event('database_failed', 'Failed to store log entries', 50, error_code='DATABASE_ERROR'))
            return

        try:
            detections = run_correlation(entries, org_id, file_id, request_id=_get_request_id())
        except Exception:
            detections = []
            log.exception('Correlation engine failed')
        yield _to_sse(
            'progress',
            _progress_event('correlation_complete', 'Correlation checks completed.', 62, detection_count=len(detections)),
        )

        rf_results = []
        rf_context = _build_rf_context([])
        try:
            classifier = get_classifier()
            rf_results = classifier.classify_batch(entries)
            rf_context = _build_rf_context(rf_results)
        except Exception:
            log.exception('RF classification failed')
        yield _to_sse('progress', _progress_event('classification_complete', 'RF classification completed.', 72))

        try:
            analysis = analyze_threats(
                entries,
                source_type,
                detections=detections,
                rf_context=rf_context,
            )
            yield _to_sse('progress', _progress_event('analysis_complete', 'Threat analysis completed.', 85))
        except Exception:
            if file_id:
                supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
            log.exception('Threat analysis failed')
            yield _to_sse('error', _progress_event('analysis_failed', 'Threat analysis failed', 85, error_code='ANALYSIS_ERROR'))
            return

        try:
            _store_analysis_result(
                file_id=file_id,
                org_id=org_id,
                analysis=analysis,
                detections=detections,
            )
            yield _to_sse('progress', _progress_event('result_stored', 'Stored analysis result.', 92))
        except Exception:
            if file_id:
                supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
            log.exception('Failed to store analysis')
            yield _to_sse('error', _progress_event('database_failed', 'Failed to store analysis', 92, error_code='DATABASE_ERROR'))
            return

        supabase_client.table('log_files').update({'status': 'completed'}).eq('id', file_id).execute()

        try:
            actionable_insights = _build_actionable_insights_payload(
                threats=analysis.get('detailed_findings', []),
                detections=detections,
                logs=entries,
                source_type=source_type,
                rf_results=rf_results,
            )
        except Exception:
            log.exception('Failed to generate actionable insights')
            actionable_insights = {
                'status': 'error',
                'message': 'Failed to generate actionable insights',
            }

        final_payload = {
            'file_id': file_id,
            'filename': file.filename,
            'entry_count': len(entries),
            'detections': detections,
            'detection_count': len(detections),
            'analysis': {
                'threat_level': analysis['threat_level'],
                'threats_found': analysis['threats_found'],
                'summary': analysis['summary'],
                'mitre_techniques': analysis.get('mitre_techniques'),
                'attack_vector': analysis.get('attack_vector'),
                'confidence_score': analysis.get('confidence_score'),
            },
            'actionable_insights': actionable_insights,
            'request_id': _get_request_id(),
        }
        yield _to_sse('progress', _progress_event('finalizing', 'Finalizing response.', 98))
        yield _to_sse('completed', _progress_event('completed', 'Analysis completed.', 100, result=final_payload))

    return Response(
        stream_with_context(_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        },
    )


@main.route('/analysis-jobs/from-storage', methods=['POST'])
def create_background_analysis_job():
    """Create an asynchronous analysis job for a file that already exists in storage."""
    log = _request_logger(route='create_background_analysis_job')
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}

    org_id, org_scope_error = _enforce_org_scope(payload.get('org_id'))
    if org_scope_error:
        return org_scope_error
    filename = payload.get('filename')
    source_type = payload.get('source_type')
    requested_by = _auth_user_id() or payload.get('requested_by')

    if not filename or not source_type:
        return _error_response('filename and source_type are required', 400, 'VALIDATION_ERROR')

    if source_type not in {'windows', 'firewall', 'auth', 'syslog', 'custom'}:
        return _error_response('source_type must be one of: windows, firewall, auth, syslog, custom', 400, 'VALIDATION_ERROR')

    try:
        job_id, item_id = _create_background_analysis_job_internal(
            org_id=org_id,
            filename=filename,
            source_type=source_type,
            requested_by=requested_by,
        )
    except ValueError as exc:
        log.exception('Validation error creating background analysis job')
        return _error_response('Invalid request parameters', 400, 'VALIDATION_ERROR')
    except Exception:
        log.exception('Failed to create background analysis job')
        return _error_response('Failed to create analysis job', 500, 'DATABASE_ERROR', retryable=True)

    return jsonify({
        'job_id': job_id,
        'item_id': item_id,
        'status': 'queued',
        'request_id': _get_request_id(),
    }), 202


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
    elif obj is not None and hasattr(obj, 'isoformat') and callable(obj.isoformat):
        # Only convert if it's actually a datetime-like object (has working isoformat method)
        try:
            return obj.isoformat()
        except (TypeError, AttributeError):
            return obj
    else:
        return obj


@main.route('/analysis-jobs/<job_id>', methods=['GET'])
def get_background_analysis_job(job_id):
    """Poll background job status and retrieve output when available."""
    log = _request_logger(route='get_background_analysis_job', job_id=job_id)
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    if not _is_uuid(job_id):
        return _error_response('job_id must be a UUID', 400, 'VALIDATION_ERROR')

    try:
        job_result, _job_select_expr = _select_with_fallback(
            'analysis_jobs',
            [
                'id, org_id, requested_by, status, source_type, total_files, processed_files, failed_files, progress_pct, created_at, started_at, completed_at, error_message, output_path',
                'id, org_id, status, source_type, total_files, processed_files, failed_files, progress_pct, created_at, started_at, completed_at, error_message, output_path',
                'id, org_id, status, source_type, total_files, processed_files, failed_files, progress_pct, created_at, started_at, completed_at, error_message',
                'id, org_id, status, source_type, total_files, processed_files, failed_files, progress_pct',
                'id, org_id, status',
            ],
            lambda query: query.eq('id', job_id).limit(1),
        )
    except Exception:
        log.exception('Failed to fetch analysis job')
        return _error_response('Failed to fetch analysis job', 500, 'DATABASE_ERROR', retryable=True)

    if not job_result.data:
        return _error_response('Analysis job not found', 404, 'NOT_FOUND')

    job = job_result.data[0]
    job.setdefault('requested_by', None)
    job.setdefault('source_type', None)
    job.setdefault('total_files', 0)
    job.setdefault('processed_files', 0)
    job.setdefault('failed_files', 0)
    job.setdefault('progress_pct', 0)
    job.setdefault('created_at', None)
    job.setdefault('started_at', None)
    job.setdefault('completed_at', None)
    job.setdefault('error_message', None)
    job.setdefault('output_path', None)
    _, org_scope_error = _enforce_org_scope(job.get('org_id'))
    if org_scope_error:
        return org_scope_error
    items = []
    try:
        items_result, _items_select_expr = _select_with_fallback(
            'analysis_job_items',
            [
                'id, job_id, file_name, file_id, status, entry_count, result_id, progress_pct, created_at, started_at, completed_at, error_message',
                'id, job_id, file_name, file_id, status, entry_count, result_id, progress_pct, created_at, started_at, completed_at',
                'id, job_id, file_name, file_id, status, entry_count, result_id, progress_pct',
                'id, job_id, file_name, status',
            ],
            lambda query: query.eq('job_id', job_id),
        )
        items = items_result.data or []
    except Exception:
        log.exception('Failed to fetch analysis job items')

    result_payload = None
    completed_item = next((item for item in items if item.get('status') == 'completed' and item.get('result_id')), None)
    if completed_item:
        result_id = completed_item['result_id']
        try:
            analysis_result = supabase_client.table('analysis_results').select('*').eq('id', result_id).limit(1).execute()
            result_payload = analysis_result.data[0] if analysis_result.data else None
        except Exception:
            log.exception('Failed to fetch analysis result for completed job item')

    return jsonify({
        'job': _serialize_timestamps(job),
        'items': _serialize_timestamps(items),
        'result': _serialize_timestamps(result_payload),
        'request_id': _get_request_id(),
    }), 200


@main.route('/upload-sessions/init', methods=['POST'])
def init_upload_session():
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get('org_id'))
    if org_scope_error:
        return org_scope_error
    filename = payload.get('filename')
    source_type = payload.get('source_type')
    total_parts = payload.get('total_parts')

    if not filename or not source_type:
        return _error_response('filename and source_type are required', 400, 'VALIDATION_ERROR')

    if source_type not in {'windows', 'firewall', 'auth', 'syslog', 'custom'}:
        return _error_response('source_type must be one of: windows, firewall, auth, syslog, custom', 400, 'VALIDATION_ERROR')

    if total_parts is not None:
        try:
            total_parts = int(total_parts)
        except (TypeError, ValueError):
            return _error_response('total_parts must be an integer when provided', 400, 'VALIDATION_ERROR')
        if total_parts <= 0:
            return _error_response('total_parts must be greater than 0', 400, 'VALIDATION_ERROR')

    session_id = str(uuid4())
    session_prefix = f"{org_id}/upload_sessions/{session_id}"

    session = {
        'session_id': session_id,
        'session_prefix': session_prefix,
        'org_id': org_id,
        'filename': filename,
        'source_type': source_type,
        'status': 'initiated',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'created_at_ts': time.time(),
        'total_parts': total_parts,
        'parts': {},
        'part_sizes': {},
        'received_parts': set(),
        'assembled_path': None,
        'job_id': None,
        'manifest_path': None,
    }

    with _upload_sessions_lock:
        _evict_expired_sessions()
        if len(_upload_sessions) >= MAX_UPLOAD_SESSIONS:
            return _error_response(
                'Too many active upload sessions. Please try again later.',
                429,
                'RATE_LIMIT',
                retryable=True,
            )
        _upload_sessions[session_id] = session

    try:
        _persist_upload_manifest(session)
    except Exception as exc:
        log = _request_logger(route='init_upload_session', org_id=org_id, filename=filename)
        log.exception('Failed to initialize upload session manifest')
        return _error_response(
            'Failed to initialize upload session manifest',
            500,
            'STORAGE_ERROR'
            ,
            retryable=True,
            details={'storage_error': 'Internal storage error', 'session_prefix': session_prefix},
        )

    return jsonify({
        'session_id': session_id,
        'status': session['status'],
        'manifest_path': session['manifest_path'],
        'request_id': _get_request_id(),
    }), 201


@main.route('/upload-sessions/upload-part', methods=['POST'])
def upload_session_part():
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error
    session_id = request.form.get('session_id')
    part_number_raw = request.form.get('part_number')
    log = _request_logger(route='upload_session_part', session_id=session_id)

    if not session_id or not part_number_raw:
        return _error_response('session_id and part_number are required', 400, 'VALIDATION_ERROR')

    try:
        part_number = int(part_number_raw)
    except ValueError:
        return _error_response('part_number must be an integer', 400, 'VALIDATION_ERROR')
    if part_number <= 0:
        return _error_response('part_number must be greater than 0', 400, 'VALIDATION_ERROR')

    if 'file' not in request.files:
        return _error_response('file part is required', 400, 'VALIDATION_ERROR')
    part_file = request.files['file']
    part_bytes = part_file.read()
    if not part_bytes:
        return _error_response('part payload is empty', 400, 'VALIDATION_ERROR')

    if len(part_bytes) > MAX_UPLOAD_PART_BYTES:
        return _error_response(
            f'Part exceeds max size of {MAX_UPLOAD_PART_BYTES} bytes',
            413,
            'PAYLOAD_TOO_LARGE',
            retryable=False,
        )

    with _upload_sessions_lock:
        _evict_expired_sessions()
        session = _upload_sessions.get(session_id)
        if not session:
            return _error_response('Upload session expired or not found', 410, 'GONE')
        _, org_scope_error = _enforce_org_scope(session.get('org_id'))
        if org_scope_error:
            return org_scope_error
        if session.get('status') == 'completed':
            return _error_response('Upload session already completed', 409, 'CONFLICT')

        part_path = f"{session['session_prefix']}/parts/{part_number:08d}.part"
        try:
            upload_binary(
                path=part_path,
                file_bytes=part_bytes,
                bucket_name=BUCKET_NAME,
                content_type='application/octet-stream',
            )
        except Exception as exc:
            log.exception('Failed to store upload part', part_path=part_path, part_number=part_number, session_id=session_id)
            return _error_response(
                'Failed to store upload part',
                500,
                'STORAGE_ERROR',
                retryable=True,
                details={'storage_error': 'Internal storage error', 'part_path': part_path, 'part_number': part_number},
            )

        session['parts'][part_number] = part_path
        session['part_sizes'][part_number] = len(part_bytes)
        session['received_parts'].add(part_number)
        session['status'] = 'uploading'

        try:
            _persist_upload_manifest(session)
        except Exception as exc:
            log.exception('Failed to update upload manifest', session_id=session_id)
            return _error_response(
                'Failed to update upload manifest',
                500,
                'STORAGE_ERROR',
                retryable=True,
                details={'storage_error': 'Internal storage error', 'session_id': session_id},
            )

        total_parts = session.get('total_parts')
        received_count = len(session['received_parts'])
        progress_pct = None
        if total_parts:
            progress_pct = round((received_count / total_parts) * 100, 2)

    return jsonify({
        'session_id': session_id,
        'part_number': part_number,
        'received_parts': received_count,
        'total_parts': total_parts,
        'progress_pct': progress_pct,
        'request_id': _get_request_id(),
    }), 201


@main.route('/upload-sessions/complete', methods=['POST'])
def complete_upload_session():
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}
    session_id = payload.get('session_id')
    requested_by = _auth_user_id() or payload.get('requested_by')
    log = _request_logger(route='complete_upload_session', session_id=session_id)

    if not session_id:
        return _error_response('session_id is required', 400, 'VALIDATION_ERROR')

    with _upload_sessions_lock:
        _evict_expired_sessions()
        session = _upload_sessions.get(session_id)
        if not session:
            return _error_response('Upload session expired or not found', 410, 'GONE')
        _, org_scope_error = _enforce_org_scope(session.get('org_id'))
        if org_scope_error:
            return org_scope_error
        if session.get('status') == 'completed':
            return jsonify({
                'session_id': session_id,
                'status': 'completed',
                'assembled_path': session.get('assembled_path'),
                'job_id': session.get('job_id'),
                'request_id': _get_request_id(),
            }), 200

        total_parts = session.get('total_parts')
        received_parts = session.get('received_parts', set())
        if total_parts and len(received_parts) != total_parts:
            return _error_response(
                f'Upload incomplete: expected {total_parts} parts, received {len(received_parts)}',
                409,
                'UPLOAD_INCOMPLETE',
            )

        ordered_parts = sorted(session['parts'].keys())
        if not ordered_parts:
            return _error_response('No parts uploaded for this session', 409, 'UPLOAD_INCOMPLETE')

        expected = list(range(1, len(ordered_parts) + 1))
        if ordered_parts != expected:
            return _error_response('Missing part numbers; parts must be contiguous starting at 1', 409, 'UPLOAD_INCOMPLETE')

        total_bytes = sum(session['part_sizes'].get(pn, 0) for pn in ordered_parts)
        if total_bytes > MAX_UPLOAD_SESSION_ASSEMBLY_BYTES:
            return _error_response(
                f'Combined upload size exceeds assembly limit of {MAX_UPLOAD_SESSION_ASSEMBLY_BYTES} bytes',
                413,
                'PAYLOAD_TOO_LARGE',
                retryable=False,
            )

        org_id = session['org_id']
        filename = session['filename']
        source_type = session['source_type']
        manifest_path = session.get('manifest_path')

    if not manifest_path:
        return _error_response('Upload manifest path missing for session', 500, 'STORAGE_ERROR', retryable=True)

    try:
        job_id, item_id = _create_background_analysis_job_internal(
            org_id=org_id,
            filename=filename,
            source_type=source_type,
            requested_by=requested_by,
            output_path=manifest_path,
        )
    except ValueError as exc:
        log.exception('Validation error creating analysis job after assembly')
        return _error_response('Invalid request parameters', 400, 'VALIDATION_ERROR')
    except Exception:
        return _error_response('File assembled, but failed to create analysis job', 500, 'DATABASE_ERROR', retryable=True)

    with _upload_sessions_lock:
        session['assembled_path'] = manifest_path
        session['job_id'] = job_id
        session['status'] = 'completed'
        try:
            _persist_upload_manifest(session)
        except Exception:
            # Upload succeeded and job is created; do not fail completion due to manifest update.
            pass

    return jsonify({
        'session_id': session_id,
        'status': 'completed',
        'assembled_path': manifest_path,
        'job_id': job_id,
        'item_id': item_id,
        'request_id': _get_request_id(),
    }), 202


@main.route('/rf/train', methods=['POST'])
def train_rf_model():
    log = _request_logger(route='train_rf_model')
    role_error = _require_roles('admin')
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}

    org_id, org_scope_error = _enforce_org_scope(payload.get('org_id'))
    if org_scope_error:
        return org_scope_error

    dataset_path = payload.get('dataset_path')
    if not dataset_path:
        return _error_response('dataset_path is required', 400, 'VALIDATION_ERROR')

    random_seed = int(payload.get('seed', 42))
    min_samples_per_class = int(payload.get('min_samples_per_class', 50))
    max_rows = payload.get('max_rows')
    max_rows = int(max_rows) if max_rows is not None else 150000
    requested_by = _auth_user_id() or payload.get('requested_by')
    dataset_name = payload.get('dataset_name', 'CICIDS2019')
    model_label = _dataset_to_model_label(dataset_name)
    model_name = _dataset_to_model_name(dataset_name)
    activation_threshold = float(payload.get('activation_threshold', os.getenv('RF_VALIDATION_PRECISION_THRESHOLD', '0.80')))

    training_run_id = None
    try:
        run_record = supabase_client.table('training_runs').insert({
            'org_id': org_id,
            'status': 'running',
            'dataset_name': dataset_name,
            'dataset_path': dataset_path,
            'split_policy': '70/15/15_stratified',
            'seed': random_seed,
            'requested_by': requested_by,
            'started_at': datetime.now(timezone.utc).isoformat(),
        }).execute()
        if run_record.data:
            training_run_id = run_record.data[0]['id']
    except Exception as exc:
        log.exception('Failed to create training run record')
        return _error_response(
            'Failed to create training run record. Ensure RF training migrations are applied.',
            500,
            'DATABASE_ERROR',
            retryable=True,
            details={'database_error': 'Database operation failed'},
        )

    try:
        bundle = prepare_cicids2019_training_bundle(
            dataset_path=dataset_path,
            seed=random_seed,
            min_samples_per_class=min_samples_per_class,
            max_rows=max_rows,
        )

        classifier = get_classifier()
        train_metrics = classifier.train(bundle['train_data'])
        if train_metrics.get('error'):
            raise ValueError(train_metrics['error'])

        validation_metrics = classifier.evaluate(bundle['validation_data'])
        if validation_metrics.get('error'):
            raise ValueError(validation_metrics['error'])

        test_metrics = classifier.evaluate(bundle['test_data'])
        if test_metrics.get('error'):
            raise ValueError(test_metrics['error'])

        model_status, validation_precision, activation_block_reason = _get_activation_status(
            validation_metrics,
            activation_threshold,
        )

        version = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S') + '-' + uuid4().hex[:8]
        local_model_path = Path(__file__).parent / '.models' / f'rf_{model_label}_{version}.pkl'
        local_model_path.parent.mkdir(parents=True, exist_ok=True)

        save_result = classifier.save_model(str(local_model_path))
        if save_result.get('error'):
            raise ValueError(save_result['error'])

        # Also keep a stable local artifact for automatic startup loading.
        stable_save_result = classifier.save_model()
        if stable_save_result.get('error'):
            raise ValueError(stable_save_result['error'])

        artifact_path = f"{org_id}/rf_models/rf_{model_label}_{version}.pkl"
        with open(local_model_path, 'rb') as artifact:
            upload_binary(artifact_path, artifact.read())

        metadata = {
            'seed': random_seed,
            'split_policy': bundle['split_policy'],
            'dataset_name': dataset_name,
            'dataset_path': bundle['dataset_path'],
            'label_column': bundle['label_column'],
            'class_distribution': bundle['class_distribution'],
            'train_samples': len(bundle['train_data']),
            'validation_samples': len(bundle['validation_data']),
            'test_samples': len(bundle['test_data']),
            'activation_threshold': activation_threshold,
            'validation_precision_weighted': validation_precision,
            'activation_status': model_status,
            'activation_block_reason': activation_block_reason,
        }

        model_version_record = supabase_client.table('model_versions').insert({
            'org_id': org_id,
            'name': model_name,
            'version': version,
            'status': model_status,
            'artifact_bucket': 'ml-models',
            'artifact_path': artifact_path,
            'label_classes': train_metrics.get('categories', []),
            'training_metadata': metadata,
            'metrics': {
                'train': train_metrics,
                'validation': validation_metrics,
                'test': test_metrics,
            },
            'created_by': requested_by,
            'activated_at': datetime.now(timezone.utc).isoformat() if model_status == 'active' else None,
        }).execute()

        model_version_id = model_version_record.data[0]['id'] if model_version_record.data else None

        _safe_update_training_run(training_run_id, {
            'status': 'completed',
            'model_version_id': model_version_id,
            'total_samples': (
                len(bundle['train_data']) + len(bundle['validation_data']) + len(bundle['test_data'])
            ),
            'class_distribution': bundle['class_distribution'],
            'train_metrics': train_metrics,
            'validation_metrics': {
                **validation_metrics,
                'activation_threshold': activation_threshold,
                'activation_status': model_status,
                'activation_block_reason': activation_block_reason,
            },
            'test_metrics': test_metrics,
            'completed_at': datetime.now(timezone.utc).isoformat(),
        })

        return jsonify({
            'status': 'completed',
            'training_run_id': training_run_id,
            'model_version_id': model_version_id,
            'model_name': model_name,
            'model_version': version,
            'artifact_path': artifact_path,
            'model_status': model_status,
            'activation_threshold': activation_threshold,
            'validation_precision_weighted': validation_precision,
            'activation_block_reason': activation_block_reason,
            'split_policy': bundle['split_policy'],
            'class_distribution': bundle['class_distribution'],
            'metrics': {
                'train': train_metrics,
                'validation': validation_metrics,
                'test': test_metrics,
            },
            'request_id': _get_request_id(),
        }), 201
    except Exception as exc:
        _safe_update_training_run(training_run_id, {
            'status': 'failed',
            'error_message': str(exc),
            'completed_at': datetime.now(timezone.utc).isoformat(),
        })
        log.exception('RF training failed')
        return _error_response('Model training failed', 500, 'TRAINING_ERROR', retryable=False)


@main.route('/rf/load-latest', methods=['POST'])
def load_latest_rf_model():
    role_error = _require_roles('admin')
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get('org_id'))
    if org_scope_error:
        return org_scope_error
    log = _request_logger(route='load_latest_rf_model', org_id=org_id)

    model_name = payload.get('model_name')
    if not model_name:
        dataset_name = payload.get('dataset_name')
        if dataset_name:
            model_name = _dataset_to_model_name(dataset_name)

    try:
        details = _load_latest_rf_model(org_id=org_id, model_name=model_name)
        return jsonify({
            'status': 'loaded',
            'details': details,
            'request_id': _get_request_id(),
        }), 200
    except Exception as exc:
        log.exception('Failed to load latest RF model')
        return _error_response('Failed to load model', 500, 'MODEL_LOAD_ERROR', retryable=True)

@main.route('/analysis/<file_id>', methods=['GET'])
def get_analysis(file_id):
    log = _request_logger(route='get_analysis', file_id=file_id)
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error
    include_mitre_links = request.args.get('include_mitre_links', 'true').strip().lower() != 'false'

    if not _is_uuid(file_id):
        return _error_response('file_id must be a UUID', 400, 'VALIDATION_ERROR')

    _, file_scope_error = _enforce_file_scope(file_id)
    if file_scope_error:
        return file_scope_error

    try:
        result = supabase_client.table('analysis_results').select('*').eq('file_id', file_id).order(
            'created_at',
            desc=True,
        ).limit(1).execute()
    except Exception:
        # Some environments still have the older analysis_results schema without created_at.
        log.exception('Failed to order analysis results by created_at; retrying without ordering')
        result = supabase_client.table('analysis_results').select('*').eq('file_id', file_id).limit(1).execute()

    if not result.data:
        return _error_response('No analysis found for this file', 404, 'NOT_FOUND')

    response_payload = result.data[0]
    if include_mitre_links:
        try:
            response_payload['mitre_links'] = _get_mitre_links_for_analysis(response_payload['id'])
        except Exception:
            log.exception('Failed to fetch normalized MITRE links')
            response_payload['mitre_links'] = []

    log.info('Retrieved analysis result')
    return jsonify(response_payload), 200


@main.route('/timeline/file/<file_id>', methods=['GET'])
def get_file_timeline_route(file_id):
    log = _request_logger(route='get_file_timeline', file_id=file_id)
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    if not _is_uuid(file_id):
        return _error_response('file_id must be a UUID', 400, 'VALIDATION_ERROR')

    _, file_scope_error = _enforce_file_scope(file_id)
    if file_scope_error:
        return file_scope_error

    start = request.args.get('start')
    end = request.args.get('end')
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')

    try:
        page = int(request.args.get('page', '1'))
        page_size = int(request.args.get('page_size', '100'))
    except (TypeError, ValueError):
        return _error_response('page and page_size must be integers', 400, 'VALIDATION_ERROR')

    if page <= 0 or page_size <= 0:
        return _error_response('page and page_size must be greater than 0', 400, 'VALIDATION_ERROR')

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
        log.exception('Failed to fetch file timeline')
        return _error_response('Failed to fetch file timeline', 500, 'DATABASE_ERROR', retryable=True)

    timeline['request_id'] = _get_request_id()
    return jsonify(timeline), 200


@main.route('/timeline/org/<org_id>', methods=['GET'])
def get_org_timeline_route(org_id):
    log = _request_logger(route='get_org_timeline', org_id=org_id)
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    if not _is_uuid(org_id):
        return _error_response('org_id must be a UUID', 400, 'VALIDATION_ERROR')

    _, org_scope_error = _enforce_org_scope(org_id)
    if org_scope_error:
        return org_scope_error

    start = request.args.get('start')
    end = request.args.get('end')
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')

    try:
        page = int(request.args.get('page', '1'))
        page_size = int(request.args.get('page_size', '100'))
    except (TypeError, ValueError):
        return _error_response('page and page_size must be integers', 400, 'VALIDATION_ERROR')

    if page <= 0 or page_size <= 0:
        return _error_response('page and page_size must be greater than 0', 400, 'VALIDATION_ERROR')

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
        log.exception('Failed to fetch org timeline')
        return _error_response('Failed to fetch org timeline', 500, 'DATABASE_ERROR', retryable=True)

    timeline['request_id'] = _get_request_id()
    return jsonify(timeline), 200


@main.route('/timeline/file/<file_id>/graph', methods=['GET'])
def get_file_timeline_graph_route(file_id):
    log = _request_logger(route='get_file_timeline_graph', file_id=file_id)
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    if not _is_uuid(file_id):
        return _error_response('file_id must be a UUID', 400, 'VALIDATION_ERROR')

    _, file_scope_error = _enforce_file_scope(file_id)
    if file_scope_error:
        return file_scope_error

    start = request.args.get('start')
    end = request.args.get('end')
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    max_nodes_raw = request.args.get('max_nodes', '120')

    try:
        max_nodes = int(max_nodes_raw)
    except (TypeError, ValueError):
        return _error_response('max_nodes must be an integer', 400, 'VALIDATION_ERROR')

    if max_nodes <= 0:
        return _error_response('max_nodes must be greater than 0', 400, 'VALIDATION_ERROR')

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
        log.exception('Failed to fetch file timeline graph')
        return _error_response('Failed to fetch file timeline graph', 500, 'DATABASE_ERROR', retryable=True)

    graph_payload['request_id'] = _get_request_id()
    return jsonify(graph_payload), 200


@main.route('/timeline/org/<org_id>/graph', methods=['GET'])
def get_org_timeline_graph_route(org_id):
    log = _request_logger(route='get_org_timeline_graph', org_id=org_id)
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    if not _is_uuid(org_id):
        return _error_response('org_id must be a UUID', 400, 'VALIDATION_ERROR')

    _, org_scope_error = _enforce_org_scope(org_id)
    if org_scope_error:
        return org_scope_error

    start = request.args.get('start')
    end = request.args.get('end')
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    max_nodes_raw = request.args.get('max_nodes', '160')

    try:
        max_nodes = int(max_nodes_raw)
    except (TypeError, ValueError):
        return _error_response('max_nodes must be an integer', 400, 'VALIDATION_ERROR')

    if max_nodes <= 0:
        return _error_response('max_nodes must be greater than 0', 400, 'VALIDATION_ERROR')

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
        log.exception('Failed to fetch org timeline graph')
        return _error_response('Failed to fetch org timeline graph', 500, 'DATABASE_ERROR', retryable=True)

    graph_payload['request_id'] = _get_request_id()
    return jsonify(graph_payload), 200


@main.route('/incidents', methods=['GET'])
def list_incidents():
    log = _request_logger(route='list_incidents')
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    org_id, org_scope_error = _enforce_org_scope(request.args.get('org_id'))
    if org_scope_error:
        return org_scope_error

    status_filter = request.args.get('status')
    limit_raw = request.args.get('limit', '50')
    try:
        limit = max(1, min(200, int(limit_raw)))
    except (TypeError, ValueError):
        return _error_response('limit must be an integer', 400, 'VALIDATION_ERROR')

    try:
        result, _select_expr = _select_with_fallback(
            'incidents',
            [
                'id, org_id, title, status, severity',
                'id, org_id, title, status',
                'id, org_id, title',
                'id, title',
            ],
            lambda query: query.eq('org_id', org_id).eq('status', status_filter) if status_filter else query.eq('org_id', org_id),
        )
        if result is None:
            return jsonify({'items': [], 'request_id': _get_request_id()}), 200
        return jsonify({'items': result.data or [], 'request_id': _get_request_id()}), 200
    except Exception:
        log.exception('Failed to load incidents')
        return _error_response('Failed to load incidents', 500, 'DATABASE_ERROR', retryable=True)


@main.route('/incidents', methods=['POST'])
def create_incident():
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error

    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get('org_id'))
    if org_scope_error:
        return org_scope_error

    title = str(payload.get('title') or '').strip()
    status = str(payload.get('status') or 'open').strip().lower()
    severity = str(payload.get('severity') or 'medium').strip().lower()

    if not title:
        return _error_response('title is required', 400, 'VALIDATION_ERROR')

    if status not in {'open', 'in_progress', 'resolved', 'closed'}:
        return _error_response('status must be one of: open, in_progress, resolved, closed', 400, 'VALIDATION_ERROR')

    if severity not in {'low', 'medium', 'high', 'critical'}:
        return _error_response('severity must be one of: low, medium, high, critical', 400, 'VALIDATION_ERROR')

    result = supabase_client.table('incidents').insert({
        'org_id': org_id,
        'title': title,
        'status': status,
        'severity': severity,
    }).execute()

    return jsonify({'incident': (result.data or [None])[0], 'request_id': _get_request_id()}), 201


@main.route('/incidents/<incident_id>', methods=['PATCH'])
def update_incident(incident_id):
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error

    org_id = _incident_org_id(incident_id)
    if not org_id:
        return _error_response('Incident not found', 404, 'NOT_FOUND')

    _, org_scope_error = _enforce_org_scope(org_id)
    if org_scope_error:
        return org_scope_error

    payload = request.get_json(silent=True) or {}
    updates = {}

    if 'title' in payload:
        title = str(payload.get('title') or '').strip()
        if not title:
            return _error_response('title cannot be empty', 400, 'VALIDATION_ERROR')
        updates['title'] = title

    if 'status' in payload:
        status = str(payload.get('status') or '').strip().lower()
        if status not in {'open', 'in_progress', 'resolved', 'closed'}:
            return _error_response('status must be one of: open, in_progress, resolved, closed', 400, 'VALIDATION_ERROR')
        updates['status'] = status

    if 'severity' in payload:
        severity = str(payload.get('severity') or '').strip().lower()
        if severity not in {'low', 'medium', 'high', 'critical'}:
            return _error_response('severity must be one of: low, medium, high, critical', 400, 'VALIDATION_ERROR')
        updates['severity'] = severity

    if not updates:
        return _error_response('No valid fields supplied to update', 400, 'VALIDATION_ERROR')

    result = supabase_client.table('incidents').update(updates).eq('id', incident_id).execute()
    return jsonify({'incident': (result.data or [None])[0], 'request_id': _get_request_id()}), 200


@main.route('/tasks', methods=['GET'])
def list_tasks():
    log = _request_logger(route='list_tasks')
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    org_id, org_scope_error = _enforce_org_scope(request.args.get('org_id'))
    if org_scope_error:
        return org_scope_error

    incident_id = request.args.get('incident_id')
    status_filter = request.args.get('status')
    limit_raw = request.args.get('limit', '50')
    try:
        limit = max(1, min(200, int(limit_raw)))
    except (TypeError, ValueError):
        return _error_response('limit must be an integer', 400, 'VALIDATION_ERROR')

    try:
        result, _select_expr = _select_with_fallback(
            'tasks',
            [
                'id, org_id, incident_id, assignee_id, title, status',
                'id, org_id, incident_id, title, status',
                'id, org_id, incident_id, title',
                'id, org_id, title',
            ],
            lambda query: (
                query.eq('org_id', org_id)
                .eq('incident_id', incident_id) if incident_id else query.eq('org_id', org_id)
            ).eq('status', status_filter) if status_filter else (
                query.eq('org_id', org_id).eq('incident_id', incident_id) if incident_id else query.eq('org_id', org_id)
            ),
        )
        if result is None:
            return jsonify({'items': [], 'request_id': _get_request_id()}), 200
        return jsonify({'items': result.data or [], 'request_id': _get_request_id()}), 200
    except Exception:
        log.exception('Failed to load tasks')
        return _error_response('Failed to load tasks', 500, 'DATABASE_ERROR', retryable=True)


@main.route('/tasks', methods=['POST'])
def create_task():
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error

    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get('org_id'))
    if org_scope_error:
        return org_scope_error

    title = str(payload.get('title') or '').strip()
    incident_id = payload.get('incident_id')
    assignee_id = payload.get('assignee_id')
    status = str(payload.get('status') or 'pending').strip().lower()

    if not title:
        return _error_response('title is required', 400, 'VALIDATION_ERROR')
    if not _is_uuid(incident_id):
        return _error_response('incident_id must be a UUID', 400, 'VALIDATION_ERROR')
    if assignee_id and not _is_uuid(assignee_id):
        return _error_response('assignee_id must be a UUID when provided', 400, 'VALIDATION_ERROR')
    if status not in {'pending', 'in_progress', 'done'}:
        return _error_response('status must be one of: pending, in_progress, done', 400, 'VALIDATION_ERROR')

    incident_org_id = _incident_org_id(incident_id)
    if not incident_org_id:
        return _error_response('Incident not found', 404, 'NOT_FOUND')
    if incident_org_id != org_id:
        return _error_response('Cross-organization access denied', 403, 'FORBIDDEN')

    result = supabase_client.table('tasks').insert({
        'org_id': org_id,
        'incident_id': incident_id,
        'assignee_id': assignee_id,
        'title': title,
        'status': status,
    }).execute()

    return jsonify({'task': (result.data or [None])[0], 'request_id': _get_request_id()}), 201


@main.route('/tasks/<task_id>', methods=['PATCH'])
def update_task(task_id):
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error

    org_id = _task_org_id(task_id)
    if not org_id:
        return _error_response('Task not found', 404, 'NOT_FOUND')

    _, org_scope_error = _enforce_org_scope(org_id)
    if org_scope_error:
        return org_scope_error

    payload = request.get_json(silent=True) or {}
    updates = {}

    if 'title' in payload:
        title = str(payload.get('title') or '').strip()
        if not title:
            return _error_response('title cannot be empty', 400, 'VALIDATION_ERROR')
        updates['title'] = title

    if 'status' in payload:
        status = str(payload.get('status') or '').strip().lower()
        if status not in {'pending', 'in_progress', 'done'}:
            return _error_response('status must be one of: pending, in_progress, done', 400, 'VALIDATION_ERROR')
        updates['status'] = status

    if 'assignee_id' in payload:
        assignee_id = payload.get('assignee_id')
        if assignee_id and not _is_uuid(assignee_id):
            return _error_response('assignee_id must be a UUID when provided', 400, 'VALIDATION_ERROR')
        updates['assignee_id'] = assignee_id

    if not updates:
        return _error_response('No valid fields supplied to update', 400, 'VALIDATION_ERROR')

    result = supabase_client.table('tasks').update(updates).eq('id', task_id).execute()
    return jsonify({'task': (result.data or [None])[0], 'request_id': _get_request_id()}), 200


@main.route('/feedback', methods=['GET'])
def list_feedback():
    log = _request_logger(route='list_feedback')
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    org_id, org_scope_error = _enforce_org_scope(request.args.get('org_id'))
    if org_scope_error:
        return org_scope_error

    try:
        result, _select_expr = _select_with_fallback(
            'feedback',
            [
                'id, org_id, summary_id, user_id, rating, suggestion_text, created_at',
                'id, org_id, summary_id, user_id, rating, created_at',
                'id, org_id, summary_id, user_id, rating',
                'id, org_id, rating',
            ],
            lambda query: query.eq('org_id', org_id).limit(100),
        )
        if result is None:
            return jsonify({'items': [], 'request_id': _get_request_id()}), 200
        return jsonify({'items': result.data or [], 'request_id': _get_request_id()}), 200
    except Exception:
        log.exception('Failed to load feedback')
        return _error_response('Failed to load feedback', 500, 'DATABASE_ERROR', retryable=True)


@main.route('/feedback', methods=['POST'])
def create_feedback():
    role_error = _require_roles('admin', 'analyst', 'viewer')
    if role_error:
        return role_error

    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get('org_id'))
    if org_scope_error:
        return org_scope_error

    summary_id = payload.get('summary_id')
    rating = payload.get('rating')
    suggestion_text = str(payload.get('suggestion_text') or '').strip()

    try:
        rating = int(rating)
    except (TypeError, ValueError):
        return _error_response('rating must be an integer between 1 and 5', 400, 'VALIDATION_ERROR')

    if rating < 1 or rating > 5:
        return _error_response('rating must be between 1 and 5', 400, 'VALIDATION_ERROR')

    if summary_id and not _is_uuid(summary_id):
        return _error_response('summary_id must be a UUID when provided', 400, 'VALIDATION_ERROR')

    payload_to_store = {
        'org_id': org_id,
        'summary_id': summary_id,
        'user_id': _auth_user_id() or None,
        'rating': rating,
        'suggestion_text': suggestion_text or None,
    }

    try:
        result = supabase_client.table('feedback').insert(payload_to_store).execute()
    except Exception as exc:
        if 'suggestion_text' not in str(exc):
            raise
        payload_to_store.pop('suggestion_text', None)
        result = supabase_client.table('feedback').insert(payload_to_store).execute()

    return jsonify({'feedback': (result.data or [None])[0], 'request_id': _get_request_id()}), 201

@main.route('/analyze/<file_id>', methods=['POST'])
def analyze_stored_file(file_id):
    """Re-analyze a previously uploaded file using raw_logs already in the DB."""
    log = _request_logger(route='analyze_stored_file', file_id=file_id)
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error

    file_result = supabase_client.table('log_files').select('id, org_id, source_type').eq('id', file_id).execute()
    if not file_result.data:
        return _error_response('File not found', 404, 'NOT_FOUND')

    file_record = file_result.data[0]
    _, org_scope_error = _enforce_org_scope(file_record.get('org_id'))
    if org_scope_error:
        return org_scope_error
    org_id = file_record['org_id']
    source_type = file_record['source_type']
    log = log.bind(org_id=org_id, source_type=source_type)

    logs_result = supabase_client.table('raw_logs').select('payload').eq('file_id', file_id).execute()
    entries = [r['payload'] for r in (logs_result.data or []) if r.get('payload')]

    if not entries:
        return _error_response('No log entries found for this file', 404, 'NOT_FOUND')

    try:
        detections = run_correlation(entries, org_id, file_id, request_id=_get_request_id())
    except Exception:
        detections = []
        log.exception('Correlation engine failed')

    rf_results = []
    rf_context = _build_rf_context([])
    try:
        classifier = get_classifier()
        rf_results = classifier.classify_batch(entries)
        rf_context = _build_rf_context(rf_results)
    except Exception:
        log.exception('RF classification failed')

    try:
        analysis = analyze_threats(
            entries,
            source_type,
            detections=detections,
            rf_context=rf_context,
        )
    except Exception:
        log.exception('Threat analysis failed')
        return _error_response('Threat analysis failed', 500, 'ANALYSIS_ERROR', retryable=True)

    try:
        _store_analysis_result(
            file_id=file_id,
            org_id=org_id,
            analysis=analysis,
            detections=detections,
        )
    except Exception:
        log.exception('Failed to store analysis')
        return _error_response('Failed to store analysis', 500, 'DATABASE_ERROR', retryable=True)

    supabase_client.table('log_files').update({'status': 'completed'}).eq('id', file_id).execute()

    try:
        actionable_insights = _build_actionable_insights_payload(
            threats=analysis.get('detailed_findings', []),
            detections=detections,
            logs=entries,
            source_type=source_type,
            rf_results=rf_results,
        )
    except Exception:
        log.exception('Failed to generate actionable insights')
        actionable_insights = {
            'status': 'error',
            'message': 'Failed to generate actionable insights',
        }

    return jsonify({
        'file_id': file_id,
        'entry_count': len(entries),
        'detections': detections,
        'detection_count': len(detections),
        'analysis': {
            'threat_level': analysis['threat_level'],
            'threats_found': analysis['threats_found'],
            'summary': analysis['summary'],
            'mitre_techniques': analysis.get('mitre_techniques'),
            'attack_vector': analysis.get('attack_vector'),
            'confidence_score': analysis.get('confidence_score'),
        },
        'actionable_insights': actionable_insights,
        'request_id': _get_request_id(),
    }), 201

@main.route('/analyze-from-storage', methods=['POST'])
def analyze_from_storage():
    """Download a file from Supabase Storage by path and run full analysis."""
    log = _request_logger(route='analyze_from_storage')
    role_error = _require_roles('admin', 'analyst')
    if role_error:
        return role_error

    data = request.get_json()
    if not data:
        return _error_response('JSON body required', 400, 'VALIDATION_ERROR')

    org_id, org_scope_error = _enforce_org_scope(data.get('org_id'))
    if org_scope_error:
        return org_scope_error
    filename = data.get('filename')
    source_type = data.get('source_type')
    log = log.bind(org_id=org_id, filename=filename, source_type=source_type)

    if not filename or not source_type:
        return _error_response('filename and source_type are required', 400, 'VALIDATION_ERROR')

    if source_type not in {'windows', 'firewall', 'auth', 'syslog', 'custom'}:
        return _error_response('source_type must be one of: windows, firewall, auth, syslog, custom', 400, 'VALIDATION_ERROR')

    storage_path = f"{org_id}/{filename}"

    try:
        file_bytes = download_file(storage_path)
    except Exception:
        log.exception('Failed to download file from storage')
        return _error_response('Failed to download file from storage', 404, 'STORAGE_ERROR')

    try:
        entries = parse_file(file_bytes, filename)
    except Exception:
        log.exception('Failed to parse file')
        return _error_response('Failed to parse file', 400, 'PARSING_ERROR')

    try:
        file_record = supabase_client.table('log_files').insert({
            'filename': filename,
            'org_id': org_id,
            'source_type': source_type,
            'storage_path': storage_path,
            'status': 'analyzing',
            'entry_count': len(entries)
        }).execute()
        file_id = file_record.data[0]['id']
        log = log.bind(file_id=file_id)
    except Exception:
        log.exception('Failed to create file record')
        return _error_response('Failed to create file record', 500, 'DATABASE_ERROR', retryable=True)

    try:
        _insert_raw_logs_in_batches(entries, org_id, file_id)
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Failed to store log entries')
        return _error_response('Failed to store log entries', 500, 'DATABASE_ERROR', retryable=True)

    try:
        detections = run_correlation(entries, org_id, file_id, request_id=_get_request_id())
    except Exception:
        detections = []
        log.exception('Correlation engine failed')

    rf_results = []
    rf_context = _build_rf_context([])
    try:
        classifier = get_classifier()
        rf_results = classifier.classify_batch(entries)
        rf_context = _build_rf_context(rf_results)
    except Exception:
        log.exception('RF classification failed')

    try:
        analysis = analyze_threats(
            entries,
            source_type,
            detections=detections,
            rf_context=rf_context,
        )
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Threat analysis failed')
        return _error_response('Threat analysis failed', 500, 'ANALYSIS_ERROR', retryable=True)

    try:
        _store_analysis_result(
            file_id=file_id,
            org_id=org_id,
            analysis=analysis,
            detections=detections,
        )
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Failed to store analysis')
        return _error_response('Failed to store analysis', 500, 'DATABASE_ERROR', retryable=True)

    supabase_client.table('log_files').update({'status': 'completed'}).eq('id', file_id).execute()

    try:
        actionable_insights = _build_actionable_insights_payload(
            threats=analysis.get('detailed_findings', []),
            detections=detections,
            logs=entries,
            source_type=source_type,
            rf_results=rf_results,
        )
    except Exception:
        log.exception('Failed to generate actionable insights')
        actionable_insights = {
            'status': 'error',
            'message': 'Failed to generate actionable insights',
        }

    return jsonify({
        'file_id': file_id,
        'filename': filename,
        'storage_path': storage_path,
        'entry_count': len(entries),
        'detections': detections,
        'detection_count': len(detections),
        'analysis': {
            'threat_level': analysis['threat_level'],
            'threats_found': analysis['threats_found'],
            'summary': analysis['summary'],
            'mitre_techniques': analysis.get('mitre_techniques'),
            'attack_vector': analysis.get('attack_vector'),
            'confidence_score': analysis.get('confidence_score'),
        },
        'actionable_insights': actionable_insights,
        'request_id': _get_request_id(),
    }), 201