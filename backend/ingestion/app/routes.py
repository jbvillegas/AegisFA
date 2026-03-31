from flask import Blueprint, request, jsonify, g
from . import supabase_client
from .normalization import normalize_log
from .file_parser import parse_file
from .rag_service import analyze_threats
from .correlation_engine import run_correlation
from .timeline_service import get_file_timeline, get_org_timeline
from .storage import upload_file, download_file, upload_binary
from .log_classifier import get_classifier
from .insights_generator import get_insights_generator
from .kaggle import prepare_cicids2019_training_bundle
from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4
from pathlib import Path
import structlog 

main = Blueprint('main', __name__)
logger = structlog.get_logger(__name__)

RAW_LOG_INSERT_BATCH_SIZE = 200
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}

@main.before_request
def _set_request_id():
    request_id = request.headers.get('X-Request-ID')
    g.request_id = request_id or str(uuid4())
    g.request_started_at = perf_counter()


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
        supabase_client.table('raw_logs').insert(batch).execute()

def _build_actionable_insights_payload(
    threats=None,
    detections=None,
    logs=None,
    source_type='custom',
):
    """Build unified actionable-insights payload from threats/detections/logs."""
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

    classifier = get_classifier()
    classification_context = {
        'total': 0,
        'by_category': {},
        'average_confidence': 0.0,
    }

    if logs:
        rf_results = classifier.classify_batch(logs)
        by_category = {}
        confidences = []
        for result in rf_results:
            category = result.get('category', 'unknown')
            by_category[category] = by_category.get(category, 0) + 1
            confidences.append(result.get('confidence', 0.0))

        classification_context = {
            'total': len(rf_results),
            'by_category': by_category,
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


def _safe_update_training_run(run_id: str | None, updates: dict):
    if not run_id:
        return
    try:
        supabase_client.table('training_runs').update(updates).eq('id', run_id).execute()
    except Exception:
        _request_logger(route='rf_train', run_id=run_id).exception('Failed to update training run status')

@main.route('/ingest', methods=['POST'])
def ingest():
    log = _request_logger(route='ingest')
    data = request.get_json()
    if not data:
        return _error_response('JSON body required', 400, 'VALIDATION_ERROR')

    source = data.get('source')
    raw_data = data.get('raw_data')
    timestamp = data.get('timestamp', datetime.now(timezone.utc).isoformat())

    if not source or raw_data is None:
        return _error_response('source and raw_data are required', 400, 'VALIDATION_ERROR')

    try:
        raw_result = supabase_client.table('raw_logs').insert({
            'org_id': data.get('org_id'),
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
            'org_id': data.get('org_id'),
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

    if 'file' not in request.files:
        return _error_response('No file provided', 400, 'VALIDATION_ERROR')

    file = request.files['file']
    source_type = request.form.get('source_type')
    org_id = request.form.get('org_id')
    log = log.bind(org_id=org_id, filename=file.filename)

    if not source_type or source_type not in {'windows', 'firewall', 'auth', 'syslog', 'custom'}:
        return _error_response('source_type must be one of: windows, firewall, auth, syslog, custom', 400, 'VALIDATION_ERROR')

    if not org_id:
        return _error_response('org_id is required', 400, 'VALIDATION_ERROR')

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

    try:
        analysis = analyze_threats(entries, source_type, detections=detections)
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Threat analysis failed')
        return _error_response('Threat analysis failed', 500, 'ANALYSIS_ERROR', retryable=True)

    try:
        supabase_client.table('analysis_results').insert({
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
            'correlation_detections': detections,
        }).execute()
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


@main.route('/rf/train', methods=['POST'])
def train_rf_model():
    log = _request_logger(route='train_rf_model')
    payload = request.get_json(silent=True) or {}

    org_id = payload.get('org_id')
    if not org_id:
        return _error_response('org_id is required', 400, 'VALIDATION_ERROR')

    dataset_path = payload.get('dataset_path')
    if not dataset_path:
        return _error_response('dataset_path is required', 400, 'VALIDATION_ERROR')

    random_seed = int(payload.get('seed', 42))
    min_samples_per_class = int(payload.get('min_samples_per_class', 5))
    max_rows = payload.get('max_rows')
    max_rows = int(max_rows) if max_rows is not None else 120000
    requested_by = payload.get('requested_by')
    dataset_name = payload.get('dataset_name', 'CICIDS2019')

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
            details={'database_error': str(exc)},
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

        version = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S') + '-' + uuid4().hex[:8]
        local_model_path = Path(__file__).parent / '.models' / f'rf_cicids2019_{version}.pkl'
        local_model_path.parent.mkdir(parents=True, exist_ok=True)

        save_result = classifier.save_model(str(local_model_path))
        if save_result.get('error'):
            raise ValueError(save_result['error'])

        artifact_path = f"{org_id}/rf_models/rf_cicids2019_{version}.pkl"
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
        }

        model_version_record = supabase_client.table('model_versions').insert({
            'org_id': org_id,
            'name': 'rf-cicids2019',
            'version': version,
            'status': 'active',
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
            'activated_at': datetime.now(timezone.utc).isoformat(),
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
            'validation_metrics': validation_metrics,
            'test_metrics': test_metrics,
            'completed_at': datetime.now(timezone.utc).isoformat(),
        })

        return jsonify({
            'status': 'completed',
            'training_run_id': training_run_id,
            'model_version_id': model_version_id,
            'model_version': version,
            'artifact_path': artifact_path,
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
        return _error_response(str(exc), 500, 'TRAINING_ERROR', retryable=False)

@main.route('/analysis/<file_id>', methods=['GET'])
def get_analysis(file_id):
    log = _request_logger(route='get_analysis', file_id=file_id)
    result = supabase_client.table('analysis_results').select('*').eq('file_id', file_id).execute()

    if not result.data:
        return _error_response('No analysis found for this file', 404, 'NOT_FOUND')

    log.info('Retrieved analysis result')
    return jsonify(result.data[0]), 200

@main.route('/analyze/<file_id>', methods=['POST'])
def analyze_stored_file(file_id):
    """Re-analyze a previously uploaded file using raw_logs already in the DB."""
    log = _request_logger(route='analyze_stored_file', file_id=file_id)

    file_result = supabase_client.table('log_files').select('id, org_id, source_type').eq('id', file_id).execute()
    if not file_result.data:
        return _error_response('File not found', 404, 'NOT_FOUND')

    file_record = file_result.data[0]
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

    try:
        analysis = analyze_threats(entries, source_type, detections=detections)
    except Exception:
        log.exception('Threat analysis failed')
        return _error_response('Threat analysis failed', 500, 'ANALYSIS_ERROR', retryable=True)

    try:
        supabase_client.table('analysis_results').insert({
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
            'correlation_detections': detections,
        }).execute()
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

    data = request.get_json()
    if not data:
        return _error_response('JSON body required', 400, 'VALIDATION_ERROR')

    org_id = data.get('org_id')
    filename = data.get('filename')
    source_type = data.get('source_type')
    log = log.bind(org_id=org_id, filename=filename, source_type=source_type)

    if not org_id or not filename or not source_type:
        return _error_response('org_id, filename, and source_type are required', 400, 'VALIDATION_ERROR')

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

    try:
        analysis = analyze_threats(entries, source_type, detections=detections)
    except Exception:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        log.exception('Threat analysis failed')
        return _error_response('Threat analysis failed', 500, 'ANALYSIS_ERROR', retryable=True)

    try:
        supabase_client.table('analysis_results').insert({
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
            'correlation_detections': detections,
        }).execute()
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