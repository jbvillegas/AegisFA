from flask import Blueprint, request, jsonify
from . import supabase_client
from .normalization import normalize_log
from .file_parser import parse_file
from .threat_analysis import analyze_threats
from .storage import upload_file
from datetime import datetime, timezone

main = Blueprint('main', __name__)

@main.route('/ingest', methods=['POST'])
def ingest():
    data = request.get_json()
    source = data.get('source')
    raw_data = data.get('raw_data')
    timestamp = data.get('timestamp', datetime.now(timezone.utc).isoformat())

    # 1. Insert raw log
    raw_result = supabase_client.table('raw_logs').insert({
        'org_id': data.get('org_id'),
        'source_id': data.get('source_id'),
        'payload': raw_data,
        'received_at': timestamp
    }).execute()

    raw_log_id = raw_result.data[0]['id']

    # 2. Normalize and insert normalized event
    normalized = normalize_log(source, raw_data)
    norm_result = supabase_client.table('normalized_events').insert({
        'org_id': data.get('org_id'),
        'raw_log_id': raw_log_id,
        'source_id': data.get('source_id'),
        'event_type': normalized.get('action'),
        'severity': normalized.get('status')
    }).execute()

    return jsonify({
        'raw_log_id': raw_log_id,
        'normalized_event_id': norm_result.data[0]['id'],
        'normalized_data': normalized
    }), 201

@main.route('/upload', methods=['POST'])
def upload_log_file():
    # Validate file is present
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    source_type = request.form.get('source_type')
    org_id = request.form.get('org_id')

    if not source_type or source_type not in {'windows', 'firewall', 'auth', 'syslog', 'custom'}:
        return jsonify({'error': 'source_type must be one of: windows, firewall, auth, syslog, custom'}), 400

    if not org_id:
        return jsonify({'error': 'org_id is required'}), 400

    file_bytes = file.read()

    # 1. Parse the file into individual log entries
    try:
        entries = parse_file(file_bytes, file.filename)
    except Exception as e:
        return jsonify({'error': f'Failed to parse file: {str(e)}'}), 400

    # 2. Upload raw file to Supabase Storage
    try:
        storage_path = upload_file(file_bytes, file.filename, org_id)
    except Exception as e:
        return jsonify({'error': f'Failed to upload file to storage: {str(e)}'}), 500

    # 3. Create log_files record with status "analyzing"
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
    except Exception as e:
        return jsonify({'error': f'Failed to save file record: {str(e)}'}), 500

    # 4. Insert each parsed entry into raw_logs
    try:
        for entry in entries:
            supabase_client.table('raw_logs').insert({
                'org_id': org_id,
                'payload': entry,
                'file_id': file_id
            }).execute()
    except Exception as e:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        return jsonify({'error': f'Failed to store log entries: {str(e)}'}), 500

    # 5. Run ML threat analysis
    try:
        analysis = analyze_threats(entries, source_type)
    except Exception as e:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        return jsonify({'error': f'Threat analysis failed: {str(e)}'}), 500

    # 6. Store analysis results
    try:
        supabase_client.table('analysis_results').insert({
            'file_id': file_id,
            'threat_level': analysis['threat_level'],
            'threats_found': analysis['threats_found'],
            'summary': analysis['summary'],
            'detailed_findings': analysis['detailed_findings']
        }).execute()
    except Exception as e:
        supabase_client.table('log_files').update({'status': 'failed'}).eq('id', file_id).execute()
        return jsonify({'error': f'Failed to store analysis: {str(e)}'}), 500

    # 7. Mark file as completed
    supabase_client.table('log_files').update({'status': 'completed'}).eq('id', file_id).execute()

    return jsonify({
        'file_id': file_id,
        'filename': file.filename,
        'entry_count': len(entries),
        'analysis': {
            'threat_level': analysis['threat_level'],
            'threats_found': analysis['threats_found'],
            'summary': analysis['summary']
        }
    }), 201


@main.route('/analysis/<file_id>', methods=['GET'])
def get_analysis(file_id):
    result = supabase_client.table('analysis_results').select('*').eq('file_id', file_id).execute()

    if not result.data:
        return jsonify({'error': 'No analysis found for this file'}), 404

    return jsonify(result.data[0]), 200


@main.route('/files', methods=['GET'])
def list_files():
    org_id = request.args.get('org_id')

    if org_id:
        result = supabase_client.table('log_files').select('*').eq('org_id', org_id).execute()
    else:
        result = supabase_client.table('log_files').select('*').execute()

    return jsonify(result.data), 200


@main.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200
