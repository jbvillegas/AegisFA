from flask import Blueprint, request, jsonify
from . import supabase_client
from .normalization import normalize_log
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

@main.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200
