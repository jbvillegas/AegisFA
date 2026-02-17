from flask import Blueprint, request, jsonify
from . import database
from .models import LogEntry
from .normalization import normalize_log as rule_based
from .openai_service import normalize_log_with_ai
from datetime import datetime
import os

main = Blueprint('main', __name__)

USE_AI = os.getenv('USE_AI_NORMALIZATION', 'False').lower() == 'true'

@main.route('/ingest', methods=['POST'])
def ingest_log():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request must be JSON"}), 400

    source = data.get('source')
    raw_data = data.get('raw_data')
    timestamp_str = data.get('timestamp')

    if source not in {'windows', 'firewall', 'auth'}:
        return jsonify({"error": "source must be one of windows, firewall, auth"}), 400

    try:
        if USE_AI:
            normalized = normalize_log_with_ai(source, raw_data)
        else:
            normalized = rule_based(source, raw_data)
    except Exception as e:
        return jsonify({"error": f"Normalization failed: {str(e)}"}), 500

    # Parse timestamp
    if timestamp_str:
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({"error": "Invalid timestamp format. Use ISO 8601."}), 400
    else:
        timestamp = datetime.utcnow()

    log_entry = LogEntry(
        source=source,
        raw_data=raw_data,
        normalized_data=normalized,
        timestamp=timestamp
    )
    database.session.add(log_entry)
    database.session.commit()

    return jsonify({
        "status": "success",
        "id": log_entry.id,
        "normalized": normalized
    }), 201

@main.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})