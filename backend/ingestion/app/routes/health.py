
from flask import jsonify
from . import main
from .utils import *
from .utils import _get_request_id  # noqa: F401,F403

@main.route("/", methods=["GET"])
def root():
    return jsonify(
        {
            "service": "AegisFA ingestion API",
            "status": "ok",
            "message": "Use the API endpoints under /ingest, /upload, /analysis, or /timeline.",
            "request_id": _get_request_id(),
        }
    )


@main.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "service": "AegisFA ingestion API",
            "status": "ok",
            "request_id": _get_request_id(),
        }
    )


