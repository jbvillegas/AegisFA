"""Route implementations for the ingestion service."""

import os
from datetime import datetime, timezone
from pathlib import Path
from flask import jsonify, request
from uuid import uuid4
from . import main, supabase_client
from .utils import *
from .utils import _require_roles
from .utils import _request_logger
from .utils import _enforce_org_scope
from .utils import _error_response
from .utils import _auth_user_id
from .utils import _get_activation_status
from .utils import _safe_update_training_run
from .utils import _get_request_id  # noqa: F401,F403

def _dataset_to_model_label(dataset_name: str | None) -> str:
    raw_value = str(dataset_name or "").strip().lower()
    if not raw_value:
        return "cicids2019"

    normalized = re.sub(r"[^a-z0-9]+", "-", raw_value).strip("-")
    return normalized or "cicids2019"


def _dataset_to_model_name(dataset_name: str | None) -> str:
    return f"rf-{_dataset_to_model_label(dataset_name)}"


def _load_latest_rf_model(
    org_id: str | None = None, model_name: str | None = None
) -> dict:
    base_query = (
        supabase_client.table("model_versions")
        .select(
            "id, org_id, version, artifact_bucket, artifact_path, status, created_at"
        )
        .eq("status", "active")
        .order("created_at", desc=True)
    )
    if org_id:
        base_query = base_query.eq("org_id", org_id)

    model_result = None
    if model_name:
        model_result = base_query.eq("name", model_name).limit(1).execute()

    if not model_result or not model_result.data:
        model_result = base_query.limit(1).execute()

    if not model_result.data:
        raise ValueError("No active RF model version found")

    model_row = model_result.data[0]
    artifact_path = model_row.get("artifact_path")
    artifact_bucket = model_row.get("artifact_bucket")
    if not artifact_path:
        raise ValueError("Active RF model version has no artifact_path")

    artifact_bytes = download_binary(artifact_path, bucket_name=artifact_bucket)
    local_path = Path(__file__).parent / ".models" / "rf_classifier.pkl"
    local_path.parent.mkdir(parents=True, exist_ok=True)
    with open(local_path, "wb") as model_file:
        model_file.write(artifact_bytes)

    classifier = get_classifier()
    load_result = classifier.load_model(str(local_path))
    if load_result.get("ERROR"):
        raise ValueError(load_result["ERROR"])

    return {
        "model_version_id": model_row.get("id"),
        "model_version": model_row.get("version"),
        "org_id": model_row.get("org_id"),
        "artifact_path": artifact_path,
        "artifact_bucket": artifact_bucket,
        "local_path": str(local_path),
    }


@main.route("/rf/train", methods=["POST"])
def train_rf_model():
    log = _request_logger(route="train_rf_model")
    role_error = _require_roles("admin")
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}

    org_id, org_scope_error = _enforce_org_scope(payload.get("org_id"))
    if org_scope_error:
        return org_scope_error

    dataset_path = payload.get("dataset_path")
    if not dataset_path:
        return _error_response("dataset_path is required", 400, "VALIDATION_ERROR")

    random_seed = int(payload.get("seed", 42))
    min_samples_per_class = int(payload.get("min_samples_per_class", 5))
    max_rows = payload.get("max_rows")
    max_rows = int(max_rows) if max_rows is not None else 120000
    requested_by = _auth_user_id() or payload.get("requested_by")
    dataset_name = payload.get("dataset_name", "CICIDS2019")
    model_label = _dataset_to_model_label(dataset_name)
    model_name = _dataset_to_model_name(dataset_name)
    activation_threshold = float(
        payload.get(
            "activation_threshold",
            os.getenv("RF_VALIDATION_PRECISION_THRESHOLD", "0.80"),
        )
    )

    training_run_id = None
    try:
        run_record = (
            supabase_client.table("training_runs")
            .insert(
                {
                    "org_id": org_id,
                    "status": "running",
                    "dataset_name": dataset_name,
                    "dataset_path": dataset_path,
                    "split_policy": "70/15/15_stratified",
                    "seed": random_seed,
                    "requested_by": requested_by,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            .execute()
        )
        if run_record.data:
            training_run_id = run_record.data[0]["id"]
    except Exception:
        log.exception("Failed to create training run record")
        return _error_response(
            "Failed to create training run record. Ensure RF training migrations are applied.",
            500,
            "DATABASE_ERROR",
            retryable=True,
            details={"database_error": "Database operation failed"},
        )

    try:
        bundle = prepare_cicids2019_training_bundle(
            dataset_path=dataset_path,
            seed=random_seed,
            min_samples_per_class=min_samples_per_class,
            max_rows=max_rows,
        )

        classifier = get_classifier()
        train_metrics = classifier.train(bundle["train_data"])
        if train_metrics.get("error"):
            raise ValueError(train_metrics["error"])

        validation_metrics = classifier.evaluate(bundle["validation_data"])
        if validation_metrics.get("error"):
            raise ValueError(validation_metrics["error"])

        test_metrics = classifier.evaluate(bundle["test_data"])
        if test_metrics.get("error"):
            raise ValueError(test_metrics["error"])

        model_status, validation_precision, activation_block_reason = (
            _get_activation_status(
                validation_metrics,
                activation_threshold,
            )
        )

        version = (
            datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid4().hex[:8]
        )
        local_model_path = (
            Path(__file__).parent / ".models" / f"rf_{model_label}_{version}.pkl"
        )
        local_model_path.parent.mkdir(parents=True, exist_ok=True)

        save_result = classifier.save_model(str(local_model_path))
        if save_result.get("error"):
            raise ValueError(save_result["error"])

        # Also keep a stable local artifact for automatic startup loading.
        stable_save_result = classifier.save_model()
        if stable_save_result.get("error"):
            raise ValueError(stable_save_result["error"])

        artifact_path = f"{org_id}/rf_models/rf_{model_label}_{version}.pkl"
        with open(local_model_path, "rb") as artifact:
            upload_binary(artifact_path, artifact.read())

        metadata = {
            "seed": random_seed,
            "split_policy": bundle["split_policy"],
            "dataset_name": dataset_name,
            "dataset_path": bundle["dataset_path"],
            "label_column": bundle["label_column"],
            "class_distribution": bundle["class_distribution"],
            "train_samples": len(bundle["train_data"]),
            "validation_samples": len(bundle["validation_data"]),
            "test_samples": len(bundle["test_data"]),
            "activation_threshold": activation_threshold,
            "validation_precision_weighted": validation_precision,
            "activation_status": model_status,
            "activation_block_reason": activation_block_reason,
        }

        model_version_record = (
            supabase_client.table("model_versions")
            .insert(
                {
                    "org_id": org_id,
                    "name": model_name,
                    "version": version,
                    "status": model_status,
                    "artifact_bucket": "ml-models",
                    "artifact_path": artifact_path,
                    "label_classes": train_metrics.get("categories", []),
                    "training_metadata": metadata,
                    "metrics": {
                        "train": train_metrics,
                        "validation": validation_metrics,
                        "test": test_metrics,
                    },
                    "created_by": requested_by,
                    "activated_at": datetime.now(timezone.utc).isoformat()
                    if model_status == "active"
                    else None,
                }
            )
            .execute()
        )

        model_version_id = (
            model_version_record.data[0]["id"] if model_version_record.data else None
        )

        _safe_update_training_run(
            training_run_id,
            {
                "status": "completed",
                "model_version_id": model_version_id,
                "total_samples": (
                    len(bundle["train_data"])
                    + len(bundle["validation_data"])
                    + len(bundle["test_data"])
                ),
                "class_distribution": bundle["class_distribution"],
                "train_metrics": train_metrics,
                "validation_metrics": {
                    **validation_metrics,
                    "activation_threshold": activation_threshold,
                    "activation_status": model_status,
                    "activation_block_reason": activation_block_reason,
                },
                "test_metrics": test_metrics,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        return jsonify(
            {
                "status": "completed",
                "training_run_id": training_run_id,
                "model_version_id": model_version_id,
                "model_name": model_name,
                "model_version": version,
                "artifact_path": artifact_path,
                "model_status": model_status,
                "activation_threshold": activation_threshold,
                "validation_precision_weighted": validation_precision,
                "activation_block_reason": activation_block_reason,
                "split_policy": bundle["split_policy"],
                "class_distribution": bundle["class_distribution"],
                "metrics": {
                    "train": train_metrics,
                    "validation": validation_metrics,
                    "test": test_metrics,
                },
                "request_id": _get_request_id(),
            }
        ), 201
    except Exception as exc:
        _safe_update_training_run(
            training_run_id,
            {
                "status": "failed",
                "error_message": str(exc),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        log.exception("RF training failed")
        return _error_response(
            "Model training failed", 500, "TRAINING_ERROR", retryable=False
        )


@main.route("/rf/load-latest", methods=["POST"])
def load_latest_rf_model():
    role_error = _require_roles("admin")
    if role_error:
        return role_error
    payload = request.get_json(silent=True) or {}
    org_id, org_scope_error = _enforce_org_scope(payload.get("org_id"))
    if org_scope_error:
        return org_scope_error
    log = _request_logger(route="load_latest_rf_model", org_id=org_id)

    model_name = payload.get("model_name")
    if not model_name:
        dataset_name = payload.get("dataset_name")
        if dataset_name:
            model_name = _dataset_to_model_name(dataset_name)

    try:
        details = _load_latest_rf_model(org_id=org_id, model_name=model_name)
        return jsonify(
            {
                "status": "loaded",
                "details": details,
                "request_id": _get_request_id(),
            }
        ), 200
    except Exception:
        log.exception("Failed to load latest RF model")
        return _error_response(
            "Failed to load model", 500, "MODEL_LOAD_ERROR", retryable=True
        )


