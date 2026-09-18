from __future__ import annotations

from typing import Any, Callable

import structlog

from .correlation_engine import run_correlation
from .log_classifier import get_classifier
from .rag_service import analyze_threats

logger = structlog.get_logger(__name__)


def build_rf_context(rf_results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rf_results = rf_results or []

    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    by_category: dict[str, int] = {}
    confidences: list[float] = []
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

        severity = (
            str(
                result.get("adjusted_severity")
                or result.get("mitre_severity")
                or "medium"
            )
            .strip()
            .lower()
        )
        if severity not in by_severity:
            severity = "medium"
        by_severity[severity] += 1

        if confidence >= high_confidence_threshold:
            if severity == "critical":
                high_conf_anomaly_count += 1
            elif severity == "high":
                high_conf_security_count += 1
            elif severity == "medium":
                high_conf_error_count += 1

    total = len(rf_results)
    return {
        "total": total,
        "average_confidence": (sum(confidences) / total) if total else 0.0,
        "by_severity": by_severity,
        "by_category": by_category,
        "high_confidence_threshold": high_confidence_threshold,
        "high_confidence_anomaly_count": high_conf_anomaly_count,
        "high_confidence_security_count": high_conf_security_count,
        "high_confidence_error_count": high_conf_error_count,
    }


def run_analysis_pipeline(
    entries: list[dict[str, Any]],
    org_id: str,
    file_id: str,
    source_type: str,
    request_id: str,
    *,
    log: Any = None,
    correlation_runner: Callable[..., list[dict[str, Any]]] = run_correlation,
    classifier_factory: Callable[[], Any] = get_classifier,
    threat_analyzer: Callable[..., dict[str, Any]] = analyze_threats,
) -> dict[str, Any]:
    analysis_log = log or logger

    try:
        detections = correlation_runner(entries, org_id, file_id, request_id=request_id)
    except Exception:
        detections = []
        analysis_log.exception("Correlation engine failed")

    rf_results: list[dict[str, Any]] = []
    try:
        classifier = classifier_factory()
        rf_results = classifier.classify_batch(entries)
    except Exception:
        analysis_log.exception("RF classification failed")

    rf_context = build_rf_context(rf_results)
    analysis = threat_analyzer(
        entries,
        source_type,
        detections=detections,
        rf_context=rf_context,
    )

    return {
        "detections": detections,
        "rf_results": rf_results,
        "rf_context": rf_context,
        "analysis": analysis,
    }
