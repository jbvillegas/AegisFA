from app.analysis_pipeline import build_rf_context, run_analysis_pipeline


class _Log:
    def __init__(self):
        self.messages = []

    def exception(self, message):
        self.messages.append(message)


class _Classifier:
    def classify_batch(self, entries):
        assert entries == [{"action": "login"}]
        return [
            {"category": "security", "confidence": 0.9, "adjusted_severity": "high"}
        ]


def test_build_rf_context_summarizes_results():
    context = build_rf_context(
        [
            {
                "category": "security",
                "confidence": 0.9,
                "adjusted_severity": "high",
            }
        ]
    )

    assert context["total"] == 1
    assert context["by_category"] == {"security": 1}
    assert context["by_severity"]["high"] == 1
    assert context["high_confidence_security_count"] == 1


def test_run_analysis_pipeline_returns_all_analysis_outputs():
    entries = [{"action": "login"}]
    calls = []

    def correlation_runner(*args, **kwargs):
        calls.append((args, kwargs))
        return [{"rule_name": "failed_login"}]

    def threat_analyzer(*args, **kwargs):
        return {"threat_level": "high", "detailed_findings": []}

    result = run_analysis_pipeline(
        entries,
        "org-id",
        "file-id",
        "auth",
        "request-id",
        correlation_runner=correlation_runner,
        classifier_factory=lambda: _Classifier(),
        threat_analyzer=threat_analyzer,
    )

    assert result["detections"] == [{"rule_name": "failed_login"}]
    assert result["rf_results"][0]["category"] == "security"
    assert result["analysis"]["threat_level"] == "high"
    assert calls[0][1] == {"request_id": "request-id"}


def test_run_analysis_pipeline_tolerates_detection_and_classifier_failures():
    log = _Log()

    def failing_correlation(*_args, **_kwargs):
        raise RuntimeError("correlation unavailable")

    def failing_classifier():
        raise RuntimeError("classifier unavailable")

    result = run_analysis_pipeline(
        [{"action": "login"}],
        "org-id",
        "file-id",
        "auth",
        "request-id",
        log=log,
        correlation_runner=failing_correlation,
        classifier_factory=failing_classifier,
        threat_analyzer=lambda *_args, **_kwargs: {"threat_level": "low"},
    )

    assert result["detections"] == []
    assert result["rf_results"] == []
    assert result["rf_context"]["total"] == 0
    assert result["analysis"]["threat_level"] == "low"
    assert log.messages == ["Correlation engine failed", "RF classification failed"]
