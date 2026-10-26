from app.routes.utils import _get_activation_status


def test_rf_activation_rejects_precision_below_hard_minimum():
    status, precision, reason = _get_activation_status(
        {"precision_weighted": 0.79},
        threshold=0.80,
    )

    assert status == "archived"
    assert precision == 0.79
    assert "0.800" in reason


def test_rf_activation_accepts_precision_at_hard_minimum():
    status, precision, reason = _get_activation_status(
        {"precision_weighted": 0.80},
        threshold=0.80,
    )

    assert status == "active"
    assert precision == 0.80
    assert reason is None


def test_rf_activation_cannot_be_lowered_by_requested_threshold():
    status, _, reason = _get_activation_status(
        {"precision_weighted": 0.79},
        threshold=0.50,
    )

    assert status == "archived"
    assert "0.800" in reason