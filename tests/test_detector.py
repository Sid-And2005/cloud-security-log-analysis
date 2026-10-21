import numpy as np
import pytest

from src import config, detector
from src.detector import (
    ModelBundle, ModelError, detection_source, evaluate_window, model_input,
    score_features, validate_bundle,
)
from src.features import FEATURE_COLUMNS
from conftest import make_event


class FakeModel:
    """Minimal classifier with a configurable class order and score."""

    def __init__(self, classes=(0, 1), anomaly_score=0.9, columns=FEATURE_COLUMNS):
        self.classes_ = np.array(classes)
        self.feature_names_in_ = np.array(columns)
        self.n_features_in_ = len(columns)
        self.anomaly_score = anomaly_score
        self.seen = None

    def predict_proba(self, X):
        self.seen = list(X.columns)
        anomaly_at = list(self.classes_).index(1)
        row = [0.0] * len(self.classes_)
        row[anomaly_at] = self.anomaly_score
        row[1 - anomaly_at] = 1 - self.anomaly_score
        return np.array([row])


def bundle_for(model):
    columns, idx = validate_bundle({"model": model, "feature_columns": FEATURE_COLUMNS}, "fake")
    return ModelBundle(model, columns, idx, "fake@1", "fake")


def test_model_input_uses_training_column_order_and_cleans_values():
    features = {c: i for i, c in enumerate(reversed(FEATURE_COLUMNS))}
    features["error_rate"] = float("nan")
    features["total_bytes"] = "oops"
    del features["request_count"]
    X = model_input(features, FEATURE_COLUMNS)
    assert list(X.columns) == FEATURE_COLUMNS
    assert X.loc[0, "error_rate"] == 0.0
    assert X.loc[0, "total_bytes"] == 0.0
    assert X.loc[0, "request_count"] == 0.0


def test_anomaly_probability_follows_class_label_not_index():
    # Classes stored as [1, 0]: index 1 is the *normal* class.
    model = FakeModel(classes=(1, 0), anomaly_score=0.8)
    score = score_features({}, bundle_for(model))
    assert score.probability == pytest.approx(0.8)
    assert score.prediction == 1
    assert model.seen == FEATURE_COLUMNS


def test_low_score_is_not_an_anomaly():
    score = score_features({}, bundle_for(FakeModel(anomaly_score=0.3)))
    assert score.prediction == 0
    assert score.probability == pytest.approx(0.3)
    assert score.detector == "random_forest"
    assert score.model_version == "fake@1"


def test_validate_bundle_rejects_schema_mismatch():
    with pytest.raises(ModelError, match="feature_columns"):
        validate_bundle({"model": FakeModel(), "feature_columns": FEATURE_COLUMNS[::-1]}, "x")
    with pytest.raises(ModelError, match="feature_names_in_"):
        validate_bundle({"model": FakeModel(columns=FEATURE_COLUMNS[::-1]),
                         "feature_columns": FEATURE_COLUMNS}, "x")
    with pytest.raises(ModelError, match="anomaly label"):
        validate_bundle({"model": FakeModel(classes=(0, 2)), "feature_columns": FEATURE_COLUMNS}, "x")
    with pytest.raises(ModelError, match="dict"):
        validate_bundle(FakeModel(), "x")


def test_detection_source_classification():
    rule = [("Possible request flood", "x", "CRITICAL")]
    ml_only = [(detector.ML_ONLY_THREAT, "x", "MEDIUM")]
    assert detection_source(1, rule) == "ml+rules"
    assert detection_source(1, ml_only) == "ml"
    assert detection_source(0, rule) == "rules"
    assert detection_source(0, []) == "none"


def _window(n, **kw):
    return [make_event(f"e{i}", f"2026-10-20T10:00:{i:02d}Z", **kw) for i in range(n)]


def test_ml_only_alert_is_labelled_and_medium():
    events = _window(1)
    record = evaluate_window(events[0], events, [], bundle_for(FakeModel(anomaly_score=0.9)))
    assert record["alert"] is True
    assert record["detection_source"] == "ml"
    assert record["threat_types"] == "ML-only anomaly"
    assert record["priority"] == "MEDIUM"
    assert record["model_version"] == "fake@1"


def test_rule_only_alert_is_not_reported_as_ml():
    events = _window(45)  # 45 requests -> "Elevated request volume" rule
    record = evaluate_window(events[-1], events, [], bundle_for(FakeModel(anomaly_score=0.1)))
    assert record["detection_source"] == "rules"
    assert record["prediction"] == 0
    assert "ML-only" not in record["threat_types"]
    assert "Random Forest" not in record["reason"]


def test_ml_flag_raises_low_rule_severity_to_medium():
    events = _window(2, event_type="login", endpoint="/login", status_code=401)  # LOW rule
    low = evaluate_window(events[-1], events, [], bundle_for(FakeModel(anomaly_score=0.1)))
    assert low["priority"] == "LOW"
    flagged = evaluate_window(events[-1], events, [], bundle_for(FakeModel(anomaly_score=0.9)))
    assert flagged["priority"] == "MEDIUM"
    assert flagged["detection_source"] == "ml+rules"


def test_no_alert_record():
    events = _window(1)
    record = evaluate_window(events[0], events, [], bundle_for(FakeModel(anomaly_score=0.1)))
    assert record["alert"] is False
    assert record["priority"] == "NONE"
    assert record["detection_source"] == "none"
    assert set(record["features"]) == set(FEATURE_COLUMNS)


def test_missing_model_raises_when_required(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(config, "REQUIRE_MODEL", True)
    monkeypatch.setattr(detector, "_bundle_loaded", False)
    with pytest.raises(ModelError, match="not found"):
        detector.load_model()


def test_missing_model_uses_labelled_fallback_when_allowed(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(config, "REQUIRE_MODEL", False)
    monkeypatch.setattr(detector, "_bundle_loaded", False)
    monkeypatch.setattr(detector, "_bundle", None)
    assert detector.load_model() is None
    score = score_features({"request_count": 50})
    assert score.detector == "rules_fallback"
    monkeypatch.setattr(detector, "_bundle_loaded", False)


@pytest.mark.skipif(not config.MODEL_PATH.exists(), reason="trained model not present")
def test_real_model_bundle_matches_feature_schema():
    bundle = detector.load_bundle()
    assert bundle.feature_columns == FEATURE_COLUMNS
    assert list(bundle.model.classes_)[bundle.anomaly_index] == 1
    assert bundle.version.startswith(config.MODEL_PATH.stem)


@pytest.mark.skipif(not config.MODEL_PATH.exists(), reason="trained model not present")
def test_real_model_prediction_matches_sklearn_predict():
    bundle = detector.load_bundle()
    rng = np.random.default_rng(0)
    for _ in range(25):
        features = {c: float(v) for c, v in zip(FEATURE_COLUMNS, rng.random(18) * rng.integers(1, 150, 18))}
        X = model_input(features, bundle.feature_columns)
        expected = int(bundle.model.predict(X)[0] == 1)
        assert score_features(features, bundle).prediction == expected
