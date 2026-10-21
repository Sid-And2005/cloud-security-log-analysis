"""Threat detection: the Random Forest is the primary detector.

The explainable rules in ``detect_threats`` are supplementary. Every result
records ``detection_source`` so ML predictions are never confused with rule
matches:

* ``ml``        - the Random Forest flagged the window; no rule matched
* ``ml+rules``  - the Random Forest flagged it and rules supply evidence
* ``rules``     - only supplementary rules matched (the model did not flag it)
* ``none``      - no alert
"""

import hashlib
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone

import joblib
import pandas as pd

from . import config
from .features import FEATURE_COLUMNS, build_window_features
from .stream_utils import window_start

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ML_ONLY_THREAT = "ML-only anomaly"


class ModelError(RuntimeError):
    """The model bundle is missing, malformed or incompatible."""


@dataclass(frozen=True)
class ModelBundle:
    model: object
    feature_columns: list
    anomaly_index: int
    version: str
    path: str


@dataclass(frozen=True)
class Score:
    prediction: int
    probability: float
    detector: str
    model_version: str


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_bundle(raw, path, anomaly_label=None):
    """Check a loaded bundle against the inference feature schema."""
    anomaly_label = config.ANOMALY_LABEL if anomaly_label is None else anomaly_label

    if not isinstance(raw, dict) or "model" not in raw or "feature_columns" not in raw:
        raise ModelError(f"{path}: bundle must be a dict with 'model' and 'feature_columns'")

    model = raw["model"]
    columns = list(raw["feature_columns"])

    if columns != FEATURE_COLUMNS:
        missing = sorted(set(columns) - set(FEATURE_COLUMNS))
        extra = sorted(set(FEATURE_COLUMNS) - set(columns))
        raise ModelError(
            f"{path}: feature_columns do not match src/features.py "
            f"(only in model: {missing}; only in code: {extra}; or order differs)"
        )

    trained_names = getattr(model, "feature_names_in_", None)
    if trained_names is not None and list(trained_names) != columns:
        raise ModelError(f"{path}: model.feature_names_in_ differs from bundle feature_columns")

    n_features = getattr(model, "n_features_in_", len(columns))
    if n_features != len(columns):
        raise ModelError(f"{path}: model expects {n_features} features, bundle lists {len(columns)}")

    if not hasattr(model, "predict_proba"):
        raise ModelError(f"{path}: model has no predict_proba")

    classes = list(getattr(model, "classes_", []))
    if anomaly_label not in classes:
        raise ModelError(
            f"{path}: anomaly label {anomaly_label!r} not in model classes {classes}"
        )

    return columns, classes.index(anomaly_label)


def load_bundle(path=None):
    path = path or config.MODEL_PATH
    if not path.exists():
        raise ModelError(f"Model file not found: {path}")

    raw = joblib.load(path)
    columns, anomaly_index = validate_bundle(raw, path)
    # Single-row scoring: a per-call thread pool (n_jobs=-1) is ~4x slower.
    # Predictions are identical; only parallelism changes.
    if hasattr(raw["model"], "n_jobs"):
        raw["model"].set_params(n_jobs=1)
    version = raw.get("version") or f"{path.stem}@{_file_sha256(path)[:12]}"
    return ModelBundle(raw["model"], columns, anomaly_index, version, str(path))


_bundle = None
_bundle_loaded = False


def load_model():
    """Load the configured model once.

    Returns None (labelled rules-only fallback) only when REQUIRE_MODEL is
    false; otherwise a missing or invalid model raises ModelError.
    """
    global _bundle, _bundle_loaded
    if _bundle_loaded:
        return _bundle

    try:
        _bundle = load_bundle()
        log.info(
            "Loaded model", extra={"operation": "model_load", "model_version": _bundle.version}
        )
    except ModelError:
        if config.REQUIRE_MODEL:
            raise
        log.warning(
            "Model unavailable; using the labelled rules-only fallback",
            exc_info=True,
            extra={"operation": "model_load"},
        )
        _bundle = None
    _bundle_loaded = True
    return _bundle


def _clean(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def model_input(features, columns):
    """One-row frame in the exact training column order; missing/invalid -> 0."""
    return pd.DataFrame(
        [[_clean(features.get(c, 0)) for c in columns]],
        columns=columns,
    )


def score_features(features, bundle=None):
    bundle = bundle if bundle is not None else load_model()

    if bundle:
        X = model_input(features, bundle.feature_columns)
        probabilities = bundle.model.predict_proba(X)[0]
        probability = float(probabilities[bundle.anomaly_index])
        # Same decision as model.predict(): the class with the highest score.
        prediction = int(int(probabilities.argmax()) == bundle.anomaly_index)
        return Score(prediction, probability, "random_forest", bundle.version)

    # Explicitly label the fallback; it is not an ML prediction.
    suspicious = (
        features.get("auth_failures", 0) >= 5
        or features.get("request_count", 0) >= 40
        or features.get("endpoint_scan_count", 0) >= 4
        or features.get("sensitive_requests", 0) >= 8
        or features.get("baseline_deviations", 0) > 0
    )
    return Score(int(suspicious), float(int(suspicious)), "rules_fallback", "none")


def detect_threats(f):
    """Supplementary explainable rules. Returns (name, evidence, severity)."""
    threats = []

    failed = int(f.get("auth_failures", 0))
    requests = int(f.get("request_count", 0))
    errors = int(f.get("http_errors", 0))
    server_errors = int(f.get("server_errors", 0))
    scans = int(f.get("endpoint_scan_count", 0))
    enumeration = int(f.get("enumeration_requests", 0))
    large = int(f.get("large_responses", 0))
    sensitive = int(f.get("sensitive_requests", 0))
    unique_sensitive = int(f.get("unique_sensitive_endpoints", 0))
    failed_users = int(f.get("failed_login_users", 0))

    # Brute-force / authentication abuse
    if failed >= 20:
        threats.append((
            "Brute-force login activity",
            f"{failed} failed authentication responses in this IP window",
            "CRITICAL",
        ))
    elif failed >= 10:
        threats.append((
            "Repeated failed logins",
            f"{failed} failed authentication responses in this IP window",
            "HIGH",
        ))
    elif failed >= 5:
        threats.append((
            "Multiple failed logins",
            f"{failed} failed authentication responses in this IP window",
            "MEDIUM",
        ))
    elif failed >= 2:
        threats.append((
            "Authentication failures",
            f"{failed} failed authentication responses in this IP window",
            "LOW",
        ))

    # Request flood
    if requests >= 120:
        threats.append((
            "Possible request flood",
            f"{requests} requests from this IP in the five-minute window",
            "CRITICAL",
        ))
    elif requests >= 60:
        threats.append((
            "High request volume",
            f"{requests} requests from this IP in the five-minute window",
            "HIGH",
        ))
    elif requests >= 40:
        threats.append((
            "Elevated request volume",
            f"{requests} requests from this IP in the five-minute window",
            "MEDIUM",
        ))

    # Endpoint scanning
    if scans >= 10:
        threats.append((
            "Endpoint scanning pattern",
            f"{scans} requests matched known scanning paths",
            "HIGH",
        ))
    elif scans >= 4:
        threats.append((
            "Possible endpoint scanning",
            f"{scans} requests matched known scanning paths",
            "MEDIUM",
        ))
    elif scans >= 2:
        threats.append((
            "Endpoint probing",
            f"{scans} requests matched known scanning paths",
            "LOW",
        ))

    # Sensitive paths
    if sensitive >= 12 or unique_sensitive >= 5:
        threats.append((
            "Repeated sensitive endpoint access",
            f"{sensitive} requests across {unique_sensitive} sensitive endpoints",
            "HIGH",
        ))
    elif sensitive >= 5:
        threats.append((
            "Sensitive endpoint access",
            f"{sensitive} requests matched sensitive paths",
            "MEDIUM",
        ))

    # Account enumeration
    if enumeration >= 15:
        threats.append((
            "Possible account enumeration",
            f"{enumeration} requests targeted account/profile paths",
            "HIGH",
        ))
    elif enumeration >= 6:
        threats.append((
            "Repeated account/profile lookups",
            f"{enumeration} requests targeted account/profile paths",
            "MEDIUM",
        ))

    # HTTP errors
    if server_errors >= 10:
        threats.append((
            "Server error spike",
            f"{server_errors} HTTP 5xx responses",
            "HIGH",
        ))
    elif errors >= 12:
        threats.append((
            "Elevated HTTP errors",
            f"{errors} HTTP 4xx/5xx responses",
            "MEDIUM",
        ))
    elif errors >= 5:
        threats.append((
            "HTTP errors observed",
            f"{errors} HTTP 4xx/5xx responses",
            "LOW",
        ))

    # Unusually large responses
    if large >= 3:
        threats.append((
            "Repeated large responses",
            f"{large} responses were at least 1 MB",
            "HIGH",
        ))
    elif large >= 1:
        threats.append((
            "Unusually large response",
            f"{large} response(s) were at least 1 MB",
            "MEDIUM",
        ))

    # Country-baseline deviation
    deviations = int(f.get("baseline_deviations", 0))
    if deviations > 0:
        threats.append((
            "Unusual login country",
            f"{deviations} successful login(s) deviated from the historical country baseline",
            "HIGH",
        ))

    if failed_users >= 5 and failed >= 8:
        threats.append((
            "Failures across multiple accounts",
            f"Authentication failures involved {failed_users} user accounts",
            "HIGH",
        ))

    return threats


def detection_source(prediction, threats):
    rule_hit = any(name != ML_ONLY_THREAT for name, _, _ in threats)
    if prediction and rule_hit:
        return "ml+rules"
    if prediction:
        return "ml"
    if rule_hit:
        return "rules"
    return "none"


def evaluate_window(event, window_events, login_history=None, bundle=None):
    """Score one event's IP window. Pure: performs no storage writes."""
    now = datetime.now(timezone.utc).isoformat()

    features = build_window_features(window_events, login_history)
    score = score_features(features, bundle)
    prediction = score.prediction
    threats = detect_threats(features)

    # Keep model-only alerts separate from concrete rule evidence.
    if prediction and not threats:
        threats.append((
            ML_ONLY_THREAT,
            f"Random Forest flagged an unusual feature combination (score {score.probability:.3f}); "
            "no configured threat rule matched",
            "MEDIUM",
        ))

    source = detection_source(prediction, threats)
    alert = source != "none"

    severity = max(
        (threat[2] for threat in threats),
        key=lambda value: SEVERITY_ORDER[value],
        default="NONE",
    )
    # An ML-flagged window is at least MEDIUM: previously an ML-only alert was
    # MEDIUM while ML plus a weak LOW rule was LOW, i.e. more evidence gave a
    # lower severity. The ML score never raises severity beyond MEDIUM.
    if prediction and SEVERITY_ORDER[severity] < SEVERITY_ORDER["MEDIUM"]:
        severity = "MEDIUM"

    reason = "; ".join(f"{name}: {detail}" for name, detail, _ in threats)
    if prediction and source == "ml+rules":
        reason = (
            f"Random Forest anomaly (score {score.probability:.3f}); " + reason
        )
    if not alert:
        reason = "No configured rule or ML alert matched this window"

    return {
        **event,
        "window": window_start(event.get("timestamp", now), config.WINDOW_MINUTES),
        "prediction": prediction,
        "anomaly_probability": round(score.probability, 5),
        "detector": score.detector,
        "model_version": score.model_version,
        "detection_source": source,
        "alert": alert,
        "threat_types": "; ".join(dict.fromkeys(name for name, _, _ in threats)),
        "reason": reason,
        "priority": severity,
        "window_event_count": int(features.get("request_count", 0)),
        "features": {c: features.get(c, 0) for c in FEATURE_COLUMNS},
        "processed_at": now,
    }


def process_event(event, window_events, login_history=None, storage=None):
    """Evaluate and persist one event (kept for scripts and backwards compatibility)."""
    from .storage import get_storage

    record = evaluate_window(event, window_events, login_history)
    (storage or get_storage()).save_result(record)
    return record
