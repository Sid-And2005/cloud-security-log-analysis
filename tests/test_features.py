from src.features import FEATURE_COLUMNS, build_window_features
from conftest import make_event


def test_empty_window():
    result = build_window_features([])
    assert result["request_count"] == 0
    assert result["error_rate"] == 0


def test_failed_logins():
    events = [
        {"timestamp":"2026-10-20T10:00:00Z","user_id":"alice","country":"India","event_type":"login","endpoint":"/login","status_code":401,"response_bytes":10,"user_agent":"test"},
        {"timestamp":"2026-10-20T10:00:01Z","user_id":"alice","country":"India","event_type":"login","endpoint":"/login","status_code":401,"response_bytes":10,"user_agent":"test"},
    ]
    result = build_window_features(events)
    assert result["failed_logins"] == 2
    assert result["request_count"] == 2


def test_all_model_features_present_and_numeric():
    events = [make_event("e1", "2026-10-20T10:00:00+00:00")]
    result = build_window_features(events)
    for column in FEATURE_COLUMNS:
        assert isinstance(result[column], (int, float)), column


def test_rates_and_counts():
    events = [
        make_event("e1", "2026-10-20T10:00:00Z", endpoint="/admin", status_code=403),
        make_event("e2", "2026-10-20T10:00:01Z", endpoint="/.env", status_code=404),
        make_event("e3", "2026-10-20T10:00:02Z", endpoint="/home", status_code=200, response_bytes=1_500_000),
        make_event("e4", "2026-10-20T10:00:03Z", endpoint="/home", status_code=500),
    ]
    f = build_window_features(events)
    assert f["request_count"] == 4
    assert f["http_errors"] == 3
    assert f["error_rate"] == 0.75
    assert f["sensitive_requests"] == 2
    assert f["unique_endpoints"] == 3
    assert f["endpoint_diversity_rate"] == 0.75
    assert f["large_responses"] == 1
    assert f["server_errors"] == 1


def test_mixed_timestamp_formats_parse_consistently():
    events = [
        make_event("e1", "2026-10-20T10:00:00Z"),
        make_event("e2", "2026-10-20T10:00:01.123456+00:00"),
        make_event("e3", "2026-10-20T15:30:02+05:30"),
    ]
    f = build_window_features(events)
    assert f["request_count"] == 3


def test_country_baseline_uses_history():
    history = [
        make_event(f"h{i}", f"2026-10-20T0{i}:00:00Z", event_type="login",
                   endpoint="/login", status_code=200, country="India")
        for i in range(4)
    ]
    current = [make_event("c1", "2026-10-20T10:00:00Z", event_type="login",
                          endpoint="/login", status_code=200, country="Brazil")]
    f = build_window_features(current, history)
    assert f["country_mismatches"] == 1
    assert f["baseline_deviations"] == 1
    assert f["new_country_logins"] == 1

    no_history = build_window_features(current, [])
    assert no_history["country_mismatches"] == 0
