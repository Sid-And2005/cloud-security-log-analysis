
import pandas as pd

FEATURE_COLUMNS = [
    "request_count", "unique_users", "unique_endpoints",
    "unique_user_agents", "failed_logins", "http_errors",
    "sensitive_requests", "country_mismatches",
    "countries_last_24h", "switches_last_24h",
    "distinct_login_countries", "total_bytes", "average_bytes",
    "error_rate", "failed_login_rate", "sensitive_request_rate",
    "country_mismatch_rate", "endpoint_diversity_rate",
]

# Keep these paths identical to the original training script.
SENSITIVE_PATHS = {
    "/admin",
    "/.env",
    "/backup.sql",
    "/wp-admin",
    "/api/users/export",
}

AUTH_PATHS = ("/login", "/signin", "/auth", "/session", "/password")
ENUMERATION_PATHS = ("/users", "/account", "/profile", "/email", "/customer")
SCAN_PATHS = (
    "/admin", "/config", "/backup", "/.env", "/wp-admin",
    "/phpmyadmin", "/server-status", "/debug", "/api/key", "/actuator",
)


def _prepare(events):
    df = pd.DataFrame(events).copy()

    defaults = {
        "event_id": "",
        "timestamp": None,
        "source_ip": "unknown",
        "user_id": "unknown",
        "country": "unknown",
        "event_type": "request",
        "endpoint": "/",
        "user_agent": "unknown",
        "status_code": 200,
        "response_bytes": 0,
    }

    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default

    # Events are ISO-8601 (validated by stream_utils.validate_event); an
    # explicit format avoids slow, inconsistent per-element dateutil parsing.
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], utc=True, errors="coerce", format="ISO8601"
    )
    df["status_code"] = pd.to_numeric(
        df["status_code"], errors="coerce"
    ).fillna(0).astype(int)
    df["response_bytes"] = pd.to_numeric(
        df["response_bytes"], errors="coerce"
    ).fillna(0)
    df["endpoint"] = df["endpoint"].fillna("/").astype(str)
    df["event_type"] = df["event_type"].fillna("").astype(str).str.lower()
    df["user_id"] = df["user_id"].fillna("unknown").astype(str)
    df["country"] = df["country"].fillna("unknown").astype(str)
    df["user_agent"] = df["user_agent"].fillna("unknown").astype(str)

    return df


def build_window_features(events, login_history=None):
    """Build the original model features plus rule-only indicators."""
    df = _prepare(events)

    if df.empty:
        return {**{c: 0 for c in FEATURE_COLUMNS}, **{
            "endpoint_scan_count": 0,
            "auth_failures": 0,
            "enumeration_requests": 0,
            "large_responses": 0,
            "server_errors": 0,
            "client_errors": 0,
            "unique_sensitive_endpoints": 0,
            "failed_login_users": 0,
            "new_country_logins": 0,
            "baseline_login_count": 0,
            "baseline_deviations": 0,
        }}

    df["endpoint_norm"] = (
        df["endpoint"].str.lower().str.split("?").str[0]
    )

    # Original training definitions: preserve these for model inputs.
    df["failed_login"] = (
        df["event_type"].eq("login") & df["status_code"].eq(401)
    ).astype(int)
    df["http_error"] = df["status_code"].ge(400).astype(int)
    df["sensitive_request"] = df["endpoint"].isin(SENSITIVE_PATHS).astype(int)

    # Extra indicators used by explainable rules only.
    df["auth_failure"] = (
        df["endpoint_norm"].apply(
            lambda p: any(part in p for part in AUTH_PATHS)
        )
        & df["status_code"].between(400, 499)
    ).astype(int)

    df["scan_path"] = df["endpoint_norm"].apply(
        lambda p: int(any(part in p for part in SCAN_PATHS))
    )
    df["enumeration_request"] = df["endpoint_norm"].apply(
        lambda p: int(any(part in p for part in ENUMERATION_PATHS))
    )
    df["large_response"] = df["response_bytes"].ge(1_000_000).astype(int)
    df["server_error"] = df["status_code"].between(500, 599).astype(int)
    df["client_error"] = df["status_code"].between(400, 499).astype(int)

    # Persistent successful-login history is supplied by the consumer.
    history = _prepare(login_history or [])
    successful = history[
        history["event_type"].eq("login")
        & history["status_code"].between(200, 399)
    ].copy()

    current_logins = df[
        df["event_type"].eq("login")
        & df["status_code"].between(200, 399)
    ].copy()

    # Calculate historical features for successful logins in this window.
    mismatch_count = 0
    countries_24h = []
    switches_24h = []
    distinct_countries = []
    new_country_logins = 0
    baseline_login_count = 0
    baseline_deviations = 0

    for _, current in current_logins.iterrows():
        previous = successful[
            (successful["user_id"] == current["user_id"])
            & (
                (successful["timestamp"] < current["timestamp"])
                | (
                    (successful["timestamp"] == current["timestamp"])
                    & (successful["event_id"] < current["event_id"])
                )
            )
        ].sort_values(["timestamp", "event_id"])

        # Include earlier successful logins in the current window too.
        earlier_current = current_logins[
            (current_logins["user_id"] == current["user_id"])
            & (
                (current_logins["timestamp"] < current["timestamp"])
                | (
                    (current_logins["timestamp"] == current["timestamp"])
                    & (current_logins["event_id"] < current["event_id"])
                )
            )
        ]
        previous = pd.concat(
            [previous, earlier_current],
            ignore_index=True,
        ).drop_duplicates("event_id").sort_values(
            ["timestamp", "event_id"]
        )

        if previous.empty:
            continue

        baseline_country = previous["country"].mode()
        if baseline_country.empty:
            continue

        baseline_login_count = max(
            baseline_login_count, len(previous)
        )

        is_new_country = current["country"] != baseline_country.iloc[0]
        if is_new_country:
            new_country_logins += 1

        if len(previous) >= 3 and is_new_country:
            baseline_deviations += 1

        if current["country"] != previous.iloc[-1]["country"]:
            mismatch_count += 1

        cutoff = current["timestamp"] - pd.Timedelta(hours=24)
        recent = previous[
            (previous["timestamp"] >= cutoff)
            & (previous["timestamp"] < current["timestamp"])
        ]

        countries_24h.append(recent["country"].nunique())

        switches_24h.append(
            int(recent["country"].ne(recent["country"].shift()).sum())
            if len(recent) > 1 else 0
        )

        distinct_countries.append(recent["country"].nunique())

    n = len(df)
    failed = int(df["failed_login"].sum())
    errors = int(df["http_error"].sum())
    sensitive = int(df["sensitive_request"].sum())
    total_bytes = float(df["response_bytes"].sum())
    unique_endpoints = int(df["endpoint"].nunique())

    features = {
        "request_count": n,
        "unique_users": int(df["user_id"].nunique()),
        "unique_endpoints": unique_endpoints,
        "unique_user_agents": int(df["user_agent"].nunique()),
        "failed_logins": failed,
        "http_errors": errors,
        "sensitive_requests": sensitive,
        "country_mismatches": mismatch_count,
        "countries_last_24h": max(countries_24h, default=0),
        "switches_last_24h": max(switches_24h, default=0),
        "distinct_login_countries": max(distinct_countries, default=0),
        "total_bytes": total_bytes,
        "average_bytes": total_bytes / n if n else 0,
        "error_rate": errors / n if n else 0,
        "failed_login_rate": failed / n if n else 0,
        "sensitive_request_rate": sensitive / n if n else 0,
        "country_mismatch_rate": mismatch_count / n if n else 0,
        "endpoint_diversity_rate": unique_endpoints / n if n else 0,
        "endpoint_scan_count": int(df["scan_path"].sum()),
        "auth_failures": int(df["auth_failure"].sum()),
        "enumeration_requests": int(df["enumeration_request"].sum()),
        "large_responses": int(df["large_response"].sum()),
        "server_errors": int(df["server_error"].sum()),
        "client_errors": int(df["client_error"].sum()),
        "unique_sensitive_endpoints": int(
            df.loc[df["sensitive_request"].eq(1), "endpoint"].nunique()
        ),
        "failed_login_users": int(
            df.loc[df["auth_failure"].eq(1), "user_id"].nunique()
        ),
        "new_country_logins": new_country_logins,
        "baseline_login_count": baseline_login_count,
        "baseline_deviations": baseline_deviations,
    }

    return features