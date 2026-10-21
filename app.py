
import pandas as pd
import plotly.express as px
import streamlit as st

from src import config
from src.storage import StorageError, get_storage, infer_detection_source

st.set_page_config(
    page_title="Security Log Threat Monitor",
    page_icon="🛡️",
    layout="wide",
)

try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=config.DASHBOARD_REFRESH_SECONDS * 1000, key="dashboard_refresh")
except ImportError:
    st.caption("Install streamlit-autorefresh for automatic refresh.")

st.title("🛡️ Security Log Analysis & Threat Detection")
st.caption(
    "Live monitoring | Random Forest ML detection (primary) + explainable "
    f"supplementary rules | backend: {config.STORAGE_BACKEND}"
)

SOURCE_LABELS = {
    "ml": "ML only",
    "ml+rules": "ML + rule evidence",
    "rules": "Rules only (supplementary)",
}


def storage():
    # get_storage() returns one shared instance (and pool) per process.
    config.validate_settings()
    return get_storage()


def load_data():
    """Load from the configured backend.

    CSV (local): a transient read error shows the last valid data, as before.
    PostgreSQL (cloud): an unavailable database stops the page with an error
    rather than showing stale data.
    """
    backend = storage()
    try:
        data = (
            backend.load_alerts(config.DASHBOARD_ALERT_LIMIT),
            backend.load_events(config.DASHBOARD_EVENT_LIMIT),
            backend.stats(),
        )
        st.session_state["last_valid"] = data
        return data
    except StorageError as exc:
        if backend.name == "csv" and "last_valid" in st.session_state:
            st.warning(f"Temporary read error ({exc}); showing last valid data.")
            return st.session_state["last_valid"]
        st.error(
            f"**Storage backend unavailable** ({backend.name}): {exc}\n\n"
            "No data is shown to avoid displaying stale results."
        )
        st.stop()


try:
    alerts, events, stats = load_data()
except config.ConfigError as exc:
    st.error(f"**Configuration error**\n\n```\n{exc}\n```")
    st.stop()
alerts, events = alerts.copy(), events.copy()

defaults = {
    "source_ip": "Unknown",
    "user_id": "Unknown",
    "priority": "NONE",
    "reason": "",
    "threat_types": "",
    "anomaly_probability": 0.0,
    "processed_at": "",
    "window": "",
    "detector": "unknown",
    "alert": False,
}

for df in (events, alerts):
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default

    df["priority"] = df["priority"].fillna("NONE").astype(str).str.upper()
    df["anomaly_probability"] = pd.to_numeric(
        df["anomaly_probability"], errors="coerce"
    ).fillna(0)
    df["processed_at"] = pd.to_datetime(
        df["processed_at"], errors="coerce", utc=True, format="ISO8601"
    )

alerts["detection_source"] = (
    alerts.apply(infer_detection_source, axis=1) if not alerts.empty else pd.Series(dtype=str)
)
alerts["Detected by"] = alerts["detection_source"].map(SOURCE_LABELS).fillna("Unknown")


# --------------------------------------------------
# SYSTEM HEALTH
# --------------------------------------------------

with st.sidebar.expander("System health", expanded=False):
    health = storage().health()
    st.write(("🟢" if health.get("ok") else "🔴") + f" Storage: {health.get('detail', '')}")
    try:
        batch = storage().last_batch()
    except StorageError:
        batch = None
    if batch:
        st.write(f"Last ingestion batch: `{batch.get('batch_id')}` ({batch.get('status')})")
        if batch.get("blob_uri"):
            st.caption(f"Raw archive: {batch['blob_uri']}")
    else:
        st.write("No ingestion batches recorded yet.")


st.sidebar.header("Filters")
severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

selected_severities = st.sidebar.multiselect(
    "Severity",
    severities,
    default=severities,
)

selected_sources = st.sidebar.multiselect(
    "Detected by",
    list(SOURCE_LABELS.values()),
    default=list(SOURCE_LABELS.values()),
)

ips = st.sidebar.text_input("Filter by source IP")

threat_names = sorted({
    name.strip()
    for value in alerts["threat_types"].dropna().astype(str)
    for name in value.split(";")
    if name.strip()
})

selected_threats = st.sidebar.multiselect(
    "Threat type",
    threat_names,
    default=[],
)

filtered = alerts[
    alerts["priority"].isin(selected_severities)
    & alerts["Detected by"].isin(selected_sources)
].copy()

if ips.strip():
    filtered = filtered[
        filtered["source_ip"].astype(str).str.contains(
            ips.strip(), case=False, na=False
        )
    ]

if selected_threats:
    filtered = filtered[
        filtered["threat_types"].apply(
            lambda value: bool(
                set(selected_threats)
                & {x.strip() for x in str(value).split(";")}
            )
        )
    ]


# --------------------------------------------------
# TOP-LEVEL METRICS
# --------------------------------------------------

by_severity = stats["by_severity"]
by_source = stats["by_source"]
critical = by_severity.get("CRITICAL", 0)
high = by_severity.get("HIGH", 0)
medium = by_severity.get("MEDIUM", 0)
low = by_severity.get("LOW", 0)

ml_detected = by_source.get("ml", 0) + by_source.get("ml+rules", 0)
ml_only = by_source.get("ml", 0)
rule_detected = by_source.get("ml+rules", 0) + by_source.get("rules", 0)
rules_only = by_source.get("rules", 0)

cols = st.columns(4)
cols[0].metric("Events processed", f"{stats['events_total']:,}")
cols[1].metric("Alert records", f"{stats['alerts_total']:,}")
cols[2].metric("Critical", critical)
cols[3].metric("High", high)

cols = st.columns(4)
cols[0].metric(
    "ML-detected alerts", ml_detected,
    help="Windows the Random Forest classified as anomalous (with or without rule evidence)",
)
cols[1].metric(
    "ML-only anomalies", ml_only,
    help="Random Forest anomalies that no supplementary rule explains",
)
cols[2].metric(
    "Rule detections", rule_detected,
    help="Alerts with at least one supplementary rule match",
)
cols[3].metric(
    "Rules-only alerts", rules_only,
    help="Supplementary rule matches the Random Forest did not flag",
)

st.divider()


# --------------------------------------------------
# CHARTS
# --------------------------------------------------

left, right = st.columns(2)

with left:
    st.subheader("Alerts by severity")

    severity_df = pd.DataFrame({
        "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "Count": [critical, high, medium, low],
    })

    fig = px.bar(
        severity_df,
        x="Severity",
        y="Count",
        color="Severity",
        category_orders={"Severity": severities},
        title="Current alert distribution",
    )
    st.plotly_chart(fig, width="stretch")

with right:
    st.subheader("Specific threat indicators")

    counts = {}
    rule_mask = alerts["detection_source"].isin(["ml+rules", "rules"])
    for value in alerts.loc[rule_mask, "threat_types"].dropna().astype(str):
        for name in value.split(";"):
            name = name.strip()
            if name and name != "ML-only anomaly":
                counts[name] = counts.get(name, 0) + 1

    if counts:
        threat_df = pd.DataFrame([
            {"Threat type": name, "Count": count}
            for name, count in counts.items()
        ]).sort_values("Count", ascending=False).head(10)

        fig = px.bar(
            threat_df,
            x="Count",
            y="Threat type",
            orientation="h",
            title="Rule-detected indicators (top 10)",
        )
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No rule-based threat indicators have been recorded yet.")

source_df = pd.DataFrame({
    "Detected by": [SOURCE_LABELS[s] for s in ("ml", "ml+rules", "rules")],
    "Count": [by_source.get(s, 0) for s in ("ml", "ml+rules", "rules")],
})
if source_df["Count"].sum():
    fig = px.bar(
        source_df, x="Count", y="Detected by", orientation="h",
        title="Alerts by detection source (Random Forest vs supplementary rules)",
    )
    st.plotly_chart(fig, width="stretch")

st.divider()


# --------------------------------------------------
# ALERT INVESTIGATION
# --------------------------------------------------

st.subheader("🚨 Alert investigation")
st.caption(
    f"{len(filtered):,} alert records match the current filters "
    f"(showing up to {config.DASHBOARD_ALERT_LIMIT:,} most recent)."
)

if filtered.empty:
    st.info("No alerts match the selected filters.")
else:
    display_cols = [
        "processed_at",
        "source_ip",
        "user_id",
        "window",
        "threat_types",
        "priority",
        "anomaly_probability",
        "Detected by",
        "reason",
        "model_version",
    ]
    display_cols = [c for c in display_cols if c in filtered.columns]

    st.dataframe(
        filtered.sort_values(
            "processed_at", ascending=False, na_position="last"
        )[display_cols],
        width="stretch",
        hide_index=True,
        column_config={
            "processed_at": st.column_config.DatetimeColumn(
                "Detected at (UTC)", format="YYYY-MM-DD HH:mm:ss"
            ),
            "anomaly_probability": st.column_config.ProgressColumn(
                "RF anomaly score", format="%.3f", min_value=0.0, max_value=1.0
            ),
            "reason": st.column_config.TextColumn(
                "Detection evidence", width="large"
            ),
            "threat_types": st.column_config.TextColumn(
                "Threat type", width="medium"
            ),
            "model_version": st.column_config.TextColumn("Model"),
        },
    )


with st.expander("Recent processed events"):
    if events.empty:
        st.info("No events have been processed yet.")
    else:
        event_cols = [
            "processed_at", "source_ip", "user_id", "event_type",
            "endpoint", "status_code", "priority",
            "anomaly_probability", "detection_source", "reason",
        ]
        event_cols = [c for c in event_cols if c in events.columns]

        st.dataframe(
            events.sort_values(
                "processed_at", ascending=False, na_position="last"
            ).head(config.DASHBOARD_EVENT_LIMIT)[event_cols],
            width="stretch",
            hide_index=True,
        )


st.divider()
st.caption(
    "Synthetic demonstration. An alert indicates suspicious behaviour, "
    "not proof of a real attack. The Random Forest score is the model's class "
    "score, not necessarily a calibrated probability of malicious activity."
)

if st.button("Refresh now"):
    st.rerun()
