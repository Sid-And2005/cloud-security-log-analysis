-- 001: initial schema for the security log platform.
-- Raw logs live in Azure Blob Storage; these tables hold structured,
-- queryable records. All timestamps are timestamptz stored in UTC.

CREATE TABLE IF NOT EXISTS ingestion_batches (
    batch_id      TEXT PRIMARY KEY,
    blob_uri      TEXT,
    event_count   INTEGER     NOT NULL DEFAULT 0,
    status        TEXT        NOT NULL CHECK (status IN ('archived', 'processed', 'partial', 'failed')),
    error         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_batches_created ON ingestion_batches (created_at DESC);

CREATE TABLE IF NOT EXISTS security_events (
    event_id             TEXT PRIMARY KEY,
    event_ts             TIMESTAMPTZ NOT NULL,
    source_ip            TEXT        NOT NULL,
    user_id              TEXT,
    country              TEXT,
    city                 TEXT,
    event_type           TEXT,
    endpoint             TEXT,
    method               TEXT,
    status_code          INTEGER,
    response_bytes       BIGINT,
    user_agent           TEXT,
    extra                JSONB       NOT NULL DEFAULT '{}'::jsonb,
    window_start         TIMESTAMPTZ NOT NULL,
    window_event_count   INTEGER,
    ml_prediction        SMALLINT    NOT NULL,
    anomaly_probability  DOUBLE PRECISION NOT NULL,
    detector             TEXT        NOT NULL,
    model_version        TEXT        NOT NULL,
    detection_source     TEXT        NOT NULL CHECK (detection_source IN ('ml', 'ml+rules', 'rules', 'none')),
    is_alert             BOOLEAN     NOT NULL,
    priority             TEXT        NOT NULL,
    threat_types         TEXT,
    reason               TEXT,
    batch_id             TEXT REFERENCES ingestion_batches (batch_id),
    processed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_events_ts           ON security_events (event_ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_ip_ts        ON security_events (source_ip, event_ts DESC);
CREATE INDEX IF NOT EXISTS ix_events_processed_at ON security_events (processed_at DESC);
-- Successful-login history used by the country-baseline features.
CREATE INDEX IF NOT EXISTS ix_events_successful_logins
    ON security_events (user_id, event_ts)
    WHERE event_type = 'login' AND status_code BETWEEN 200 AND 399;

CREATE TABLE IF NOT EXISTS alerts (
    alert_id             BIGSERIAL PRIMARY KEY,
    source_ip            TEXT        NOT NULL,
    window_start         TIMESTAMPTZ NOT NULL,
    user_id              TEXT,
    first_detected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    detected_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    ml_prediction        SMALLINT    NOT NULL,
    anomaly_probability  DOUBLE PRECISION NOT NULL,
    peak_probability     DOUBLE PRECISION NOT NULL,
    severity             TEXT        NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    threat_types         TEXT,
    evidence             TEXT,
    detector             TEXT        NOT NULL,
    model_version        TEXT        NOT NULL,
    detection_source     TEXT        NOT NULL CHECK (detection_source IN ('ml', 'ml+rules', 'rules')),
    features             JSONB,
    last_event_id        TEXT REFERENCES security_events (event_id),
    evaluation_count     INTEGER     NOT NULL DEFAULT 1,
    status               TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    -- One alert per source IP and five-minute window; re-evaluations update it.
    CONSTRAINT uq_alert_ip_window UNIQUE (source_ip, window_start)
);
CREATE INDEX IF NOT EXISTS ix_alerts_detected_at ON alerts (detected_at DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_severity    ON alerts (severity, detected_at DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_source      ON alerts (detection_source);
