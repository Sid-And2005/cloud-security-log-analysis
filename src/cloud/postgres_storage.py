"""Azure Database for PostgreSQL backend."""

import logging
import time
from importlib import resources

import pandas as pd

from .. import config
from ..storage import (
    EVENT_FIELDS,
    RESULT_FIELDS,
    StorageBackend,
    StorageError,
    summarise_alerts,
)

log = logging.getLogger(__name__)

MIGRATIONS_PACKAGE = "src.cloud.migrations"
# Arbitrary constant so only one process applies migrations at a time.
MIGRATION_LOCK_ID = 727_001


def _conninfo():
    import psycopg.conninfo

    params = {
        "connect_timeout": config.PG_CONNECT_TIMEOUT,
        "application_name": f"seclog-{config.SERVICE_NAME}",
        # Every session works in UTC so timestamps are consistent.
        "options": "-c TimeZone=UTC",
    }
    if config.DATABASE_URL:
        return psycopg.conninfo.make_conninfo(config.DATABASE_URL, **params)
    return psycopg.conninfo.make_conninfo(
        host=config.PGHOST,
        port=config.PGPORT,
        dbname=config.PGDATABASE,
        user=config.PGUSER,
        sslmode=config.PGSSLMODE,
        **params,
    )


def _connection_kwargs():
    """Evaluated for every new connection so Entra tokens are always fresh."""
    if config.PG_AUTH == "entra":
        from .credentials import postgres_access_token

        return {"password": postgres_access_token()}
    if config.PGPASSWORD and not config.DATABASE_URL:
        return {"password": config.PGPASSWORD}
    return {}


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class PostgresStorage(StorageBackend):
    name = "postgres"

    def __init__(self, pool=None):
        self._pool = pool

    # -- connection management ---------------------------------------------
    @property
    def pool(self):
        if self._pool is None:
            from psycopg_pool import ConnectionPool

            self._pool = ConnectionPool(
                _conninfo(),
                kwargs=_connection_kwargs,
                min_size=config.PG_POOL_MIN,
                max_size=config.PG_POOL_MAX,
                # Recycle before Entra tokens (about 1 hour) would matter.
                max_lifetime=1800,
                check=ConnectionPool.check_connection,
                open=False,
                name="seclog",
            )
            self._pool.open(wait=False)
        return self._pool

    def _run(self, operation, fn):
        """Run fn(conn) in one transaction, translating driver errors."""
        import psycopg
        from psycopg_pool import PoolTimeout

        try:
            with self.pool.connection(timeout=config.PG_CONNECT_TIMEOUT + 5) as conn:
                with conn.transaction():
                    return fn(conn)
        except PoolTimeout as exc:
            log.error(
                "PostgreSQL unavailable during %s", operation,
                extra={"operation": f"db_{operation}", "error_type": "PoolTimeout"},
            )
            raise StorageError(
                f"PostgreSQL is unavailable ({operation}: no connection within "
                f"{config.PG_CONNECT_TIMEOUT + 5}s)"
            ) from exc
        except psycopg.Error as exc:
            log.error(
                "PostgreSQL %s failed: %s", operation, exc.__class__.__name__,
                extra={"operation": f"db_{operation}", "error_type": exc.__class__.__name__},
            )
            raise StorageError(f"PostgreSQL {operation} failed: {exc}") from exc

    def close(self):
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    # -- schema ----------------------------------------------------------------
    def ensure_database(self):
        """Create PGDATABASE if it does not exist (Azure: run once by init-db).

        The app's Entra identity is a server administrator (CREATEDB), so the
        database it creates is owned by it and migrations can create tables.
        Skipped for DATABASE_URL (local Docker), where the database exists.
        """
        import psycopg
        from psycopg import sql

        if config.DATABASE_URL:
            return False
        admin_info = psycopg.conninfo.make_conninfo(_conninfo(), dbname="postgres")
        with psycopg.connect(admin_info, autocommit=True, **_connection_kwargs()) as conn:
            exists = conn.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s", (config.PGDATABASE,)
            ).fetchone()
            if exists:
                return False
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(config.PGDATABASE)))
            log.info("Created database %s", config.PGDATABASE, extra={"operation": "db_create"})
            return True

    def init_schema(self):
        files = sorted(
            f for f in resources.files(MIGRATIONS_PACKAGE).iterdir()
            if f.name.endswith(".sql")
        )

        def migrate(conn):
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK_ID,))
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                " version TEXT PRIMARY KEY,"
                " applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
            applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            newly = []
            for f in files:
                version = f.name.removesuffix(".sql")
                if version in applied:
                    continue
                conn.execute(f.read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
                newly.append(version)
            return newly

        newly = self._run("migrate", migrate)
        log.info(
            "Database schema up to date (applied: %s)", ", ".join(newly) or "none",
            extra={"operation": "db_migrate"},
        )
        return newly

    def health(self):
        started = time.monotonic()
        try:
            version = self._run(
                "health",
                lambda c: c.execute(
                    "SELECT max(version) FROM schema_migrations"
                ).fetchone()[0],
            )
            return {
                "ok": version is not None,
                "backend": self.name,
                "schema_version": version,
                "latency_ms": round((time.monotonic() - started) * 1000, 1),
                "detail": "connected" if version else "schema not initialised (run manage.py init-db)",
            }
        except Exception as exc:  # health checks report, never raise
            return {"ok": False, "backend": self.name, "detail": str(exc).splitlines()[0]}

    # -- ingestion -------------------------------------------------------------
    def existing_event_ids(self, event_ids):
        ids = [str(e) for e in event_ids]
        if not ids:
            return set()
        rows = self._run(
            "lookup_events",
            lambda c: c.execute(
                "SELECT event_id FROM security_events WHERE event_id = ANY(%s)", (ids,)
            ).fetchall(),
        )
        return {r[0] for r in rows}

    def record_batch(self, batch_id, blob_uri, event_count, status, error=None):
        self._run(
            "record_batch",
            lambda c: c.execute(
                """
                INSERT INTO ingestion_batches (batch_id, blob_uri, event_count, status, error)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (batch_id) DO UPDATE SET
                    blob_uri = COALESCE(EXCLUDED.blob_uri, ingestion_batches.blob_uri),
                    event_count = EXCLUDED.event_count,
                    status = EXCLUDED.status,
                    error = EXCLUDED.error,
                    updated_at = now()
                """,
                (batch_id, blob_uri, event_count, status, error),
            ),
        )

    def save_result(self, record, batch_id=None):
        from psycopg.types.json import Jsonb

        batch_id = batch_id or record.get("batch_id")
        extra = {
            k: v for k, v in record.items()
            if k not in EVENT_FIELDS and k not in RESULT_FIELDS
        }

        def write(conn):
            inserted = conn.execute(
                """
                INSERT INTO security_events (
                    event_id, event_ts, source_ip, user_id, country, city, event_type,
                    endpoint, method, status_code, response_bytes, user_agent, extra,
                    window_start, window_event_count, ml_prediction, anomaly_probability,
                    detector, model_version, detection_source, is_alert, priority,
                    threat_types, reason, batch_id, processed_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    str(record["event_id"]), record["timestamp"], str(record["source_ip"]),
                    record.get("user_id"), record.get("country"), record.get("city"),
                    str(record.get("event_type", "")).lower() or None,
                    record.get("endpoint"), record.get("method"),
                    _int_or_none(record.get("status_code")),
                    _int_or_none(record.get("response_bytes")),
                    record.get("user_agent"), Jsonb(extra),
                    record["window"], record.get("window_event_count"),
                    int(record["prediction"]), float(record["anomaly_probability"]),
                    record["detector"], record.get("model_version", "unknown"),
                    record["detection_source"], bool(record["alert"]), record["priority"],
                    record.get("threat_types"), record.get("reason"), batch_id,
                    record["processed_at"],
                ),
            ).fetchone()

            # A duplicate (retried) event must not re-count its alert.
            if inserted is None or not record.get("alert"):
                return inserted is not None

            conn.execute(
                """
                INSERT INTO alerts (
                    source_ip, window_start, user_id, first_detected_at, detected_at,
                    ml_prediction, anomaly_probability, peak_probability, severity,
                    threat_types, evidence, detector, model_version, detection_source,
                    features, last_event_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_ip, window_start) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    detected_at = EXCLUDED.detected_at,
                    ml_prediction = EXCLUDED.ml_prediction,
                    anomaly_probability = EXCLUDED.anomaly_probability,
                    peak_probability = GREATEST(alerts.peak_probability, EXCLUDED.peak_probability),
                    severity = EXCLUDED.severity,
                    threat_types = EXCLUDED.threat_types,
                    evidence = EXCLUDED.evidence,
                    detector = EXCLUDED.detector,
                    model_version = EXCLUDED.model_version,
                    detection_source = EXCLUDED.detection_source,
                    features = EXCLUDED.features,
                    last_event_id = EXCLUDED.last_event_id,
                    evaluation_count = alerts.evaluation_count + 1
                """,
                (
                    str(record["source_ip"]), record["window"], record.get("user_id"),
                    record["processed_at"], record["processed_at"],
                    int(record["prediction"]), float(record["anomaly_probability"]),
                    float(record["anomaly_probability"]), record["priority"],
                    record.get("threat_types"), record.get("reason"), record["detector"],
                    record.get("model_version", "unknown"), record["detection_source"],
                    Jsonb(record.get("features") or {}), str(record["event_id"]),
                ),
            )
            return True

        return self._run("save_result", write)

    # -- state for the consumer ------------------------------------------------
    def login_history(self, user_ids):
        users = [str(u) for u in user_ids]
        history = {u: [] for u in users}
        if not users:
            return history
        rows = self._run(
            "login_history",
            lambda c: c.execute(
                """
                SELECT event_id, event_ts, source_ip, user_id, country, event_type,
                       endpoint, status_code
                FROM security_events
                WHERE event_type = 'login' AND status_code BETWEEN 200 AND 399
                  AND user_id = ANY(%s)
                ORDER BY user_id, event_ts, event_id
                """,
                (users,),
            ).fetchall(),
        )
        for event_id, ts, ip, user, country, etype, endpoint, status in rows:
            history[user].append({
                "event_id": event_id, "timestamp": _iso(ts), "source_ip": ip,
                "user_id": user, "country": country, "event_type": etype,
                "endpoint": endpoint, "status_code": status,
            })
        return history

    def recent_events(self, since):
        columns = ", ".join(
            "event_ts AS timestamp" if f == "timestamp" else f for f in EVENT_FIELDS
        )

        def query(conn):
            cur = conn.execute(
                f"SELECT {columns} FROM security_events WHERE event_ts >= %s "
                "ORDER BY event_ts, event_id",
                (since,),
            )
            names = [d.name for d in cur.description]
            return [dict(zip(names, row)) for row in cur.fetchall()]

        events = self._run("recent_events", query)
        for event in events:
            event["timestamp"] = _iso(event["timestamp"])
        return events

    # -- dashboard ---------------------------------------------------------------
    def _frame(self, operation, sql, params=()):
        def query(conn):
            cur = conn.execute(sql, params)
            names = [d.name for d in cur.description]
            return pd.DataFrame(cur.fetchall(), columns=names)

        return self._run(operation, query)

    def load_alerts(self, limit=None):
        frame = self._frame(
            "load_alerts",
            """
            SELECT alert_id, detected_at AS processed_at, first_detected_at, source_ip,
                   user_id, window_start AS "window", threat_types, severity AS priority,
                   anomaly_probability, peak_probability, ml_prediction AS prediction,
                   evidence AS reason, detector, detection_source, model_version,
                   evaluation_count, status
            FROM alerts ORDER BY detected_at DESC LIMIT %s
            """,
            (limit or config.DASHBOARD_ALERT_LIMIT,),
        )
        if not frame.empty:
            frame["features"] = None
        return frame

    def load_events(self, limit=None):
        return self._frame(
            "load_events",
            """
            SELECT processed_at, event_ts AS timestamp, event_id, source_ip, user_id,
                   event_type, endpoint, status_code, priority, anomaly_probability,
                   ml_prediction AS prediction, detection_source, reason, batch_id
            FROM security_events ORDER BY processed_at DESC LIMIT %s
            """,
            (limit or config.DASHBOARD_EVENT_LIMIT,),
        )

    def stats(self):
        def query(conn):
            events_total = conn.execute("SELECT count(*) FROM security_events").fetchone()[0]
            rows = conn.execute(
                "SELECT severity, detection_source, count(*) FROM alerts GROUP BY 1, 2"
            ).fetchall()
            return events_total, rows

        events_total, rows = self._run("stats", query)
        stats = summarise_alerts(pd.DataFrame(), events_total)
        for severity, source, count in rows:
            stats["alerts_total"] += count
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + count
            stats["by_source"][source] = stats["by_source"].get(source, 0) + count
        return stats

    def last_batch(self):
        def query(conn):
            cur = conn.execute(
                "SELECT batch_id, blob_uri, event_count, status, error, updated_at "
                "FROM ingestion_batches ORDER BY updated_at DESC LIMIT 1"
            )
            row = cur.fetchone()
            return dict(zip([d.name for d in cur.description], row)) if row else None

        return self._run("last_batch", query)

