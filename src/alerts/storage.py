"""Small SQLite repository for final alerts only."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from src.alerts.models import StructuredAlert


class AlertStorageError(RuntimeError):
    pass


class AlertRepository(Protocol):
    def insert(self, alert: StructuredAlert) -> None: ...


@dataclass(frozen=True, slots=True)
class AlertRetentionConfig:
    max_alerts: int = 100_000
    max_age: timedelta | None = timedelta(days=30)

    def __post_init__(self) -> None:
        if self.max_alerts <= 0:
            raise ValueError("maximum retained alerts must be positive")
        if self.max_age is not None and self.max_age <= timedelta(0):
            raise ValueError("alert retention age must be positive")


class SQLiteAlertRepository:
    def __init__(
        self, path: str | Path, retention: AlertRetentionConfig | None = None,
        *, read_only: bool = False,
    ) -> None:
        self.path = str(path)
        self.retention = retention or AlertRetentionConfig()
        self.read_only = read_only
        try:
            if self.path != ":memory:" and not read_only:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            if read_only:
                if self.path == ":memory:":
                    raise ValueError("an in-memory alert database cannot be opened read-only")
                uri = Path(self.path).resolve().as_uri() + "?mode=ro"
                self._connection = sqlite3.connect(uri, timeout=2.0, uri=True)
            else:
                self._connection = sqlite3.connect(self.path, timeout=2.0)
            self._connection.row_factory = sqlite3.Row
            if not read_only:
                with self._connect() as connection:
                    self._initialize(connection)
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise AlertStorageError(f"could not initialize alert database: {exc}") from exc

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                threat_family TEXT NOT NULL,
                threat_class TEXT NOT NULL,
                subject TEXT NOT NULL,
                src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                protocol INTEGER, confidence REAL NOT NULL, severity TEXT NOT NULL,
                rule_score REAL, ml_score REAL, rule_disposition TEXT,
                ml_prediction TEXT, evidence_json TEXT NOT NULL,
                supporting_features_json TEXT NOT NULL,
                model_name TEXT, model_version TEXT,
                detection_sources_json TEXT NOT NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS alerts_timestamp_idx ON alerts(timestamp DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS alerts_family_idx ON alerts(threat_family, timestamp DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS alerts_severity_idx ON alerts(severity, timestamp DESC)")

    def insert(self, alert: StructuredAlert) -> None:
        if self.read_only:
            raise AlertStorageError("cannot insert through a read-only alert repository")
        value = alert.to_dict()
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT OR IGNORE INTO alerts VALUES (
                        :alert_id, :timestamp, :threat_family, :threat_class, :subject,
                        :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                        :confidence, :severity, :rule_score, :ml_score,
                        :rule_disposition, :ml_prediction, :evidence_json,
                        :supporting_features_json, :model_name, :model_version,
                        :detection_sources_json
                    )""",
                    {**value,
                     "evidence_json": json.dumps(value["evidence"]),
                     "supporting_features_json": json.dumps(value["supporting_features"]),
                     "detection_sources_json": json.dumps(value["detection_sources"])},
                )
                self._prune(connection, alert.timestamp)
        except sqlite3.Error as exc:
            raise AlertStorageError(f"could not persist alert: {exc}") from exc

    def recent(
        self, limit: int = 100, *, threat_family: str | None = None,
        severity: str | None = None,
    ) -> tuple[StructuredAlert, ...]:
        return self._query(limit=limit, threat_family=threat_family, severity=severity)

    def alerts_since(
        self, timestamp: datetime, limit: int = 1_000, *,
        threat_family: str | None = None, severity: str | None = None,
    ) -> tuple[StructuredAlert, ...]:
        return self._query(
            limit=limit, since=_timestamp(timestamp),
            threat_family=threat_family, severity=severity,
        )

    def count(
        self, *, since: datetime | None = None,
        threat_family: str | None = None, severity: str | None = None,
    ) -> int:
        clauses, parameters = self._filters(
            since=_timestamp(since) if since is not None else None,
            threat_family=threat_family, severity=severity,
        )
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            row = self._connect().execute(
                f"SELECT COUNT(*) AS count FROM alerts{where}",  # noqa: S608 -- clauses are fixed strings
                parameters,
            ).fetchone()
        except sqlite3.Error as exc:
            raise AlertStorageError(f"could not count alerts: {exc}") from exc
        return int(row["count"])

    def counts_by(
        self, field: str, *, since: datetime | None = None,
    ) -> dict[str, int]:
        if field not in {"threat_family", "severity"}:
            raise ValueError("alert grouping field must be threat_family or severity")
        clauses, parameters = self._filters(
            since=_timestamp(since) if since is not None else None,
            threat_family=None, severity=None,
        )
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            rows = self._connect().execute(
                f"SELECT {field} AS value, COUNT(*) AS count FROM alerts{where} GROUP BY {field} ORDER BY count DESC",  # noqa: S608 -- field is allow-listed
                parameters,
            ).fetchall()
        except sqlite3.Error as exc:
            raise AlertStorageError(f"could not aggregate alerts: {exc}") from exc
        return {str(row["value"]): int(row["count"]) for row in rows}

    def latest_timestamp(self) -> datetime | None:
        try:
            row = self._connect().execute("SELECT MAX(timestamp) AS timestamp FROM alerts").fetchone()
        except sqlite3.Error as exc:
            raise AlertStorageError(f"could not read latest alert timestamp: {exc}") from exc
        if row["timestamp"] is None:
            return None
        return datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))

    def _query(
        self, *, limit: int, since: str | None = None,
        threat_family: str | None = None, severity: str | None = None,
    ) -> tuple[StructuredAlert, ...]:
        if limit <= 0:
            raise ValueError("alert query limit must be positive")
        clauses, parameters = self._filters(
            since=since, threat_family=threat_family, severity=severity,
        )
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    f"SELECT * FROM alerts{where} ORDER BY timestamp DESC LIMIT ?",  # noqa: S608 -- clauses are fixed strings
                    (*parameters, limit),
                ).fetchall()
        except sqlite3.Error as exc:
            raise AlertStorageError(f"could not read alerts: {exc}") from exc
        return tuple(_row_to_alert(row) for row in rows)

    @staticmethod
    def _filters(
        *, since: str | None, threat_family: str | None, severity: str | None,
    ) -> tuple[list[str], list[object]]:
        clauses: list[str] = []
        parameters: list[object] = []
        if since is not None:
            clauses.append("timestamp >= ?")
            parameters.append(since)
        if threat_family is not None:
            clauses.append("threat_family = ?")
            parameters.append(threat_family)
        if severity is not None:
            clauses.append("severity = ?")
            parameters.append(severity)
        return clauses, parameters

    def _prune(self, connection: sqlite3.Connection, now: datetime) -> None:
        if self.retention.max_age is not None:
            connection.execute(
                "DELETE FROM alerts WHERE timestamp < ?",
                (_timestamp(now - self.retention.max_age),),
            )
        connection.execute(
            """DELETE FROM alerts WHERE alert_id IN (
                SELECT alert_id FROM alerts ORDER BY timestamp DESC LIMIT -1 OFFSET ?
            )""",
            (self.retention.max_alerts,),
        )

    def _connect(self) -> sqlite3.Connection:
        return self._connection

    def close(self) -> None:
        self._connection.close()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _row_to_alert(row: sqlite3.Row) -> StructuredAlert:
    value = dict(row)
    value["evidence"] = json.loads(value.pop("evidence_json"))
    value["supporting_features"] = json.loads(value.pop("supporting_features_json"))
    value["detection_sources"] = json.loads(value.pop("detection_sources_json"))
    return StructuredAlert.from_dict(value)
