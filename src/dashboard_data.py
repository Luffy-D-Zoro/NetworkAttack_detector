"""Read-only dashboard view model backed by the alert repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.alerts.models import StructuredAlert
from src.alerts.storage import SQLiteAlertRepository


@dataclass(frozen=True, slots=True)
class DashboardSnapshot:
    generated_at: datetime
    recent_since: datetime
    total_alerts: int
    recent_alert_count: int
    latest_alert_timestamp: datetime | None
    family_counts: dict[str, int]
    severity_counts: dict[str, int]
    alerts: tuple[StructuredAlert, ...]
    chart_alerts: tuple[StructuredAlert, ...]


def load_dashboard_snapshot(
    database: str | Path, *, recent_window: timedelta = timedelta(hours=1),
    limit: int = 500, threat_family: str | None = None,
    severity: str | None = None, now: datetime | None = None,
) -> DashboardSnapshot:
    if recent_window <= timedelta(0):
        raise ValueError("dashboard recent window must be positive")
    if limit <= 0:
        raise ValueError("dashboard alert limit must be positive")
    now = now or datetime.now(UTC)
    since = now - recent_window
    repository = SQLiteAlertRepository(database, read_only=True)
    try:
        return DashboardSnapshot(
            generated_at=now,
            recent_since=since,
            total_alerts=repository.count(),
            recent_alert_count=repository.count(since=since),
            latest_alert_timestamp=repository.latest_timestamp(),
            family_counts=repository.counts_by("threat_family"),
            severity_counts=repository.counts_by("severity"),
            alerts=repository.alerts_since(
                since, limit=limit, threat_family=threat_family, severity=severity,
            ),
            chart_alerts=repository.alerts_since(since, limit=max(limit, 5_000)),
        )
    finally:
        repository.close()
