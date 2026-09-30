"""Read-only Streamlit dashboard for retained structured alerts."""

from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from src.alerts.storage import AlertStorageError  # noqa: E402
from src.dashboard_data import DashboardSnapshot, load_dashboard_snapshot  # noqa: E402

DEFAULT_DATABASE = ROOT / "var" / "alerts" / "alerts.db"
SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _endpoint(alert) -> str:
    source = alert.src_ip or "—"
    if alert.src_port is not None:
        source += f":{alert.src_port}"
    destination = alert.dst_ip or "—"
    if alert.dst_port is not None:
        destination += f":{alert.dst_port}"
    return f"{source} → {destination}"


def _table(snapshot: DashboardSnapshot) -> pd.DataFrame:
    return pd.DataFrame([
        {
            "timestamp": alert.timestamp,
            "threat family": alert.threat_family,
            "threat class": alert.threat_class,
            "subject": alert.subject,
            "source → destination": _endpoint(alert),
            "confidence": round(alert.confidence, 3),
            "severity": alert.severity,
            "detection sources": ", ".join(alert.detection_sources),
        }
        for alert in snapshot.alerts
    ])


def _overview(snapshot: DashboardSnapshot, hours: int) -> None:
    columns = st.columns(4)
    columns[0].metric("Total retained alerts", snapshot.total_alerts)
    columns[1].metric(f"Alerts in last {hours}h", snapshot.recent_alert_count)
    columns[2].metric("Threat families", len(snapshot.family_counts))
    latest = snapshot.latest_alert_timestamp
    columns[3].metric("Latest alert", latest.strftime("%Y-%m-%d %H:%M:%S UTC") if latest else "None")

    family_column, severity_column = st.columns(2)
    family_column.subheader("Alerts by threat family")
    family_column.bar_chart(
        pd.DataFrame.from_dict(snapshot.family_counts, orient="index", columns=["alerts"]),
        horizontal=True,
    )
    severity_column.subheader("Alerts by severity")
    severity_values = {name: snapshot.severity_counts.get(name, 0) for name in SEVERITY_ORDER}
    severity_column.bar_chart(
        pd.DataFrame.from_dict(severity_values, orient="index", columns=["alerts"]),
        horizontal=True,
    )


def _timeline(snapshot: DashboardSnapshot) -> None:
    st.subheader("Alerts over time")
    if not snapshot.chart_alerts:
        st.info("No alerts exist in the selected recent window.")
        return
    frame = pd.DataFrame({"timestamp": [item.timestamp for item in snapshot.chart_alerts]})
    frame["bucket"] = pd.to_datetime(frame["timestamp"], utc=True).dt.floor("min")
    timeline = frame.groupby("bucket").size().rename("alerts")
    st.line_chart(timeline)


def _detail(snapshot: DashboardSnapshot) -> None:
    st.subheader("Alert detail")
    if not snapshot.alerts:
        st.info("No alert matches the current filters.")
        return
    labels = {
        item.alert_id: f"{item.timestamp:%Y-%m-%d %H:%M:%S} · {item.severity.upper()} · {item.threat_class} · {item.subject}"
        for item in snapshot.alerts
    }
    selected_id = st.selectbox("Select an alert", tuple(labels), format_func=labels.get)
    selected = next(item for item in snapshot.alerts if item.alert_id == selected_id)
    left, right = st.columns(2)
    left.metric("Confidence", f"{selected.confidence:.3f}")
    right.metric("Severity", selected.severity.upper())
    st.json({
        "alert_id": selected.alert_id,
        "timestamp": selected.to_dict()["timestamp"],
        "threat_family": selected.threat_family,
        "threat_class": selected.threat_class,
        "subject": selected.subject,
        "endpoints": {
            "src_ip": selected.src_ip, "src_port": selected.src_port,
            "dst_ip": selected.dst_ip, "dst_port": selected.dst_port,
            "protocol": selected.protocol,
        },
        "rule_score": selected.rule_score,
        "rule_disposition": selected.rule_disposition,
        "ml_score": selected.ml_score,
        "ml_prediction": selected.ml_prediction,
        "model_name": selected.model_name,
        "model_version": selected.model_version,
        "detection_sources": list(selected.detection_sources),
        "evidence": list(selected.evidence),
        "supporting_features": list(selected.supporting_features),
    }, expanded=True)


def _render(database: Path, hours: int, limit: int, family: str, severity: str) -> None:
    try:
        snapshot = load_dashboard_snapshot(
            database, recent_window=timedelta(hours=hours), limit=limit,
            threat_family=None if family == "All" else family,
            severity=None if severity == "All" else severity,
        )
    except AlertStorageError as exc:
        st.warning(f"Alert database is not available yet: {exc}")
        st.caption("Start the backend or run the controlled demo to create it.")
        return

    _overview(snapshot, hours)
    _timeline(snapshot)
    st.subheader("Live / recent alerts")
    table = _table(snapshot)
    if table.empty:
        st.info("No alert matches the current filters.")
    else:
        st.dataframe(table, hide_index=True, use_container_width=True)
    _detail(snapshot)
    st.caption(f"Read-only view · refreshed {snapshot.generated_at:%Y-%m-%d %H:%M:%S UTC}")


def main() -> None:
    st.set_page_config(page_title="SIH Threat Monitor", page_icon="🛡️", layout="wide")
    st.title("Passive Threat Monitoring")
    st.caption("Unidirectional Zeek metadata · bounded streaming state · rules + ML · structured alerts")

    default_database = Path(os.getenv("ALERT_DB_PATH", str(DEFAULT_DATABASE)))
    with st.sidebar:
        st.header("View controls")
        database = Path(st.text_input("Alert database", str(default_database)))
        hours = st.select_slider("Recent window (hours)", options=(1, 6, 12, 24, 72, 168), value=24)
        limit = st.slider("Maximum table rows", 25, 1_000, 250, 25)
        family = st.selectbox("Threat family", ("All", "ddos", "scan", "exfiltration", "beaconing", "dns", "encrypted_traffic"))
        severity = st.selectbox("Severity", ("All", *SEVERITY_ORDER))
        refresh_seconds = st.select_slider("Refresh interval (seconds)", options=(2, 5, 10, 30, 60), value=5)
        st.caption("The dashboard opens SQLite read-only and never changes detector state.")

    @st.fragment(run_every=timedelta(seconds=refresh_seconds))
    def live_panel() -> None:
        _render(database, hours, limit, family, severity)

    live_panel()


if __name__ == "__main__":
    main()
