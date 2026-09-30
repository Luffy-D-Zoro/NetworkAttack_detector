"""Convert cumulative bidirectional Zeek snapshots into directional deltas."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate, FlowKey
from src.ingestion.zeek_websocket import FlowSnapshot


@dataclass(frozen=True, slots=True)
class _Counters:
    packets: int
    ip_bytes: int


@dataclass(slots=True)
class _SnapshotBaseline:
    directions: dict[FlowKey, _Counters]
    started_directions: set[FlowKey]
    last_observed_at: datetime
    finalized: bool


@dataclass(frozen=True, slots=True)
class AdaptedSnapshot:
    """Directional traffic deltas and lifecycle events from one snapshot."""

    updates: tuple[DirectionalFlowUpdate, ...]
    connection_events: tuple[DirectionalConnectionEvent, ...]


class CumulativeSnapshotAdapter:
    """Track compact UID baselines and emit only newly observed traffic."""

    def __init__(self) -> None:
        self._baselines: dict[str, _SnapshotBaseline] = {}

    @property
    def correlation_count(self) -> int:
        return len(self._baselines)

    def adapt(self, snapshot: FlowSnapshot) -> tuple[DirectionalFlowUpdate, ...]:
        """Preserve the Phase 1 API by returning traffic deltas only."""

        return self.adapt_with_lifecycle(snapshot).updates

    def adapt_with_lifecycle(self, snapshot: FlowSnapshot) -> AdaptedSnapshot:
        """Adapt one snapshot into deltas and UID-deduplicated lifecycle events."""

        previous = self._baselines.get(snapshot.uid)

        # Late delivery must not roll a newer cumulative baseline backwards.
        if previous is not None and snapshot.observed_at < previous.last_observed_at:
            return AdaptedSnapshot((), ())

        # A later open after a finalized UID is treated as UID reuse. A normal
        # duplicate open is still compared with the existing baseline.
        if (
            previous is not None
            and previous.finalized
            and snapshot.kind == "open"
            and snapshot.observed_at > previous.last_observed_at
        ):
            previous = None
        elif previous is not None and previous.finalized and snapshot.kind != "final":
            return AdaptedSnapshot((), ())

        current = self._direction_counters(snapshot)
        roles = self._direction_roles(snapshot)
        prior_directions = previous.directions if previous is not None else {}
        started_directions = (
            set(previous.started_directions) if previous is not None else set()
        )
        updates: list[DirectionalFlowUpdate] = []
        lifecycle: list[DirectionalConnectionEvent] = []

        for key, counters in current.items():
            prior = prior_directions.get(key, _Counters(0, 0))

            # A regression indicates a reset or incompatible replacement. Use
            # the new values as the next baseline but emit nothing now.
            if counters.packets < prior.packets or counters.ip_bytes < prior.ip_bytes:
                continue

            packet_delta = counters.packets - prior.packets
            byte_delta = counters.ip_bytes - prior.ip_bytes
            if packet_delta == 0 and byte_delta == 0:
                pass
            else:
                updates.append(
                    DirectionalFlowUpdate(
                        key=key,
                        first_seen=snapshot.first_seen,
                        last_seen=snapshot.last_seen,
                        packet_delta=packet_delta,
                        byte_delta=byte_delta,
                        zeek_uid=snapshot.uid,
                    )
                )

            if (counters.packets > 0 or counters.ip_bytes > 0) and key not in started_directions:
                lifecycle.append(
                    self._connection_event(snapshot, key, roles[key], counters, "start")
                )
                started_directions.add(key)

        if snapshot.kind == "final" and (previous is None or not previous.finalized):
            for key, counters in current.items():
                if counters.packets > 0 or counters.ip_bytes > 0:
                    lifecycle.append(
                        self._connection_event(
                            snapshot, key, roles[key], counters, "final"
                        )
                    )

        self._baselines[snapshot.uid] = _SnapshotBaseline(
            directions=current,
            started_directions=started_directions,
            last_observed_at=snapshot.observed_at,
            finalized=snapshot.kind == "final",
        )
        return AdaptedSnapshot(tuple(updates), tuple(lifecycle))

    def expire_inactive(self, now: datetime, timeout: timedelta) -> int:
        """Remove stale UID baselines and return the number removed."""

        if timeout <= timedelta(0):
            raise ValueError("correlation timeout must be positive")
        cutoff = now - timeout
        expired = [
            uid
            for uid, baseline in self._baselines.items()
            if baseline.last_observed_at <= cutoff
        ]
        for uid in expired:
            del self._baselines[uid]
        return len(expired)

    @staticmethod
    def _direction_counters(snapshot: FlowSnapshot) -> dict[FlowKey, _Counters]:
        orig_key = FlowKey(
            src_ip=snapshot.orig_h,
            src_port=snapshot.orig_p,
            dst_ip=snapshot.resp_h,
            dst_port=snapshot.resp_p,
            protocol=snapshot.ip_proto,
        )
        resp_key = FlowKey(
            src_ip=snapshot.resp_h,
            src_port=snapshot.resp_p,
            dst_ip=snapshot.orig_h,
            dst_port=snapshot.orig_p,
            protocol=snapshot.ip_proto,
        )

        if orig_key == resp_key:
            return {
                orig_key: _Counters(
                    snapshot.orig_pkts + snapshot.resp_pkts,
                    snapshot.orig_ip_bytes + snapshot.resp_ip_bytes,
                )
            }

        return {
            orig_key: _Counters(snapshot.orig_pkts, snapshot.orig_ip_bytes),
            resp_key: _Counters(snapshot.resp_pkts, snapshot.resp_ip_bytes),
        }

    @staticmethod
    def _direction_roles(snapshot: FlowSnapshot) -> dict[FlowKey, str]:
        orig_key = FlowKey(
            src_ip=snapshot.orig_h,
            src_port=snapshot.orig_p,
            dst_ip=snapshot.resp_h,
            dst_port=snapshot.resp_p,
            protocol=snapshot.ip_proto,
        )
        resp_key = FlowKey(
            src_ip=snapshot.resp_h,
            src_port=snapshot.resp_p,
            dst_ip=snapshot.orig_h,
            dst_port=snapshot.orig_p,
            protocol=snapshot.ip_proto,
        )
        if orig_key == resp_key:
            return {orig_key: "originator"}
        return {orig_key: "originator", resp_key: "responder"}

    @staticmethod
    def _connection_event(
        snapshot: FlowSnapshot,
        key: FlowKey,
        role: str,
        counters: _Counters,
        kind: str,
    ) -> DirectionalConnectionEvent:
        return DirectionalConnectionEvent(
            schema_version=1,
            kind=kind,
            event_time=snapshot.observed_at,
            zeek_uid=snapshot.uid,
            key=key,
            direction_role=role,
            first_seen=snapshot.first_seen,
            last_seen=snapshot.last_seen,
            total_packets=counters.packets,
            total_ip_bytes=counters.ip_bytes,
        )
