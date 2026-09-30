from __future__ import annotations

import ipaddress
import unittest
from datetime import UTC, datetime, timedelta

from src.coordinator import StreamingCoordinator
from src.flow.flow_manager import FlowManager
from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate, FlowKey
from src.ingestion.zeek_websocket import FlowSnapshot
from src.states.beacon import BeaconStateConfig, BeaconStateManager
from src.states.exfil import ExfilStateConfig, ExfilStateManager

BASE = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def ip(value: str):
    return ipaddress.ip_address(value)


def flow_key(
    *,
    src: str = "192.0.2.1",
    dst: str = "198.51.100.10",
    src_port: int = 50000,
    dst_port: int = 443,
    protocol: int = 6,
) -> FlowKey:
    return FlowKey(ip(src), src_port, ip(dst), dst_port, protocol)


def update(
    seconds: float,
    *,
    key: FlowKey | None = None,
    packets: int = 1,
    ip_bytes: int = 80,
    uid: str = "C1",
) -> DirectionalFlowUpdate:
    return DirectionalFlowUpdate(
        key=key or flow_key(),
        first_seen=BASE,
        last_seen=BASE + timedelta(seconds=seconds),
        packet_delta=packets,
        byte_delta=ip_bytes,
        zeek_uid=uid,
    )


def lifecycle(
    kind: str,
    *,
    contact_seconds: float,
    event_seconds: float | None = None,
    end_seconds: float | None = None,
    key: FlowKey | None = None,
    packets: int = 1,
    ip_bytes: int = 80,
    uid: str = "C1",
) -> DirectionalConnectionEvent:
    end_seconds = contact_seconds if end_seconds is None else end_seconds
    event_seconds = end_seconds if event_seconds is None else event_seconds
    return DirectionalConnectionEvent(
        schema_version=1,
        kind=kind,
        event_time=BASE + timedelta(seconds=event_seconds),
        zeek_uid=uid,
        key=key or flow_key(),
        direction_role="originator",
        first_seen=BASE + timedelta(seconds=contact_seconds),
        last_seen=BASE + timedelta(seconds=end_seconds),
        total_packets=packets,
        total_ip_bytes=ip_bytes,
    )


def snapshot(
    *,
    kind: str,
    seconds: float,
    packets: int,
    ip_bytes: int,
) -> FlowSnapshot:
    event_time = BASE + timedelta(seconds=seconds)
    return FlowSnapshot(
        schema_version=1,
        kind=kind,
        observed_at=event_time,
        uid="C-snapshot",
        orig_h=ip("192.0.2.1"),
        orig_p=50000,
        resp_h=ip("198.51.100.10"),
        resp_p=443,
        ip_proto=6,
        first_seen=BASE,
        last_seen=event_time,
        orig_pkts=packets,
        orig_ip_bytes=ip_bytes,
        orig_payload_bytes=0,
        resp_pkts=0,
        resp_ip_bytes=0,
        resp_payload_bytes=0,
        orig_state=1,
        resp_state=0,
        history="S",
    )


class ExfilStateTests(unittest.TestCase):
    def manager(self, *, max_entries: int = 10) -> ExfilStateManager:
        return ExfilStateManager(
            ExfilStateConfig(
                window=timedelta(seconds=30),
                bucket_width=timedelta(seconds=10),
                inactivity_timeout=timedelta(seconds=40),
                cleanup_interval=timedelta(seconds=5),
                max_state_entries=max_entries,
                protocol_capacity=4,
            )
        )

    def test_directional_pair_and_protocol_aggregation(self) -> None:
        manager = self.manager()
        manager.update_flow(update(0, packets=3, ip_bytes=300))
        manager.update_flow(
            update(
                5,
                key=flow_key(src_port=51000, dst_port=8443, protocol=17),
                packets=2,
                ip_bytes=500,
            )
        )
        state = manager.get((ip("192.0.2.1"), ip("198.51.100.10")))
        bucket = next(iter(state.buckets))
        self.assertEqual((bucket.packets, bucket.ip_bytes), (5, 800))
        self.assertEqual(bucket.protocol_packets.values[6], 3)
        self.assertEqual(bucket.protocol_packets.values[17], 2)
        self.assertEqual(bucket.protocol_bytes.values[17], 500)
        self.assertEqual(state.first_activity, BASE)
        self.assertEqual(state.last_activity, BASE + timedelta(seconds=5))

    def test_reverse_direction_is_a_separate_state(self) -> None:
        manager = self.manager()
        forward = (ip("192.0.2.1"), ip("198.51.100.10"))
        reverse = (forward[1], forward[0])
        manager.update_flow(update(0, packets=4, ip_bytes=400))
        manager.update_flow(
            update(
                1,
                key=flow_key(
                    src="198.51.100.10",
                    dst="192.0.2.1",
                    src_port=443,
                    dst_port=50000,
                ),
                packets=2,
                ip_bytes=180,
            )
        )
        self.assertEqual(len(manager), 2)
        self.assertIs(manager.get_reverse(forward), manager.get(reverse))
        self.assertEqual(next(iter(manager.get(forward).buckets)).packets, 4)
        self.assertEqual(next(iter(manager.get(reverse).buckets)).packets, 2)

    def test_bucket_rollover_sustained_transfer_and_expiration(self) -> None:
        manager = self.manager()
        for seconds in (0, 9, 10, 20, 29):
            manager.update_flow(update(seconds, packets=2, ip_bytes=200))
        state_key = (ip("192.0.2.1"), ip("198.51.100.10"))
        state = manager.get(state_key)
        self.assertEqual(len(state.buckets), 3)
        self.assertEqual(sum(bucket.packets for bucket in state.buckets), 10)

        manager.expire(BASE + timedelta(seconds=41))
        self.assertEqual(len(manager.get(state_key).buckets), 2)
        self.assertEqual(manager.expire(BASE + timedelta(seconds=80)), 1)
        self.assertIsNone(manager.get(state_key))

    def test_late_events_and_state_cap_eviction(self) -> None:
        manager = self.manager(max_entries=2)
        manager.update_flow(update(35))
        self.assertTrue(manager.update_flow(update(10)))
        self.assertFalse(manager.update_flow(update(0)))

        second = flow_key(src="192.0.2.2", dst="198.51.100.20")
        third = flow_key(src="192.0.2.3", dst="198.51.100.30")
        manager.update_flow(update(36, key=second))
        manager.update_flow(update(37, key=third))
        self.assertEqual(len(manager), 2)
        self.assertIsNone(manager.get((ip("192.0.2.1"), ip("198.51.100.10"))))
        self.assertEqual(manager.capacity_evictions, 1)


class BeaconStateTests(unittest.TestCase):
    def manager(
        self,
        *,
        max_entries: int = 10,
        sample_cap: int = 10,
    ) -> BeaconStateManager:
        return BeaconStateManager(
            BeaconStateConfig(
                horizon=timedelta(seconds=60),
                episode_gap=timedelta(seconds=5),
                inactivity_timeout=timedelta(seconds=70),
                cleanup_interval=timedelta(seconds=5),
                max_state_entries=max_entries,
                episode_max_samples=sample_cap,
                connection_start_max_samples=sample_cap,
                completed_connection_max_samples=sample_cap,
            )
        )

    @staticmethod
    def state_key() -> tuple:
        return (ip("192.0.2.1"), ip("198.51.100.10"), 443, 6)

    def test_source_port_exclusion_and_connection_start_intervals(self) -> None:
        manager = self.manager()
        manager.update_connection(
            lifecycle("start", contact_seconds=0, key=flow_key(src_port=50000), uid="C1")
        )
        manager.update_connection(
            lifecycle("start", contact_seconds=12, key=flow_key(src_port=51000), uid="C2")
        )
        state = manager.get(self.state_key())
        starts = tuple(state.connection_starts)
        self.assertEqual(len(manager), 1)
        self.assertEqual(starts, (BASE, BASE + timedelta(seconds=12)))
        self.assertEqual(starts[1] - starts[0], timedelta(seconds=12))

    def test_episode_creation_extension_and_closure(self) -> None:
        manager = self.manager()
        manager.update_flow(update(0, packets=1, ip_bytes=80))
        manager.update_flow(update(3, packets=2, ip_bytes=200))
        state = manager.get(self.state_key())
        self.assertEqual(state.current_episode.start_time, BASE)
        self.assertEqual(state.current_episode.last_time, BASE + timedelta(seconds=3))
        self.assertEqual(state.current_episode.packets, 3)

        manager.update_flow(update(10, packets=4, ip_bytes=500))
        self.assertEqual(len(state.episodes), 1)
        closed = next(iter(state.episodes))
        self.assertEqual((closed.packets, closed.ip_bytes), (3, 280))
        self.assertEqual(state.current_episode.start_time, BASE + timedelta(seconds=10))

    def test_long_lived_connection_periodic_bursts(self) -> None:
        manager = self.manager()
        for seconds in (0, 10, 20):
            manager.update_flow(update(seconds, uid="one-long-connection"))
        state = manager.get(self.state_key())
        self.assertEqual(len(state.episodes), 2)
        self.assertEqual(state.current_episode.start_time, BASE + timedelta(seconds=20))
        manager.expire(BASE + timedelta(seconds=30))
        self.assertEqual(len(state.episodes), 3)
        self.assertIsNone(state.current_episode)

    def test_completed_connection_size_and_duration(self) -> None:
        manager = self.manager()
        manager.update_connection(
            lifecycle(
                "final",
                contact_seconds=2,
                end_seconds=14,
                event_seconds=15,
                packets=9,
                ip_bytes=1_200,
            )
        )
        sample = next(iter(manager.get(self.state_key()).completed_connections))
        self.assertEqual(sample.end_time, BASE + timedelta(seconds=14))
        self.assertEqual(sample.duration, timedelta(seconds=12))
        self.assertEqual((sample.packets, sample.ip_bytes), (9, 1_200))

    def test_coordinator_suppresses_duplicate_lifecycle_events(self) -> None:
        beacon = self.manager()
        coordinator = StreamingCoordinator(
            flow_manager=FlowManager(
                inactivity_timeout=timedelta(seconds=120),
                cleanup_interval=timedelta(seconds=5),
            ),
            beacon_manager=beacon,
            correlation_timeout=timedelta(seconds=300),
        )
        opened = snapshot(kind="open", seconds=0, packets=1, ip_bytes=80)
        final = snapshot(kind="final", seconds=12, packets=3, ip_bytes=260)
        coordinator.process(opened)
        coordinator.process(opened)
        coordinator.process(final)
        coordinator.process(final)

        state = beacon.get(self.state_key())
        self.assertEqual(len(state.connection_starts), 1)
        self.assertEqual(len(state.completed_connections), 1)
        self.assertEqual(next(iter(state.completed_connections)).packets, 3)

    def test_deques_are_bounded_by_count_and_time(self) -> None:
        manager = self.manager(sample_cap=2)
        for seconds in (0, 10, 20):
            manager.update_connection(
                lifecycle("start", contact_seconds=seconds, uid=f"S{seconds}")
            )
            manager.update_connection(
                lifecycle(
                    "final",
                    contact_seconds=seconds,
                    end_seconds=seconds,
                    uid=f"F{seconds}",
                )
            )
            manager.update_flow(update(seconds, uid="long"))
        state = manager.get(self.state_key())
        self.assertEqual(len(state.connection_starts), 2)
        self.assertEqual(len(state.completed_connections), 2)
        self.assertEqual(len(state.episodes), 2)

        manager.update_connection(
            lifecycle("start", contact_seconds=90, uid="late-new")
        )
        self.assertEqual(tuple(state.connection_starts), (BASE + timedelta(seconds=90),))
        manager.expire(BASE + timedelta(seconds=100))
        self.assertEqual(len(state.completed_connections), 0)
        self.assertEqual(len(state.episodes), 0)

    def test_late_observations_and_unidirectional_operation(self) -> None:
        manager = self.manager()
        manager.update_flow(update(20, packets=2, ip_bytes=200))
        self.assertTrue(manager.update_flow(update(17, packets=3, ip_bytes=300)))
        state = manager.get(self.state_key())
        self.assertEqual(state.current_episode.start_time, BASE + timedelta(seconds=17))
        self.assertEqual((state.current_episode.packets, state.current_episode.ip_bytes), (5, 500))

        manager.update_flow(update(80))
        self.assertFalse(manager.update_flow(update(10)))
        self.assertIsNone(
            manager.get((ip("198.51.100.10"), ip("192.0.2.1"), 50000, 6))
        )

    def test_state_cap_and_whole_state_cleanup(self) -> None:
        manager = self.manager(max_entries=2)
        manager.update_flow(update(0))
        manager.update_flow(
            update(1, key=flow_key(src="192.0.2.2", dst="198.51.100.20"))
        )
        manager.update_flow(
            update(2, key=flow_key(src="192.0.2.3", dst="198.51.100.30"))
        )
        self.assertEqual(manager.capacity_evictions, 1)
        self.assertIsNone(manager.get(self.state_key()))
        self.assertEqual(manager.expire(BASE + timedelta(seconds=140)), 2)
        self.assertEqual(len(manager), 0)


if __name__ == "__main__":
    unittest.main()
