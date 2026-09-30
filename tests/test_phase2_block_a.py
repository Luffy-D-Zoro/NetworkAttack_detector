from __future__ import annotations

import ipaddress
import json
import unittest
from datetime import UTC, datetime, timedelta

from src.coordinator import StreamingCoordinator
from src.flow.flow_manager import FlowManager
from src.flow.models import (
    DirectionalConnectionEvent,
    DirectionalFlowUpdate,
    FlowKey,
)
from src.flow.snapshot_adapter import CumulativeSnapshotAdapter
from src.ingestion.zeek_websocket import (
    DEFAULT_TOPIC,
    TCP_SIGNAL_EVENT,
    FlowSnapshot,
    SnapshotValidationError,
    TcpConnectionSignal,
    decode_stream_event,
    iter_snapshots,
)
from src.states.common import BoundedCounterMap, BoundedHashSet, BucketRing
from src.states.ddos import DDoSStateConfig, DDoSStateManager
from src.states.scan import ScanStateConfig, ScanStateManager

BASE = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def ip(value: str):
    return ipaddress.ip_address(value)


def key(
    src: str = "192.0.2.1",
    dst: str = "198.51.100.10",
    src_port: int = 50000,
    dst_port: int = 443,
    protocol: int = 6,
) -> FlowKey:
    return FlowKey(ip(src), src_port, ip(dst), dst_port, protocol)


def flow_update(
    *,
    seconds: float = 0,
    packets: int = 1,
    byte_count: int = 80,
    flow_key: FlowKey | None = None,
    uid: str = "C1",
) -> DirectionalFlowUpdate:
    return DirectionalFlowUpdate(
        key=flow_key or key(),
        first_seen=BASE,
        last_seen=BASE + timedelta(seconds=seconds),
        packet_delta=packets,
        byte_delta=byte_count,
        zeek_uid=uid,
    )


def connection_event(
    *,
    seconds: float = 0,
    flow_key: FlowKey | None = None,
    uid: str = "C1",
    kind: str = "start",
    role: str = "originator",
) -> DirectionalConnectionEvent:
    event_time = BASE + timedelta(seconds=seconds)
    return DirectionalConnectionEvent(
        schema_version=1,
        kind=kind,
        event_time=event_time,
        zeek_uid=uid,
        key=flow_key or key(),
        direction_role=role,
        first_seen=BASE,
        last_seen=event_time,
        total_packets=1,
        total_ip_bytes=80,
    )


def tcp_signal(
    kind: str,
    *,
    seconds: float = 0,
    uid: str = "C1",
    src: str = "192.0.2.1",
    dst: str = "198.51.100.10",
    actor: str = "unknown",
) -> TcpConnectionSignal:
    return TcpConnectionSignal(
        schema_version=1,
        event_time=BASE + timedelta(seconds=seconds),
        zeek_uid=uid,
        kind=kind,
        orig_h=ip(src),
        orig_p=50000,
        resp_h=ip(dst),
        resp_p=443,
        ip_protocol=6,
        actor_role=actor,
    )


def snapshot(
    *,
    kind: str = "open",
    seconds: float = 0,
    uid: str = "C1",
    orig_h: str = "192.0.2.1",
    orig_p: int = 50000,
    resp_h: str = "198.51.100.10",
    resp_p: int = 443,
    orig_pkts: int = 1,
    orig_bytes: int = 80,
    resp_pkts: int = 0,
    resp_bytes: int = 0,
) -> FlowSnapshot:
    when = BASE + timedelta(seconds=seconds)
    return FlowSnapshot(
        1,
        kind,
        when,
        uid,
        ip(orig_h),
        orig_p,
        ip(resp_h),
        resp_p,
        6,
        BASE,
        when,
        orig_pkts,
        orig_bytes,
        0,
        resp_pkts,
        resp_bytes,
        0,
        1,
        1,
        "S",
    )


def typed(data_type: str, data: object) -> dict[str, object]:
    return {"@data-type": data_type, "data": data}


def tcp_wire_message(
    *, kind: str = "reset", actor: str = "resp", protocol: int = 6
) -> str:
    args = [
        typed("count", 1),
        typed("timestamp", "2026-09-30T12:00:00Z"),
        typed("string", "C1"),
        typed("string", kind),
        typed("address", "192.0.2.1"),
        typed("count", 50000),
        typed("address", "198.51.100.10"),
        typed("count", 443),
        typed("count", protocol),
        typed("string", actor),
    ]
    event = typed(
        "vector",
        [typed("string", TCP_SIGNAL_EVENT), typed("vector", args)],
    )
    return json.dumps(
        {
            "type": "data-message",
            "topic": DEFAULT_TOPIC,
            "@data-type": "vector",
            "data": [typed("count", 1), typed("count", 1), event],
        }
    )


class LifecycleTests(unittest.TestCase):
    def test_start_and_final_are_emitted_once(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        first = adapter.adapt_with_lifecycle(snapshot())
        final = adapter.adapt_with_lifecycle(
            snapshot(kind="final", seconds=2, orig_pkts=3, orig_bytes=260)
        )
        duplicate = adapter.adapt_with_lifecycle(
            snapshot(kind="final", seconds=2, orig_pkts=3, orig_bytes=260)
        )

        self.assertEqual([event.kind for event in first.connection_events], ["start"])
        self.assertEqual([event.kind for event in final.connection_events], ["final"])
        self.assertEqual(final.connection_events[0].total_packets, 3)
        self.assertEqual(duplicate.connection_events, ())

    def test_short_final_emits_start_then_final_and_zero_direction_is_ignored(self) -> None:
        result = CumulativeSnapshotAdapter().adapt_with_lifecycle(
            snapshot(kind="final", orig_pkts=2, orig_bytes=160)
        )
        self.assertEqual([event.kind for event in result.connection_events], ["start", "final"])
        self.assertTrue(all(event.direction_role == "originator" for event in result.connection_events))

    def test_flip_does_not_emit_duplicate_start(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        adapter.adapt_with_lifecycle(snapshot(orig_pkts=3, orig_bytes=240))
        result = adapter.adapt_with_lifecycle(
            snapshot(
                kind="flipped",
                seconds=1,
                orig_h="198.51.100.10",
                orig_p=443,
                resp_h="192.0.2.1",
                resp_p=50000,
                orig_pkts=0,
                orig_bytes=0,
                resp_pkts=4,
                resp_bytes=320,
            )
        )
        self.assertEqual(result.connection_events, ())

    def test_counter_reset_does_not_emit_a_second_start(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        adapter.adapt_with_lifecycle(snapshot(orig_pkts=5, orig_bytes=500))
        reset = adapter.adapt_with_lifecycle(
            snapshot(kind="update", seconds=1, orig_pkts=1, orig_bytes=100)
        )
        after_reset = adapter.adapt_with_lifecycle(
            snapshot(kind="update", seconds=2, orig_pkts=2, orig_bytes=180)
        )
        self.assertEqual(reset.connection_events, ())
        self.assertEqual(after_reset.connection_events, ())

    def test_both_visible_directions_receive_distinct_roles(self) -> None:
        result = CumulativeSnapshotAdapter().adapt_with_lifecycle(
            snapshot(resp_pkts=2, resp_bytes=160)
        )
        roles = {
            str(event.key.src_ip): event.direction_role
            for event in result.connection_events
        }
        self.assertEqual(roles["192.0.2.1"], "originator")
        self.assertEqual(roles["198.51.100.10"], "responder")


class DispatcherAndCoordinatorTests(unittest.TestCase):
    def test_tcp_signal_is_strictly_dispatched(self) -> None:
        for kind in ("syn_start", "established", "attempt_timeout", "rejected"):
            with self.subTest(kind=kind):
                event = decode_stream_event(
                    tcp_wire_message(kind=kind, actor="unknown")
                )
                self.assertIsInstance(event, TcpConnectionSignal)
                self.assertEqual(event.kind, kind)

        event = decode_stream_event(tcp_wire_message())
        self.assertEqual(event.actor_role, "resp")

        with self.assertRaises(SnapshotValidationError):
            decode_stream_event(tcp_wire_message(kind="established", actor="orig"))
        with self.assertRaises(SnapshotValidationError):
            decode_stream_event(tcp_wire_message(protocol=17))

    def test_iter_snapshots_filters_known_non_snapshot_events(self) -> None:
        from tests.test_zeek_websocket import FakeWebSocket, encoded_message

        websocket = FakeWebSocket(
            [
                json.dumps({"type": "ack", "endpoint": "e", "version": "8.0.6"}),
                tcp_wire_message(),
                encoded_message(),
            ]
        )
        iterator = iter_snapshots(
            "ws://example.invalid",
            connector=lambda *args, **kwargs: websocket,
            sleep=lambda delay: None,
        )
        try:
            self.assertEqual(next(iterator).uid, "C123example")
        finally:
            iterator.close()

    def test_tcp_semantic_deduplication(self) -> None:
        flow_manager = FlowManager(
            inactivity_timeout=timedelta(minutes=2),
            cleanup_interval=timedelta(seconds=5),
        )
        coordinator = StreamingCoordinator(
            flow_manager=flow_manager,
            correlation_timeout=timedelta(minutes=5),
            tcp_dedup_max_entries=2,
        )
        signal = tcp_signal("syn_start")
        self.assertTrue(coordinator.process(signal).tcp_signal_accepted)
        self.assertFalse(coordinator.process(signal).tcp_signal_accepted)
        bucket = next(iter(coordinator.scan_manager.get(signal.orig_h).buckets))
        self.assertEqual(bucket.syn_starts, 1)

    def test_tcp_dedup_capacity_eviction_is_operational_telemetry(self) -> None:
        coordinator = StreamingCoordinator(
            flow_manager=FlowManager(
                inactivity_timeout=timedelta(minutes=2),
                cleanup_interval=timedelta(seconds=5),
            ),
            correlation_timeout=timedelta(minutes=5),
            tcp_dedup_max_entries=2,
        )
        for uid in ("C1", "C2", "C3"):
            self.assertTrue(
                coordinator.process(tcp_signal("syn_start", uid=uid)).tcp_signal_accepted
            )
        self.assertEqual(coordinator.tcp_dedup_capacity_evictions, 1)

    def test_unidirectional_snapshot_fans_out_without_flow_scan(self) -> None:
        flow_manager = FlowManager(
            inactivity_timeout=timedelta(minutes=2),
            cleanup_interval=timedelta(seconds=5),
        )
        coordinator = StreamingCoordinator(
            flow_manager=flow_manager,
            correlation_timeout=timedelta(minutes=5),
        )
        result = coordinator.process(snapshot())
        self.assertEqual(len(result.updates), 1)
        self.assertEqual(len(flow_manager), 1)
        self.assertIsNotNone(coordinator.ddos_manager.get(ip("198.51.100.10")))
        self.assertIsNotNone(coordinator.scan_manager.get(ip("192.0.2.1")))
        self.assertIsNotNone(
            coordinator.exfil_manager.get(
                (ip("192.0.2.1"), ip("198.51.100.10"))
            )
        )
        self.assertIsNotNone(
            coordinator.beacon_manager.get(
                (ip("192.0.2.1"), ip("198.51.100.10"), 443, 6)
            )
        )


class BoundedPrimitiveTests(unittest.TestCase):
    def test_bucket_rollover_expiry_and_late_event_rules(self) -> None:
        ring = BucketRing(
            window=timedelta(seconds=20),
            bucket_width=timedelta(seconds=10),
            factory=lambda start: {"start": start},
        )
        self.assertIsNotNone(ring.bucket_for(BASE))
        self.assertIsNotNone(ring.bucket_for(BASE + timedelta(seconds=25)))
        self.assertIsNotNone(ring.bucket_for(BASE + timedelta(seconds=10)))
        self.assertIsNone(ring.bucket_for(BASE + timedelta(seconds=4)))
        self.assertLessEqual(len(ring), ring.max_buckets)
        ring.expire(BASE + timedelta(seconds=31))
        self.assertEqual(len(ring), 2)

    def test_bounded_map_and_hash_set_saturation(self) -> None:
        counters = BoundedCounterMap[str, int](capacity=1, zero=0)
        self.assertTrue(counters.add("retained", 2))
        self.assertFalse(counters.add("overflow", 3))
        self.assertTrue(counters.add("retained", 4))
        self.assertEqual(counters.values["retained"], 6)
        self.assertEqual(counters.overflow_count, 1)
        self.assertEqual(counters.overflow_value, 3)

        values = BoundedHashSet(capacity=1)
        self.assertTrue(values.add(("a", 1)))
        self.assertFalse(values.add(("a", 1)))
        self.assertFalse(values.add(("b", 2)))
        self.assertEqual(len(values), 1)
        self.assertEqual(values.overflow_count, 1)


class DDoSAndScanStateTests(unittest.TestCase):
    def ddos(self, *, max_entries: int = 10, source_cap: int = 10) -> DDoSStateManager:
        return DDoSStateManager(
            DDoSStateConfig(
                window=timedelta(seconds=30),
                bucket_width=timedelta(seconds=10),
                inactivity_timeout=timedelta(seconds=40),
                cleanup_interval=timedelta(seconds=5),
                max_state_entries=max_entries,
                source_capacity=source_cap,
                port_capacity=10,
                protocol_capacity=4,
            )
        )

    def scan(self, *, max_entries: int = 10) -> ScanStateManager:
        return ScanStateManager(
            ScanStateConfig(
                window=timedelta(seconds=60),
                bucket_width=timedelta(seconds=10),
                inactivity_timeout=timedelta(seconds=70),
                cleanup_interval=timedelta(seconds=5),
                max_state_entries=max_entries,
                destination_ip_capacity=10,
                destination_port_capacity=10,
                destination_pair_capacity=20,
                protocol_capacity=4,
            )
        )

    def test_ddos_aggregates_sources_and_udp_volume(self) -> None:
        manager = self.ddos()
        destination = "198.51.100.10"
        manager.update_flow(
            flow_update(
                packets=4,
                byte_count=400,
                flow_key=key(src="192.0.2.1", dst=destination, protocol=17, dst_port=53),
            )
        )
        manager.update_flow(
            flow_update(
                packets=6,
                byte_count=900,
                flow_key=key(src="192.0.2.2", dst=destination, protocol=17, dst_port=53),
            )
        )
        bucket = next(iter(manager.get(ip(destination)).buckets))
        self.assertEqual((bucket.packets, bucket.ip_bytes), (10, 1300))
        self.assertEqual(bucket.protocol_packets.values[17], 10)
        self.assertEqual(len(bucket.observed_sources), 2)

    def test_ddos_connection_and_tcp_semantics(self) -> None:
        manager = self.ddos()
        manager.update_connection(connection_event())
        manager.update_tcp(tcp_signal("syn_start"))
        manager.update_tcp(tcp_signal("established", uid="C2"))
        manager.update_tcp(tcp_signal("attempt_timeout", uid="C3"))
        manager.update_tcp(tcp_signal("rejected", uid="C4"))
        manager.update_tcp(tcp_signal("reset", uid="C5", actor="orig"))
        manager.update_tcp(tcp_signal("reset", uid="C6", actor="resp"))
        manager.update_tcp(tcp_signal("reset", uid="C7"))
        bucket = next(iter(manager.get(ip("198.51.100.10")).buckets))
        self.assertEqual(bucket.connection_starts, 1)
        self.assertEqual(bucket.destination_ports.values[443], 1)
        self.assertEqual(bucket.syn_starts, 1)
        self.assertEqual(bucket.tcp_established, 1)
        self.assertEqual(bucket.tcp_attempt_timeouts, 1)
        self.assertEqual(bucket.tcp_rejected, 1)
        self.assertEqual(bucket.tcp_resets_from_source, 1)
        self.assertEqual(bucket.tcp_resets_from_destination, 1)
        self.assertEqual(bucket.tcp_resets_unknown, 1)

    def test_source_saturation_and_top_level_lru_eviction(self) -> None:
        manager = self.ddos(max_entries=2, source_cap=1)
        destination_a = ip("198.51.100.1")
        destination_b = ip("198.51.100.2")
        manager.update_flow(flow_update(flow_key=key(dst=str(destination_a))))
        manager.update_flow(
            flow_update(flow_key=key(src="192.0.2.2", dst=str(destination_a)))
        )
        bucket = next(iter(manager.get(destination_a).buckets))
        self.assertEqual(bucket.source_overflow_packets, 1)

        manager.update_flow(flow_update(flow_key=key(dst=str(destination_b))))
        manager.update_flow(
            flow_update(seconds=1, flow_key=key(dst=str(destination_a)))
        )
        destination_c = ip("198.51.100.3")
        manager.update_flow(flow_update(seconds=2, flow_key=key(dst=str(destination_c))))
        self.assertIsNone(manager.get(destination_b))
        self.assertEqual(manager.capacity_evictions, 1)

    def test_scan_horizontal_and_vertical_fanout(self) -> None:
        horizontal = self.scan()
        for index in range(1, 4):
            horizontal.update_connection(
                connection_event(
                    uid=f"H{index}",
                    flow_key=key(dst=f"198.51.100.{index}", dst_port=80),
                )
            )
        h_bucket = next(iter(horizontal.get(ip("192.0.2.1")).buckets))
        self.assertEqual(len(h_bucket.destination_ips), 3)
        self.assertEqual(len(h_bucket.destination_ports), 1)

        vertical = self.scan()
        for index, port in enumerate((22, 80, 443), 1):
            vertical.update_connection(
                connection_event(
                    uid=f"V{index}", flow_key=key(dst="198.51.100.20", dst_port=port)
                )
            )
        v_bucket = next(iter(vertical.get(ip("192.0.2.1")).buckets))
        self.assertEqual(len(v_bucket.destination_ips), 1)
        self.assertEqual(len(v_bucket.destination_ports), 3)
        self.assertEqual(len(v_bucket.destination_pairs), 3)

    def test_scan_tcp_outcomes_state_cap_and_cleanup(self) -> None:
        manager = self.scan(max_entries=2)
        for index, kind in enumerate(
            ("syn_start", "established", "attempt_timeout", "rejected", "reset")
        ):
            manager.update_tcp(
                tcp_signal(kind, uid=f"C{index}", actor="orig" if kind == "reset" else "unknown")
            )
        state = manager.get(ip("192.0.2.1"))
        bucket = next(iter(state.buckets))
        self.assertEqual(bucket.syn_starts, 1)
        self.assertEqual(bucket.tcp_established, 1)
        self.assertEqual(bucket.tcp_attempt_timeouts, 1)
        self.assertEqual(bucket.tcp_rejected, 1)
        self.assertEqual(bucket.tcp_resets, 1)

        manager.update_connection(
            connection_event(
                seconds=1,
                uid="other",
                flow_key=key(src="192.0.2.2", dst="198.51.100.20"),
            )
        )
        manager.update_connection(
            connection_event(
                seconds=2,
                uid="third",
                flow_key=key(src="192.0.2.3", dst="198.51.100.30"),
            )
        )
        self.assertIsNone(manager.get(ip("192.0.2.1")))
        self.assertEqual(manager.capacity_evictions, 1)

        removed = manager.expire(BASE + timedelta(seconds=100))
        self.assertEqual(removed, 2)
        self.assertEqual(len(manager), 0)

    def test_late_events_and_memory_cleanup(self) -> None:
        manager = self.ddos()
        manager.update_flow(flow_update(seconds=35))
        self.assertTrue(manager.update_flow(flow_update(seconds=10)))
        self.assertFalse(manager.update_flow(flow_update(seconds=0)))
        destination = ip("198.51.100.10")
        self.assertIsNotNone(manager.get(destination))
        removed = manager.expire(BASE + timedelta(seconds=90))
        self.assertEqual(removed, 1)
        self.assertIsNone(manager.get(destination))


if __name__ == "__main__":
    unittest.main()
