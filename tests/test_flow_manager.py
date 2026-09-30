from __future__ import annotations

import ipaddress
import io
import json
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from src.flow.flow_manager import FlowManager
from src.flow.models import FlowKey
from src.flow.snapshot_adapter import CumulativeSnapshotAdapter
from src.ingestion.zeek_websocket import FlowSnapshot
from src.main import run_pipeline

BASE_TIME = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def make_snapshot(
    *,
    uid: str = "C-flow-1",
    kind: str = "update",
    seconds: float = 1,
    orig_h: str = "192.0.2.10",
    orig_p: int = 50000,
    resp_h: str = "198.51.100.20",
    resp_p: int = 443,
    protocol: int = 6,
    orig_pkts: int = 0,
    orig_bytes: int = 0,
    resp_pkts: int = 0,
    resp_bytes: int = 0,
) -> FlowSnapshot:
    observed_at = BASE_TIME + timedelta(seconds=seconds)
    return FlowSnapshot(
        schema_version=1,
        kind=kind,
        observed_at=observed_at,
        uid=uid,
        orig_h=ipaddress.ip_address(orig_h),
        orig_p=orig_p,
        resp_h=ipaddress.ip_address(resp_h),
        resp_p=resp_p,
        ip_proto=protocol,
        first_seen=BASE_TIME,
        last_seen=observed_at,
        orig_pkts=orig_pkts,
        orig_ip_bytes=orig_bytes,
        orig_payload_bytes=0,
        resp_pkts=resp_pkts,
        resp_ip_bytes=resp_bytes,
        resp_payload_bytes=0,
        orig_state=1,
        resp_state=1,
        history="ShADadFf",
    )


def make_manager(timeout: float = 30, cleanup: float = 5) -> FlowManager:
    return FlowManager(
        inactivity_timeout=timedelta(seconds=timeout),
        cleanup_interval=timedelta(seconds=cleanup),
    )


def apply_snapshot(
    adapter: CumulativeSnapshotAdapter,
    manager: FlowManager,
    snapshot: FlowSnapshot,
) -> tuple:
    updates = adapter.adapt(snapshot)
    for update in updates:
        manager.update(update)
    return updates


class SnapshotAdapterAndFlowManagerTests(unittest.TestCase):
    def test_new_flow_creation(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager()

        updates = apply_snapshot(
            adapter,
            manager,
            make_snapshot(kind="open", orig_pkts=2, orig_bytes=160),
        )

        self.assertEqual(len(updates), 1)
        self.assertEqual(len(manager), 1)
        state = manager.get(updates[0].key)
        self.assertIsNotNone(state)
        self.assertEqual(state.packet_count, 2)
        self.assertEqual(state.byte_count, 160)

    def test_existing_flow_is_updated_with_cumulative_delta(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager()
        first = make_snapshot(orig_pkts=5, orig_bytes=500)
        second = make_snapshot(seconds=2, orig_pkts=8, orig_bytes=860)

        apply_snapshot(adapter, manager, first)
        updates = apply_snapshot(adapter, manager, second)

        self.assertEqual(updates[0].packet_delta, 3)
        self.assertEqual(updates[0].byte_delta, 360)
        state = manager.get(updates[0].key)
        self.assertEqual(state.packet_count, 8)
        self.assertEqual(state.byte_count, 860)
        self.assertEqual(state.last_seen, second.last_seen)

    def test_originator_and_responder_map_to_separate_directional_keys(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        snapshot = make_snapshot(
            protocol=17,
            orig_pkts=3,
            orig_bytes=240,
            resp_pkts=2,
            resp_bytes=180,
        )

        updates = adapter.adapt(snapshot)

        self.assertEqual(len(updates), 2)
        by_source = {str(update.key.src_ip): update for update in updates}
        outbound = by_source["192.0.2.10"]
        inbound = by_source["198.51.100.20"]
        self.assertEqual(outbound.key.dst_ip, ipaddress.ip_address("198.51.100.20"))
        self.assertEqual(outbound.key.src_port, 50000)
        self.assertEqual(outbound.key.dst_port, 443)
        self.assertEqual(outbound.key.protocol, 17)
        self.assertEqual(inbound.key.dst_ip, ipaddress.ip_address("192.0.2.10"))
        self.assertEqual(inbound.key.src_port, 443)
        self.assertEqual(inbound.key.dst_port, 50000)

    def test_duplicate_snapshot_does_not_increase_counters(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager()
        snapshot = make_snapshot(orig_pkts=4, orig_bytes=320)

        first_updates = apply_snapshot(adapter, manager, snapshot)
        duplicate_updates = apply_snapshot(adapter, manager, snapshot)

        self.assertEqual(duplicate_updates, ())
        state = manager.get(first_updates[0].key)
        self.assertEqual(state.packet_count, 4)
        self.assertEqual(state.byte_count, 320)

    def test_counter_regression_resets_baseline_without_negative_delta(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager()
        first = make_snapshot(orig_pkts=5, orig_bytes=500)
        regressed = make_snapshot(seconds=2, orig_pkts=2, orig_bytes=200)
        after_reset = make_snapshot(seconds=3, orig_pkts=4, orig_bytes=350)

        initial_updates = apply_snapshot(adapter, manager, first)
        self.assertEqual(apply_snapshot(adapter, manager, regressed), ())
        reset_updates = apply_snapshot(adapter, manager, after_reset)

        self.assertEqual(reset_updates[0].packet_delta, 2)
        self.assertEqual(reset_updates[0].byte_delta, 150)
        state = manager.get(initial_updates[0].key)
        self.assertEqual(state.packet_count, 7)
        self.assertEqual(state.byte_count, 650)

    def test_reconnect_gap_is_recovered_from_cumulative_counters(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        first = make_snapshot(orig_pkts=2, orig_bytes=200)
        after_gap = make_snapshot(seconds=20, orig_pkts=9, orig_bytes=950)

        adapter.adapt(first)
        updates = adapter.adapt(after_gap)

        self.assertEqual(updates[0].packet_delta, 7)
        self.assertEqual(updates[0].byte_delta, 750)

    def test_connection_flipped_keeps_network_directions_separate(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        first = make_snapshot(
            orig_pkts=5,
            orig_bytes=500,
            resp_pkts=2,
            resp_bytes=200,
        )
        flipped = make_snapshot(
            kind="flipped",
            seconds=2,
            orig_h="198.51.100.20",
            orig_p=443,
            resp_h="192.0.2.10",
            resp_p=50000,
            orig_pkts=4,
            orig_bytes=420,
            resp_pkts=8,
            resp_bytes=830,
        )

        adapter.adapt(first)
        updates = adapter.adapt(flipped)
        by_source = {str(update.key.src_ip): update for update in updates}

        self.assertEqual(by_source["192.0.2.10"].packet_delta, 3)
        self.assertEqual(by_source["192.0.2.10"].byte_delta, 330)
        self.assertEqual(by_source["198.51.100.20"].packet_delta, 2)
        self.assertEqual(by_source["198.51.100.20"].byte_delta, 220)

    def test_final_snapshot_adds_only_final_delta_and_suppresses_duplicates(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager()
        first = make_snapshot(orig_pkts=2, orig_bytes=200)
        final = make_snapshot(kind="final", seconds=3, orig_pkts=4, orig_bytes=440)

        initial_updates = apply_snapshot(adapter, manager, first)
        final_updates = apply_snapshot(adapter, manager, final)
        duplicate_updates = apply_snapshot(adapter, manager, final)

        self.assertEqual(final_updates[0].packet_delta, 2)
        self.assertEqual(final_updates[0].byte_delta, 240)
        self.assertEqual(duplicate_updates, ())
        state = manager.get(initial_updates[0].key)
        self.assertEqual(state.packet_count, 4)
        self.assertEqual(state.byte_count, 440)
        self.assertEqual(adapter.correlation_count, 1)

    def test_zero_traffic_direction_does_not_create_flow(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager()

        updates = apply_snapshot(adapter, manager, make_snapshot(kind="open"))

        self.assertEqual(updates, ())
        self.assertEqual(len(manager), 0)

    def test_flow_and_uid_baseline_expiration_bound_state(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager(timeout=10, cleanup=5)
        snapshot = make_snapshot(orig_pkts=1, orig_bytes=80)
        updates = apply_snapshot(adapter, manager, snapshot)

        self.assertEqual(manager.expire_inactive(snapshot.last_seen + timedelta(seconds=9)), ())
        expired = manager.expire_inactive(snapshot.last_seen + timedelta(seconds=10))
        expired_baselines = adapter.expire_inactive(
            snapshot.observed_at + timedelta(seconds=20), timedelta(seconds=20)
        )

        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].key, updates[0].key)
        self.assertEqual(len(manager), 0)
        self.assertEqual(expired_baselines, 1)
        self.assertEqual(adapter.correlation_count, 0)

    def test_periodic_cleanup_does_not_scan_on_every_update(self) -> None:
        manager = make_manager(timeout=3, cleanup=5)
        adapter = CumulativeSnapshotAdapter()
        snapshot = make_snapshot(orig_pkts=1, orig_bytes=80)
        apply_snapshot(adapter, manager, snapshot)

        self.assertIsNone(manager.maybe_expire(snapshot.observed_at))
        self.assertIsNone(
            manager.maybe_expire(snapshot.observed_at + timedelta(seconds=4))
        )
        expired = manager.maybe_expire(snapshot.observed_at + timedelta(seconds=5))

        self.assertEqual(len(expired), 1)
        self.assertEqual(len(manager), 0)

    def test_multiple_independent_flow_keys(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        manager = make_manager()
        first = make_snapshot(uid="C-one", orig_pkts=1, orig_bytes=80)
        second = make_snapshot(
            uid="C-two",
            orig_h="203.0.113.5",
            orig_p=53000,
            resp_h="203.0.113.53",
            resp_p=53,
            protocol=17,
            orig_pkts=2,
            orig_bytes=140,
        )

        apply_snapshot(adapter, manager, first)
        apply_snapshot(adapter, manager, second)

        self.assertEqual(len(manager), 2)
        keys = set(manager.active_flows)
        self.assertIn(
            FlowKey(
                ipaddress.ip_address("192.0.2.10"),
                50000,
                ipaddress.ip_address("198.51.100.20"),
                443,
                6,
            ),
            keys,
        )
        self.assertIn(
            FlowKey(
                ipaddress.ip_address("203.0.113.5"),
                53000,
                ipaddress.ip_address("203.0.113.53"),
                53,
                17,
            ),
            keys,
        )

    def test_out_of_order_snapshot_does_not_roll_baseline_back(self) -> None:
        adapter = CumulativeSnapshotAdapter()
        latest = make_snapshot(seconds=5, orig_pkts=5, orig_bytes=500)
        stale = make_snapshot(seconds=4, orig_pkts=3, orig_bytes=300)
        next_snapshot = make_snapshot(seconds=6, orig_pkts=7, orig_bytes=720)

        adapter.adapt(latest)
        self.assertEqual(adapter.adapt(stale), ())
        updates = adapter.adapt(next_snapshot)

        self.assertEqual(updates[0].packet_delta, 2)
        self.assertEqual(updates[0].byte_delta, 220)

    def test_runtime_pipeline_composes_receiver_adapter_manager_and_inspection(self) -> None:
        first = make_snapshot(orig_pkts=2, orig_bytes=200)
        second = make_snapshot(seconds=2, orig_pkts=5, orig_bytes=560)
        output = io.StringIO()

        with patch("src.main.iter_events", return_value=iter((first, second))):
            run_pipeline(
                uri="ws://127.0.0.1:9997/v1/messages/json",
                topic="sih/flow/v1",
                inactivity_timeout=timedelta(seconds=30),
                cleanup_interval=timedelta(seconds=5),
                inspection_interval=timedelta(seconds=1),
                correlation_timeout=timedelta(seconds=60),
                output=output,
            )

        reports = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[-1]["active_flow_count"], 1)
        self.assertEqual(reports[-1]["active_flows"][0]["packet_count"], 5)
        self.assertEqual(reports[-1]["active_flows"][0]["byte_count"], 560)


if __name__ == "__main__":
    unittest.main()
