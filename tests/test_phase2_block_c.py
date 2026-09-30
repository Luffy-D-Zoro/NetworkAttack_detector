from __future__ import annotations

import ipaddress
import importlib.util
import json
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.coordinator import StreamingCoordinator
from src.flow.flow_manager import FlowManager
from src.flow.models import DirectionalFlowUpdate, FlowKey
from src.ingestion.zeek_websocket import (
    DEFAULT_TOPIC,
    DNS_QUERY_EVENT,
    DNS_RESULT_EVENT,
    ENCRYPTED_PROTOCOL_EVENT,
    DNSQueryObservation,
    DNSResultObservation,
    EncryptedProtocolObservation,
    FlowSnapshot,
    SnapshotValidationError,
    decode_stream_event,
    validate_ack,
    websocket_uri,
)
from src.states.dns import DNSStateConfig, DNSStateManager
from src.states.encrypted import EncryptedStateConfig, EncryptedStateManager

BASE = datetime(2026, 9, 30, 12, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "zeek" / "flow_stream.zeek"


def ip(value: str):
    return ipaddress.ip_address(value)


def query(seconds: float = 0, *, uid: str = "D1", name: str = "a.example.co.uk", source: str = "192.0.2.1", tx: int = 1, qtype: int = 1) -> DNSQueryObservation:
    return DNSQueryObservation(1, BASE + timedelta(seconds=seconds), uid, ip(source), 53000, ip("198.51.100.53"), 53, 17, tx, name, qtype, 1)


def result(seconds: float = 1, *, uid: str = "D1", name: str | None = "a.example.co.uk", source: str = "192.0.2.1", tx: int = 1, saw_reply: bool = True, rcode: int | None = 0) -> DNSResultObservation:
    return DNSResultObservation(1, BASE, BASE + timedelta(seconds=seconds), uid, ip(source), ip("198.51.100.53"), 17, tx, name, saw_reply, False, rcode, 0.02 if saw_reply else None, 2 if saw_reply else None)


def encrypted(seconds: float = 0, *, uid: str = "E1", kind: str = "identified", family: str = "tls", version: str | None = None, server_name: str | None = None, established: bool | None = None) -> EncryptedProtocolObservation:
    protocol = 17 if family in {"dtls", "quic"} else 6
    return EncryptedProtocolObservation(
        1, kind, BASE + timedelta(seconds=seconds), uid, family,
        ip("192.0.2.10"), 50000, ip("198.51.100.20"), 443, protocol,
        version, "TLS_AES_128_GCM_SHA256" if kind == "metadata" and family != "quic" else None,
        "x25519" if kind == "metadata" and family != "quic" else None,
        server_name, "h2" if kind == "metadata" else None,
        False if kind == "metadata" and family != "quic" else None,
        established, None, "sha256:abc" if kind == "metadata" and family != "quic" else None, None,
    )


def update(seconds: float, *, uid: str = "E1", reverse: bool = False, packets: int = 2, size: int = 200) -> DirectionalFlowUpdate:
    if reverse:
        key = FlowKey(ip("198.51.100.20"), 443, ip("192.0.2.10"), 50000, 6)
    else:
        key = FlowKey(ip("192.0.2.10"), 50000, ip("198.51.100.20"), 443, 6)
    return DirectionalFlowUpdate(key, BASE, BASE + timedelta(seconds=seconds), packets, size, uid)


def snapshot(*, uid: str = "E1", seconds: float = 10, packets: int = 5, size: int = 500, reverse_packets: int = 0, reverse_size: int = 0) -> FlowSnapshot:
    return FlowSnapshot(1, "final", BASE + timedelta(seconds=seconds), uid, ip("192.0.2.10"), 50000, ip("198.51.100.20"), 443, 6, BASE, BASE + timedelta(seconds=seconds - 1), packets, size, 0, reverse_packets, reverse_size, 0, 1, 1, "ShAD")


def typed(kind: str, value: object) -> dict[str, object]:
    return {"@data-type": kind, "data": value}


def wire(event_name: str, args: list[dict[str, object]]) -> str:
    event = typed("vector", [typed("string", event_name), typed("vector", args)])
    return json.dumps({"type": "data-message", "topic": DEFAULT_TOPIC, "@data-type": "vector", "data": [typed("count", 1), typed("count", 1), event]})


class TransportTests(unittest.TestCase):
    def test_dns_query_and_result_are_strictly_dispatched(self) -> None:
        qargs = [typed("count", 1), typed("timestamp", "2026-09-30T12:00:00Z"), typed("string", "D1"), typed("address", "192.0.2.1"), typed("count", 53000), typed("address", "198.51.100.53"), typed("count", 53), typed("count", 17), typed("count", 4), typed("string", "a.example"), typed("count", 1), typed("count", 1)]
        self.assertIsInstance(decode_stream_event(wire(DNS_QUERY_EVENT, qargs)), DNSQueryObservation)
        rargs = [typed("count", 1), typed("timestamp", "2026-09-30T12:00:00Z"), typed("timestamp", "2026-09-30T12:00:01Z"), typed("string", "D1"), typed("address", "192.0.2.1"), typed("address", "198.51.100.53"), typed("count", 17), typed("count", 4), typed("boolean", False), typed("string", ""), typed("boolean", False), typed("boolean", False), typed("boolean", True), typed("count", 3), typed("boolean", False), typed("real", 0.0), typed("boolean", False), typed("count", 0)]
        decoded = decode_stream_event(wire(DNS_RESULT_EVENT, rargs))
        self.assertIsNone(decoded.query)
        self.assertEqual(decoded.rcode, 3)

    def test_encrypted_nullable_fields_and_schema_are_strict(self) -> None:
        args = [typed("count", 1), typed("string", "identified"), typed("timestamp", "2026-09-30T12:00:00Z"), typed("string", "E1"), typed("string", "quic"), typed("address", "192.0.2.10"), typed("count", 50000), typed("address", "198.51.100.20"), typed("count", 443), typed("count", 17)]
        for value in ["1", "", "", "example.com", "h3"]:
            args.extend([typed("boolean", bool(value)), typed("string", value)])
        args.extend([typed("boolean", False), typed("boolean", False), typed("boolean", False), typed("boolean", False)])
        for value in ["", "", ""]:
            args.extend([typed("boolean", False), typed("string", value)])
        decoded = decode_stream_event(wire(ENCRYPTED_PROTOCOL_EVENT, args))
        self.assertEqual(decoded.security_family, "quic")
        self.assertIsNone(decoded.cipher)
        args[9] = typed("count", 6)
        with self.assertRaises(SnapshotValidationError):
            decode_stream_event(wire(ENCRYPTED_PROTOCOL_EVENT, args))


class DNSStateTests(unittest.TestCase):
    def manager(self, **changes: object) -> DNSStateManager:
        values = dict(source_window=timedelta(seconds=20), source_bucket_width=timedelta(seconds=5), domain_window=timedelta(seconds=30), domain_bucket_width=timedelta(seconds=5), inactivity_timeout=timedelta(seconds=40), domain_inactivity_timeout=timedelta(seconds=35), cleanup_interval=timedelta(seconds=1), max_state_entries=4, domain_capacity=2, category_capacity=4, qname_hash_capacity=4, domain_hash_capacity=4, subdomain_hash_capacity=4, dedup_horizon=timedelta(seconds=30), dedup_max_entries=20)
        values.update(changes)
        return DNSStateManager(DNSStateConfig(**values))

    def test_query_result_uniqueness_entropy_psl_and_no_double_count(self) -> None:
        manager = self.manager()
        self.assertTrue(manager.update_query(query(name="ab.example.co.uk")))
        self.assertFalse(manager.update_query(query(name="ab.example.co.uk")))
        self.assertTrue(manager.update_result(result(name="ab.example.co.uk")))
        self.assertFalse(manager.update_result(result(name="ab.example.co.uk")))
        state = manager.get(ip("192.0.2.1"))
        source = list(state.source_buckets)[0]
        domain = list(state.domains["example.co.uk"].buckets)[0]
        self.assertEqual(source.query_count, 1)
        self.assertEqual(source.result_count, 1)
        self.assertEqual(len(source.unique_qname_hashes), 1)
        self.assertEqual(len(source.unique_base_domain_hashes), 1)
        self.assertEqual(domain.query_count, 1)
        self.assertGreater(domain.subdomain_entropy_sum, 0)

    def test_malformed_nxdomain_and_missing_reply_statistics(self) -> None:
        manager = self.manager()
        manager.update_query(query(name="bad..name"))
        manager.update_result(result(rcode=3))
        manager.update_result(result(seconds=2, uid="D2", tx=2, saw_reply=False, rcode=None))
        state = manager.get(ip("192.0.2.1"))
        bucket = list(state.source_buckets)[0]
        self.assertEqual(bucket.malformed_query_count, 1)
        self.assertEqual(bucket.rcode_counts.values[3], 1)
        self.assertEqual(bucket.no_reply_count, 1)
        self.assertFalse(state.domains)

    def test_domain_overflow_state_cap_and_cleanup(self) -> None:
        manager = self.manager(domain_capacity=1, max_state_entries=1)
        manager.update_query(query(name="a.one.com"))
        manager.update_query(query(seconds=1, uid="D2", tx=2, name="b.two.net"))
        state = manager.get(ip("192.0.2.1"))
        self.assertEqual(len(state.domains), 1)
        self.assertEqual(list(state.domain_overflow.buckets)[0].query_count, 1)
        manager.update_query(query(seconds=2, uid="D3", tx=3, source="192.0.2.2"))
        self.assertEqual(manager.capacity_evictions, 1)
        manager.expire(BASE + timedelta(seconds=100))
        self.assertEqual(len(manager), 0)

    def test_late_queries_inside_horizon_are_kept_and_older_are_ignored(self) -> None:
        manager = self.manager()
        manager.update_query(query(seconds=20, uid="D1", tx=1))
        self.assertTrue(manager.update_query(query(seconds=5, uid="D2", tx=2)))
        self.assertFalse(manager.update_query(query(seconds=-20, uid="D3", tx=3)))
        state = manager.get(ip("192.0.2.1"))
        self.assertEqual(sum(bucket.query_count for bucket in state.source_buckets), 2)


class EncryptedStateTests(unittest.TestCase):
    def manager(self, **changes: object) -> EncryptedStateManager:
        values = dict(window=timedelta(seconds=30), bucket_width=timedelta(seconds=5), completed_horizon=timedelta(seconds=40), completed_sample_capacity=3, session_timeout=timedelta(seconds=20), inactivity_timeout=timedelta(seconds=50), cleanup_interval=timedelta(seconds=1), max_state_entries=3, sessions_per_state=2, uid_capacity=4, category_capacity=3, final_dedup_horizon=timedelta(seconds=20), final_dedup_capacity=4, category_length_limit=64)
        values.update(changes)
        return EncryptedStateManager(EncryptedStateConfig(**values))

    @staticmethod
    def key(family: str = "tls"):
        return (ip("192.0.2.10"), ip("198.51.100.20"), 443, 17 if family in {"dtls", "quic"} else 6, family)

    def test_tls_metadata_merge_duplicate_and_uid_routing(self) -> None:
        manager = self.manager()
        manager.update_protocol(encrypted())
        manager.update_protocol(encrypted(1, kind="metadata", version="TLSv13", established=True))
        self.assertTrue(manager.update_protocol(encrypted(2, kind="metadata", version="TLSv13", server_name="Example.COM", established=True)))
        self.assertFalse(manager.update_protocol(encrypted(3, kind="metadata", version="TLSv13", server_name="Example.COM", established=True)))
        state = manager.get(self.key())
        bucket = list(state.buckets)[0]
        self.assertEqual(bucket.session_starts, 1)
        self.assertEqual(bucket.metadata_records, 1)
        self.assertEqual(bucket.established_count, 1)
        self.assertEqual(bucket.version_counts.values["TLSv13"], 1)
        self.assertEqual(len(bucket.server_name_hashes), 1)
        self.assertEqual(manager.key_for_uid("E1"), self.key())

    def test_quic_identification_and_missing_reverse_direction(self) -> None:
        manager = self.manager()
        manager.update_protocol(encrypted(family="quic", version="1"))
        state = manager.get(self.key("quic"))
        session = state.active_sessions["E1"]
        self.assertEqual(session.directions_observed_mask, 0)
        self.assertEqual(list(state.buckets)[0].version_counts.values["1"], 1)
        manager.update_protocol(encrypted(1, uid="E2", family="dtls"))
        self.assertIsNotNone(manager.get(self.key("dtls")))

    def test_directional_traffic_and_final_reconciliation(self) -> None:
        manager = self.manager()
        manager.update_protocol(encrypted())
        manager.update_flow(update(1, packets=2, size=200))
        manager.update_flow(update(2, reverse=True, packets=1, size=100))
        self.assertTrue(manager.finalize(snapshot(packets=5, size=500, reverse_packets=1, reverse_size=100)))
        self.assertFalse(manager.finalize(snapshot(packets=5, size=500, reverse_packets=1, reverse_size=100)))
        state = manager.get(self.key())
        sample = list(state.completed_sessions)[0]
        self.assertEqual((sample.client_to_server_packets, sample.client_to_server_ip_bytes), (5, 500))
        self.assertEqual(sample.directions_observed_mask, 3)
        self.assertIn("E1", state.active_sessions)
        manager.expire(BASE + timedelta(seconds=31))
        self.assertFalse(state.active_sessions)

    def test_traffic_before_identification_is_recovered_at_final(self) -> None:
        manager = self.manager()
        self.assertFalse(manager.update_flow(update(1, packets=4, size=400)))
        manager.update_protocol(encrypted(2))
        manager.finalize(snapshot(packets=5, size=500))
        sample = list(manager.get(self.key()).completed_sessions)[0]
        self.assertEqual(sample.client_to_server_packets, 5)
        self.assertEqual(sample.directions_observed_mask, 1)

    def test_capacity_bounds_and_cleanup(self) -> None:
        manager = self.manager(sessions_per_state=1, max_state_entries=1)
        manager.update_protocol(encrypted(uid="E1"))
        manager.update_protocol(encrypted(1, uid="E2"))
        self.assertEqual(manager.session_capacity_evictions, 1)
        other = EncryptedProtocolObservation(1, "identified", BASE + timedelta(seconds=2), "E3", "tls", ip("192.0.2.11"), 50001, ip("198.51.100.21"), 443, 6, None, None, None, None, None, None, None, None, None, None)
        manager.update_protocol(other)
        self.assertEqual(manager.capacity_evictions, 1)
        manager.expire(BASE + timedelta(seconds=100))
        self.assertEqual(len(manager), 0)

    def test_completed_samples_are_count_and_time_bounded(self) -> None:
        manager = self.manager(completed_sample_capacity=2, sessions_per_state=10)
        for index in range(3):
            uid = f"E{index}"
            manager.update_protocol(encrypted(index, uid=uid))
            manager.finalize(snapshot(uid=uid, seconds=10 + index))
        state = manager.get(self.key())
        self.assertEqual(len(state.completed_sessions), 2)
        manager.expire(BASE + timedelta(seconds=100))
        self.assertEqual(len(state.completed_sessions), 0)

    def test_late_protocol_observations_follow_the_bucket_horizon(self) -> None:
        manager = self.manager(sessions_per_state=10)
        manager.update_protocol(encrypted(20, uid="E1"))
        self.assertTrue(manager.update_protocol(encrypted(0, uid="E2")))
        self.assertFalse(manager.update_protocol(encrypted(-20, uid="E3")))
        self.assertEqual(len(manager.get(self.key()).active_sessions), 2)

    def test_coordinator_routes_protocol_flow_and_final_directly(self) -> None:
        flow_manager = FlowManager(inactivity_timeout=timedelta(seconds=30), cleanup_interval=timedelta(seconds=1))
        encrypted_manager = self.manager()
        coordinator = StreamingCoordinator(flow_manager=flow_manager, encrypted_manager=encrypted_manager, correlation_timeout=timedelta(seconds=60))
        coordinator.process(encrypted())
        coordinator.process(snapshot())
        state = encrypted_manager.get(self.key())
        self.assertEqual(list(state.completed_sessions)[0].client_to_server_packets, 5)


@unittest.skipUnless(
    shutil.which("zeek") and importlib.util.find_spec("websockets"),
    "requires Zeek and the websockets dependency",
)
class BlockCPCAPIntegrationTests(unittest.TestCase):
    def _run(self, pcap: Path, helper_source: str, wanted: tuple[type, ...]):
        from websockets.sync.client import connect

        if not pcap.exists():
            self.skipTest(f"packaged PCAP is unavailable: {pcap}")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with tempfile.TemporaryDirectory() as output_dir:
            helper = Path(output_dir) / "block-c-helper.zeek"
            helper.write_text(helper_source, encoding="utf-8")
            process = subprocess.Popen(
                ["zeek", "-C", "--pseudo-realtime=1", "-r", str(pcap), str(POLICY), str(helper), f"FlowStream::listen_port={port}/tcp"],
                cwd=output_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                websocket = None
                deadline = time.monotonic() + 10
                while websocket is None and time.monotonic() < deadline:
                    try:
                        websocket = connect(websocket_uri("127.0.0.1", port), open_timeout=0.5, close_timeout=0.5)
                    except OSError:
                        time.sleep(0.05)
                self.assertIsNotNone(websocket, "Zeek WebSocket listener did not start")
                found: dict[type, object] = {}
                with websocket:
                    websocket.send(json.dumps([DEFAULT_TOPIC]))
                    validate_ack(websocket.recv(timeout=2))
                    deadline = time.monotonic() + 8
                    while not all(kind in found for kind in wanted) and time.monotonic() < deadline:
                        try:
                            event = decode_stream_event(websocket.recv(timeout=2))
                        except TimeoutError:
                            break
                        for kind in wanted:
                            if isinstance(event, kind):
                                found[kind] = event
                self.assertTrue(all(kind in found for kind in wanted), found)
                return found
            finally:
                process.terminate()
                try:
                    _, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, stderr = process.communicate(timeout=5)
                self.assertNotIn("error in", stderr.lower(), stderr)

    def test_dns_pcap_websocket_and_coordinator(self) -> None:
        helper = r'''
module BlockCIntegration;
type SavedQuery: record { uid: string; ts: time; id: conn_id; proto: count; tx: count; query: string; qtype: count; qclass: count; };
global queries: table[count] of SavedQuery;
global results: table[count] of DNS::Info;
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=-10
    { queries[|queries|] = [$uid=c$uid, $ts=network_time(), $id=c$id, $proto=c$id$proto, $tx=msg$id, $query=query, $qtype=qtype, $qclass=qclass]; }
event DNS::log_dns(rec: DNS::Info) &priority=-10 { results[|results|] = rec; }
event Cluster::websocket_client_added(endpoint: Cluster::EndpointInfo, subscriptions: string_vec) &priority=-1
    {
    for ( i in queries ) { local saved_query=queries[i]; Cluster::publish(FlowStream::topic, FlowStream::dns_query_observation, FlowStream::schema_version, saved_query$ts, saved_query$uid, saved_query$id$orig_h, port_to_count(saved_query$id$orig_p), saved_query$id$resp_h, port_to_count(saved_query$id$resp_p), saved_query$proto, saved_query$tx, saved_query$query, saved_query$qtype, saved_query$qclass); }
    for ( j in results ) { local saved_result=results[j]; local tx: count=0; local query_value=""; local rc: count=0; local rt: double=0.0; local answers: count=0; local ip_protocol: count=saved_result$proto==tcp?6:17; if(saved_result?$trans_id)tx=saved_result$trans_id; if(saved_result?$query)query_value=saved_result$query; if(saved_result?$rcode)rc=saved_result$rcode; if(saved_result?$rtt)rt=interval_to_double(saved_result$rtt); if(saved_result?$total_answers)answers=saved_result$total_answers; Cluster::publish(FlowStream::topic, FlowStream::dns_result_observation, FlowStream::schema_version, saved_result$ts, network_time(), saved_result$uid, saved_result$id$orig_h, saved_result$id$resp_h, ip_protocol, tx, saved_result?$query && query_value!="", query_value, saved_result$saw_reply, saved_result$rejected, saved_result?$rcode, rc, saved_result?$rtt, rt, saved_result?$total_answers, answers); }
    }
'''
        events = self._run(Path("/usr/share/btest/data/pcaps/dns/long-connection.pcap"), helper, (DNSQueryObservation, DNSResultObservation))
        coordinator = StreamingCoordinator(flow_manager=FlowManager(inactivity_timeout=timedelta(seconds=120), cleanup_interval=timedelta(seconds=5)), correlation_timeout=timedelta(seconds=300))
        coordinator.process(events[DNSQueryObservation])
        coordinator.process(events[DNSResultObservation])
        self.assertIsNotNone(coordinator.dns_manager.get(events[DNSQueryObservation].source_ip))

    def test_tls_pcap_websocket_and_coordinator(self) -> None:
        helper = r'''
module BlockCIntegration;
global tls_connections: table[string] of connection;
global tls_records: table[string] of SSL::Info;
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=-10 { if(!c?$quic) tls_connections[c$uid]=c; }
event SSL::log_ssl(rec: SSL::Info) &priority=-10 { tls_records[rec$uid]=rec; }
event Cluster::websocket_client_added(endpoint: Cluster::EndpointInfo, subscriptions: string_vec) &priority=-1
    {
    for ( uid1 in tls_connections ) { local c1=tls_connections[uid1]; Cluster::publish(FlowStream::topic, FlowStream::encrypted_protocol_observation, FlowStream::schema_version,"identified",network_time(),uid1,c1$id$proto==17?"dtls":"tls",c1$id$orig_h,port_to_count(c1$id$orig_p),c1$id$resp_h,port_to_count(c1$id$resp_p),c1$id$proto,F,"",F,"",F,"",F,"",F,"",F,F,F,F,F,"",F,"",F,""); }
    for ( uid2 in tls_records ) { local r=tls_records[uid2]; local v=r?$version?r$version:""; local ci=r?$cipher?r$cipher:""; local cu=r?$curve?r$curve:""; local sn=r?$server_name?r$server_name:""; local al=r?$next_protocol?r$next_protocol:""; local la=r?$last_alert?r$last_alert:""; local fp=""; if(r?$cert_chain_fps && |r$cert_chain_fps|>0)fp=r$cert_chain_fps[0]; Cluster::publish(FlowStream::topic, FlowStream::encrypted_protocol_observation, FlowStream::schema_version,"metadata",network_time(),uid2,r$id$proto==17?"dtls":"tls",r$id$orig_h,port_to_count(r$id$orig_p),r$id$resp_h,port_to_count(r$id$resp_p),r$id$proto,r?$version&&v!="",v,r?$cipher&&ci!="",ci,r?$curve&&cu!="",cu,r?$server_name&&sn!="",sn,r?$next_protocol&&al!="",al,T,r$resumed,T,r$established,r?$last_alert&&la!="",la,fp!="",fp,F,""); }
    for ( uid3 in tls_connections ) { local c3=tls_connections[uid3]; Cluster::publish(FlowStream::topic, FlowStream::flow_snapshot, FlowStream::schema_version,"final",network_time(),c3$uid,c3$id$orig_h,port_to_count(c3$id$orig_p),c3$id$resp_h,port_to_count(c3$id$resp_p),c3$id$proto,c3$start_time,c3$start_time+c3$duration,c3$orig$num_pkts,c3$orig$num_bytes_ip,c3$orig$size,c3$resp$num_pkts,c3$resp$num_bytes_ip,c3$resp$size,c3$orig$state,c3$resp$state,c3$history); }
    }
'''
        events = self._run(Path("/usr/share/btest/data/pcaps/tls/ecdhe.pcap"), helper, (EncryptedProtocolObservation, FlowSnapshot))
        coordinator = StreamingCoordinator(flow_manager=FlowManager(inactivity_timeout=timedelta(seconds=120), cleanup_interval=timedelta(seconds=5)), correlation_timeout=timedelta(seconds=300))
        coordinator.process(events[EncryptedProtocolObservation])
        coordinator.process(events[FlowSnapshot])
        self.assertIsNotNone(coordinator.encrypted_manager.key_for_uid(events[EncryptedProtocolObservation].zeek_uid) or coordinator.encrypted_manager.get((events[EncryptedProtocolObservation].client_ip, events[EncryptedProtocolObservation].server_ip, events[EncryptedProtocolObservation].server_port, events[EncryptedProtocolObservation].ip_protocol, events[EncryptedProtocolObservation].security_family)))


if __name__ == "__main__":
    unittest.main()
