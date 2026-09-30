# Offline JSON sink for the exact local events produced by flow_stream.zeek.
# Loaded only by the external-dataset harness with emit_local_events=T and
# enable_websocket=F; normal live operation is unchanged.

@load tuning/json-logs

module CalibrationCapture;

export {
    redef enum Log::ID += { FLOW_LOG, TCP_LOG, DNS_QUERY_LOG, DNS_RESULT_LOG, ENCRYPTED_LOG };
}

global sequence: count = 0;

type FlowRec: record { seq: count &log; version: count &log; kind: string &log; observed_at: time &log; uid: string &log; orig_h: addr &log; orig_p: count &log; resp_h: addr &log; resp_p: count &log; ip_proto: count &log; first_seen: time &log; last_seen: time &log; orig_pkts: count &log; orig_ip_bytes: count &log; orig_payload_bytes: count &log; resp_pkts: count &log; resp_ip_bytes: count &log; resp_payload_bytes: count &log; orig_state: count &log; resp_state: count &log; history: string &log; };
type TcpRec: record { seq: count &log; version: count &log; event_time: time &log; uid: string &log; kind: string &log; orig_h: addr &log; orig_p: count &log; resp_h: addr &log; resp_p: count &log; ip_proto: count &log; actor_role: string &log; };
type DNSQueryRec: record { seq: count &log; version: count &log; event_time: time &log; uid: string &log; source_ip: addr &log; source_port: count &log; resolver_ip: addr &log; resolver_port: count &log; ip_proto: count &log; transaction_id: count &log; query: string &log; qtype: count &log; qclass: count &log; };
type DNSResultRec: record { seq: count &log; version: count &log; query_time: time &log; result_time: time &log; uid: string &log; source_ip: addr &log; resolver_ip: addr &log; ip_proto: count &log; transaction_id: count &log; query: string &log &optional; saw_reply: bool &log; rejected: bool &log; rcode: count &log &optional; rtt: double &log &optional; answer_count: count &log &optional; };
type EncryptedRec: record { seq: count &log; version: count &log; kind: string &log; event_time: time &log; uid: string &log; family: string &log; client_ip: addr &log; client_port: count &log; server_ip: addr &log; server_port: count &log; ip_proto: count &log; version_value: string &log &optional; cipher: string &log &optional; curve: string &log &optional; server_name: string &log &optional; alpn: string &log &optional; resumed: bool &log &optional; established: bool &log &optional; last_alert: string &log &optional; server_cert_fingerprint: string &log &optional; client_fingerprint: string &log &optional; };

event zeek_init()
    {
    Log::create_stream(FLOW_LOG, [$columns=FlowRec, $path="calibration_flow"]);
    Log::create_stream(TCP_LOG, [$columns=TcpRec, $path="calibration_tcp"]);
    Log::create_stream(DNS_QUERY_LOG, [$columns=DNSQueryRec, $path="calibration_dns_query"]);
    Log::create_stream(DNS_RESULT_LOG, [$columns=DNSResultRec, $path="calibration_dns_result"]);
    Log::create_stream(ENCRYPTED_LOG, [$columns=EncryptedRec, $path="calibration_encrypted"]);
    }

event FlowStream::flow_snapshot(version: count, kind: string, observed_at: time, uid: string, orig_h: addr, orig_p: count, resp_h: addr, resp_p: count, ip_proto: count, first_seen: time, last_seen: time, orig_pkts: count, orig_ip_bytes: count, orig_payload_bytes: count, resp_pkts: count, resp_ip_bytes: count, resp_payload_bytes: count, orig_state: count, resp_state: count, history: string)
    { ++sequence; Log::write(FLOW_LOG, [$seq=sequence, $version=version, $kind=kind, $observed_at=observed_at, $uid=uid, $orig_h=orig_h, $orig_p=orig_p, $resp_h=resp_h, $resp_p=resp_p, $ip_proto=ip_proto, $first_seen=first_seen, $last_seen=last_seen, $orig_pkts=orig_pkts, $orig_ip_bytes=orig_ip_bytes, $orig_payload_bytes=orig_payload_bytes, $resp_pkts=resp_pkts, $resp_ip_bytes=resp_ip_bytes, $resp_payload_bytes=resp_payload_bytes, $orig_state=orig_state, $resp_state=resp_state, $history=history]); }

event FlowStream::tcp_connection_signal(version: count, event_time: time, uid: string, kind: string, orig_h: addr, orig_p: count, resp_h: addr, resp_p: count, ip_proto: count, actor_role: string)
    { ++sequence; Log::write(TCP_LOG, [$seq=sequence, $version=version, $event_time=event_time, $uid=uid, $kind=kind, $orig_h=orig_h, $orig_p=orig_p, $resp_h=resp_h, $resp_p=resp_p, $ip_proto=ip_proto, $actor_role=actor_role]); }

event FlowStream::dns_query_observation(version: count, event_time: time, uid: string, source_ip: addr, source_port: count, resolver_ip: addr, resolver_port: count, ip_proto: count, transaction_id: count, query: string, qtype: count, qclass: count)
    { ++sequence; Log::write(DNS_QUERY_LOG, [$seq=sequence, $version=version, $event_time=event_time, $uid=uid, $source_ip=source_ip, $source_port=source_port, $resolver_ip=resolver_ip, $resolver_port=resolver_port, $ip_proto=ip_proto, $transaction_id=transaction_id, $query=query, $qtype=qtype, $qclass=qclass]); }

event FlowStream::dns_result_observation(version: count, query_time: time, result_time: time, uid: string, source_ip: addr, resolver_ip: addr, ip_proto: count, transaction_id: count, has_query: bool, query: string, saw_reply: bool, rejected: bool, has_rcode: bool, rcode: count, has_rtt: bool, rtt: double, has_answer_count: bool, answer_count: count)
    {
    ++sequence;
    local rec: DNSResultRec = [$seq=sequence, $version=version, $query_time=query_time, $result_time=result_time, $uid=uid, $source_ip=source_ip, $resolver_ip=resolver_ip, $ip_proto=ip_proto, $transaction_id=transaction_id, $saw_reply=saw_reply, $rejected=rejected];
    if ( has_query ) rec$query=query; if ( has_rcode ) rec$rcode=rcode; if ( has_rtt ) rec$rtt=rtt; if ( has_answer_count ) rec$answer_count=answer_count;
    Log::write(DNS_RESULT_LOG, rec);
    }

event FlowStream::encrypted_protocol_observation(version: count, kind: string, event_time: time, uid: string, family: string, client_ip: addr, client_port: count, server_ip: addr, server_port: count, ip_proto: count, has_version: bool, version_value: string, has_cipher: bool, cipher_value: string, has_curve: bool, curve_value: string, has_server_name: bool, server_name_value: string, has_alpn: bool, alpn_value: string, has_resumed: bool, resumed_value: bool, has_established: bool, established_value: bool, has_last_alert: bool, last_alert_value: string, has_server_cert_fingerprint: bool, server_cert_fingerprint_value: string, has_client_fingerprint: bool, client_fingerprint_value: string)
    {
    ++sequence;
    local rec: EncryptedRec = [$seq=sequence, $version=version, $kind=kind, $event_time=event_time, $uid=uid, $family=family, $client_ip=client_ip, $client_port=client_port, $server_ip=server_ip, $server_port=server_port, $ip_proto=ip_proto];
    if ( has_version ) rec$version_value=version_value; if ( has_cipher ) rec$cipher=cipher_value; if ( has_curve ) rec$curve=curve_value; if ( has_server_name ) rec$server_name=server_name_value; if ( has_alpn ) rec$alpn=alpn_value; if ( has_resumed ) rec$resumed=resumed_value; if ( has_established ) rec$established=established_value; if ( has_last_alert ) rec$last_alert=last_alert_value; if ( has_server_cert_fingerprint ) rec$server_cert_fingerprint=server_cert_fingerprint_value; if ( has_client_fingerprint ) rec$client_fingerprint=client_fingerprint_value;
    Log::write(ENCRYPTED_LOG, rec);
    }
