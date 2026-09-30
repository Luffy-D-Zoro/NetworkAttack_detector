@load base/frameworks/cluster
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/quic

module FlowStream;

export {
	const topic = "sih/flow/v1" &redef;
	const listen_addr = 127.0.0.1 &redef;
	const listen_port = 9997/tcp &redef;
	const snapshot_interval = 1sec &redef;
	const schema_version: count = 1;

	global flow_snapshot: event(
		version: count,
		kind: string,
		observed_at: time,
		uid: string,
		orig_h: addr,
		orig_p: count,
		resp_h: addr,
		resp_p: count,
		ip_proto: count,
		first_seen: time,
		last_seen: time,
		orig_pkts: count,
		orig_ip_bytes: count,
		orig_payload_bytes: count,
		resp_pkts: count,
		resp_ip_bytes: count,
		resp_payload_bytes: count,
		orig_state: count,
		resp_state: count,
		history: string);

	global tcp_connection_signal: event(
		version: count,
		event_time: time,
		zeek_uid: string,
		kind: string,
		orig_h: addr,
		orig_p: count,
		resp_h: addr,
		resp_p: count,
		ip_protocol: count,
		actor_role: string);

	global dns_query_observation: event(
		version: count, event_time: time, zeek_uid: string,
		source_ip: addr, source_port: count,
		resolver_ip: addr, resolver_port: count, ip_protocol: count,
		transaction_id: count, query: string, qtype: count, qclass: count);

	global dns_result_observation: event(
		version: count, query_time: time, result_time: time, zeek_uid: string,
		source_ip: addr, resolver_ip: addr, ip_protocol: count,
		transaction_id: count, has_query: bool, query: string,
		saw_reply: bool, rejected: bool, has_rcode: bool, rcode: count,
		has_rtt: bool, rtt: double,
		has_answer_count: bool, answer_count: count);

	global encrypted_protocol_observation: event(
		version: count, kind: string, event_time: time, zeek_uid: string,
		security_family: string, client_ip: addr, client_port: count,
		server_ip: addr, server_port: count, ip_protocol: count,
		has_version: bool, version_value: string,
		has_cipher: bool, cipher_value: string,
		has_curve: bool, curve_value: string,
		has_server_name: bool, server_name_value: string,
		has_alpn: bool, alpn_value: string,
		has_resumed: bool, resumed_value: bool,
		has_established: bool, established_value: bool,
		has_last_alert: bool, last_alert_value: string,
		has_server_cert_fingerprint: bool, server_cert_fingerprint_value: string,
		has_client_fingerprint: bool, client_fingerprint_value: string);
}

module GLOBAL;

# Zeek 8.0.6 reads this optional global when it creates a connection. Defining
# it activates periodic connection_status_update events without handling every
# packet in script space.
global connection_status_update_interval: interval = FlowStream::snapshot_interval;

module FlowStream;

global publish_failures: count = 0;
const protocol_correlation_lifetime = 10min &redef;
global encrypted_identified: set[string] &write_expire=protocol_correlation_lifetime;
global encrypted_family: table[string] of string &write_expire=protocol_correlation_lifetime;
global quic_client_is_orig: table[string] of bool &write_expire=protocol_correlation_lifetime;

function publish_encrypted(
	kind: string, event_time: time, uid: string, family: string,
	client_h: addr, client_p: port, server_h: addr, server_p: port, proto: count,
	has_version: bool, version_value: string,
	has_cipher: bool, cipher_value: string,
	has_curve: bool, curve_value: string,
	has_server_name: bool, server_name_value: string,
	has_alpn: bool, alpn_value: string,
	has_resumed: bool, resumed_value: bool,
	has_established: bool, established_value: bool,
	has_last_alert: bool, last_alert_value: string,
	has_server_cert_fingerprint: bool, server_cert_fingerprint_value: string)
	{
	if ( ! Cluster::publish(topic, encrypted_protocol_observation,
	                       schema_version, kind, event_time, uid, family,
	                       client_h, port_to_count(client_p),
	                       server_h, port_to_count(server_p), proto,
	                       has_version, version_value, has_cipher, cipher_value,
	                       has_curve, curve_value, has_server_name, server_name_value,
	                       has_alpn, alpn_value, has_resumed, resumed_value,
	                       has_established, established_value,
	                       has_last_alert, last_alert_value,
	                       has_server_cert_fingerprint, server_cert_fingerprint_value,
	                       F, "") )
		++publish_failures;
	}

function publish_connection(c: connection, kind: string)
	{
	local orig_pkts = c$orig?$num_pkts ? c$orig$num_pkts : 0;
	local orig_ip_bytes = c$orig?$num_bytes_ip ? c$orig$num_bytes_ip : 0;
	local resp_pkts = c$resp?$num_pkts ? c$resp$num_pkts : 0;
	local resp_ip_bytes = c$resp?$num_bytes_ip ? c$resp$num_bytes_ip : 0;

	if ( ! Cluster::publish(topic, flow_snapshot,
	                       schema_version, kind, network_time(), c$uid,
	                       c$id$orig_h, port_to_count(c$id$orig_p),
	                       c$id$resp_h, port_to_count(c$id$resp_p), c$id$proto,
	                       c$start_time, c$start_time + c$duration,
	                       orig_pkts, orig_ip_bytes, c$orig$size,
	                       resp_pkts, resp_ip_bytes, c$resp$size,
	                       c$orig$state, c$resp$state, c$history) )
		++publish_failures;
	}

function publish_tcp_signal(c: connection, kind: string, actor_role: string)
	{
	if ( c$id$proto != 6 )
		return;

	if ( ! Cluster::publish(topic, tcp_connection_signal,
	                       schema_version, network_time(), c$uid, kind,
	                       c$id$orig_h, port_to_count(c$id$orig_p),
	                       c$id$resp_h, port_to_count(c$id$resp_p),
	                       c$id$proto, actor_role) )
		++publish_failures;
	}

event zeek_init()
	{
	if ( ! Cluster::listen_websocket([
		$listen_addr=listen_addr,
		$listen_port=listen_port,
	]) )
		Reporter::fatal(fmt("failed to listen for flow snapshots on %s:%s",
		                    listen_addr, listen_port));

	}

event new_connection(c: connection) &priority=-1
	{
	publish_connection(c, "open");

	# new_connection runs once. The strict state/history check deliberately
	# represents a unique connection-level SYN start, not a packet count.
	if ( c$id$proto == 6 && c$orig$state == TCP_SYN_SENT && c$history == "S" )
		publish_tcp_signal(c, "syn_start", "unknown");
	}

event connection_established(c: connection)
	{
	publish_tcp_signal(c, "established", "unknown");
	}

event connection_attempt(c: connection)
	{
	publish_tcp_signal(c, "attempt_timeout", "unknown");
	}

event connection_rejected(c: connection)
	{
	publish_tcp_signal(c, "rejected", "unknown");
	}

event connection_reset(c: connection)
	{
	local actor_role = "unknown";
	if ( c$orig$state == TCP_RESET && c$resp$state != TCP_RESET )
		actor_role = "orig";
	else if ( c$resp$state == TCP_RESET && c$orig$state != TCP_RESET )
		actor_role = "resp";

	publish_tcp_signal(c, "reset", actor_role);
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=-5
	{
	if ( ! Cluster::publish(topic, dns_query_observation,
	                       schema_version, network_time(), c$uid,
	                       c$id$orig_h, port_to_count(c$id$orig_p),
	                       c$id$resp_h, port_to_count(c$id$resp_p), c$id$proto,
	                       msg$id, query, qtype, qclass) )
		++publish_failures;
	}

event DNS::log_dns(rec: DNS::Info)
	{
	# The versioned schema requires a real transaction ID; do not invent a
	# sentinel for unusual incomplete records where Zeek has none.
	if ( ! rec?$trans_id )
		return;
	local trans_id = rec$trans_id;
	local query_value = "";
	local rcode_value: count = 0;
	local rtt_value: double = 0.0;
	local answer_count_value: count = 0;
	local ip_protocol: count = rec$proto == tcp ? 6 : 17;
	if ( rec?$query ) query_value = rec$query;
	if ( rec?$rcode ) rcode_value = rec$rcode;
	if ( rec?$rtt ) rtt_value = interval_to_double(rec$rtt);
	if ( rec?$total_answers ) answer_count_value = rec$total_answers;
	if ( ! Cluster::publish(topic, dns_result_observation,
	                       schema_version, rec$ts, network_time(), rec$uid,
	                       rec$id$orig_h, rec$id$resp_h, ip_protocol, trans_id,
	                       rec?$query && query_value != "", query_value,
	                       rec$saw_reply, rec$rejected, rec?$rcode, rcode_value,
	                       rec?$rtt, rtt_value,
	                       rec?$total_answers, answer_count_value) )
		++publish_failures;
	}

event ssl_client_hello(c: connection, version: count, record_version: count,
	possible_ts: time, client_random: string, session_id: string,
	ciphers: index_vec, comp_methods: index_vec) &priority=-5
	{
	if ( c?$quic || c$uid in encrypted_identified )
		return;
	add encrypted_identified[c$uid];
	local family = c$id$proto == 17 ? "dtls" : "tls";
	encrypted_family[c$uid] = family;
	local client_h = c$id$orig_h;
	local client_p = c$id$orig_p;
	local server_h = c$id$resp_h;
	local server_p = c$id$resp_p;
	if ( c?$ssl && /^\^/ in c$ssl$ssl_history )
		{
		client_h = c$id$resp_h; client_p = c$id$resp_p;
		server_h = c$id$orig_h; server_p = c$id$orig_p;
		}
	publish_encrypted("identified", network_time(), c$uid, family,
	                  client_h, client_p, server_h, server_p, c$id$proto,
	                  F, "", F, "", F, "", F, "", F, "",
	                  F, F, F, F, F, "", F, "");
	}

event QUIC::initial_packet(c: connection, is_orig: bool, version: count,
	dcid: string, scid: string) &priority=-5
	{
	if ( c$uid in encrypted_identified )
		return;
	add encrypted_identified[c$uid];
	encrypted_family[c$uid] = "quic";
	quic_client_is_orig[c$uid] = is_orig;
	local client_h = is_orig ? c$id$orig_h : c$id$resp_h;
	local client_p = is_orig ? c$id$orig_p : c$id$resp_p;
	local server_h = is_orig ? c$id$resp_h : c$id$orig_h;
	local server_p = is_orig ? c$id$resp_p : c$id$orig_p;
	publish_encrypted("identified", network_time(), c$uid, "quic",
	                  client_h, client_p, server_h, server_p, c$id$proto,
	                  T, QUIC::version_strings[version], F, "", F, "", F, "", F, "",
	                  F, F, F, F, F, "", F, "");
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	if ( rec$uid in encrypted_family && encrypted_family[rec$uid] == "quic" )
		return;
	local client_h = rec$id$orig_h;
	local client_p = rec$id$orig_p;
	local server_h = rec$id$resp_h;
	local server_p = rec$id$resp_p;
	if ( /^\^/ in rec$ssl_history )
		{
		client_h = rec$id$resp_h; client_p = rec$id$resp_p;
		server_h = rec$id$orig_h; server_p = rec$id$orig_p;
		}
	local family = rec$id$proto == 17 ? "dtls" : "tls";
	local version_value = rec?$version ? rec$version : "";
	local cipher_value = rec?$cipher ? rec$cipher : "";
	local curve_value = rec?$curve ? rec$curve : "";
	local server_name_value = rec?$server_name ? rec$server_name : "";
	local alpn_value = rec?$next_protocol ? rec$next_protocol : "";
	local alert_value = rec?$last_alert ? rec$last_alert : "";
	local cert_value = "";
	if ( rec?$cert_chain_fps && |rec$cert_chain_fps| > 0 )
		cert_value = rec$cert_chain_fps[0];
	publish_encrypted("metadata", network_time(), rec$uid, family,
	                  client_h, client_p, server_h, server_p, rec$id$proto,
	                  rec?$version && version_value != "", version_value,
	                  rec?$cipher && cipher_value != "", cipher_value,
	                  rec?$curve && curve_value != "", curve_value,
	                  rec?$server_name && server_name_value != "", server_name_value,
	                  rec?$next_protocol && alpn_value != "", alpn_value,
	                  T, rec$resumed, T, rec$established,
	                  rec?$last_alert && alert_value != "", alert_value,
	                  cert_value != "", cert_value);
	}

event QUIC::log_quic(rec: QUIC::Info)
	{
	local is_orig = rec$uid in quic_client_is_orig ? quic_client_is_orig[rec$uid] : T;
	local client_h = is_orig ? rec$id$orig_h : rec$id$resp_h;
	local client_p = is_orig ? rec$id$orig_p : rec$id$resp_p;
	local server_h = is_orig ? rec$id$resp_h : rec$id$orig_h;
	local server_p = is_orig ? rec$id$resp_p : rec$id$orig_p;
	local server_name_value = rec?$server_name ? rec$server_name : "";
	local alpn_value = rec?$client_protocol ? rec$client_protocol : "";
	# Lowercase history letters are server-side observations. A client-only
	# Initial/Hello must not be presented as completed establishment.
	local established_value = /[hs]/ in rec$history;
	publish_encrypted("metadata", network_time(), rec$uid, "quic",
	                  client_h, client_p, server_h, server_p, 17,
	                  rec$version != "", rec$version, F, "", F, "",
	                  rec?$server_name && server_name_value != "", server_name_value,
	                  rec?$client_protocol && alpn_value != "", alpn_value,
	                  F, F, T, established_value, F, "", F, "");
	}

event connection_status_update(c: connection)
	{
	publish_connection(c, "update");
	}

event connection_flipped(c: connection)
	{
	publish_connection(c, "flipped");
	}

event connection_state_remove(c: connection) &priority=-10
	{
	publish_connection(c, "final");
	}

event zeek_done()
	{
	if ( publish_failures > 0 )
		Reporter::warning(fmt("%d flow snapshots were not accepted for publication",
		                      publish_failures));
	}
