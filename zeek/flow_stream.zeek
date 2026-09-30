@load base/frameworks/cluster

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
}

module GLOBAL;

# Zeek 8.0.6 reads this optional global when it creates a connection. Defining
# it activates periodic connection_status_update events without handling every
# packet in script space.
global connection_status_update_interval: interval = FlowStream::snapshot_interval;

module FlowStream;

global publish_failures: count = 0;

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

event connection_status_update(c: connection)
	{
	publish_connection(c, "update");
	}

event connection_flipped(c: connection)
	{
	publish_connection(c, "flipped");
	}

event connection_state_remove(c: connection) &priority=0
	{
	publish_connection(c, "final");
	}

event zeek_done()
	{
	if ( publish_failures > 0 )
		Reporter::warning(fmt("%d flow snapshots were not accepted for publication",
		                      publish_failures));
	}
