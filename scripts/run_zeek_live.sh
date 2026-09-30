#!/usr/bin/env bash

set -euo pipefail

usage() {
    printf 'Usage: %s INTERFACE [OUTPUT_ROOT]\n' "${0##*/}"
    printf 'Runs Zeek in the foreground and writes each run to a new directory.\n'
}

if (( $# < 1 || $# > 2 )); then
    usage >&2
    exit 64
fi

interface=$1

if [[ ! "$interface" =~ ^[[:alnum:]_.:-]+$ ]] || [[ ! -e "/sys/class/net/$interface" ]]; then
    printf 'Error: network interface %q does not exist.\n' "$interface" >&2
    printf 'Available interfaces:\n' >&2
    for interface_path in /sys/class/net/*; do
        printf '  %s\n' "${interface_path##*/}" >&2
    done
    exit 66
fi

if ! zeek_bin=$(command -v zeek); then
    printf 'Error: zeek is not installed or is not available on PATH.\n' >&2
    exit 69
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/.." && pwd)
output_root=${2:-"$project_root/var/zeek"}
flow_stream_host=${FLOW_STREAM_HOST:-127.0.0.1}
flow_stream_port=${FLOW_STREAM_PORT:-9997}
flow_stream_topic=${FLOW_STREAM_TOPIC:-sih/flow/v1}
flow_stream_interval=${FLOW_STREAM_INTERVAL:-1sec}
flow_stream_policy=$project_root/zeek/flow_stream.zeek
run_id=$(date -u '+%Y%m%dT%H%M%SZ')-$$
run_dir=${output_root%/}/$run_id

if [[ ! "$flow_stream_port" =~ ^[0-9]+$ ]] ||
   (( flow_stream_port < 1 || flow_stream_port > 65535 )); then
    printf 'Error: FLOW_STREAM_PORT must be an integer between 1 and 65535.\n' >&2
    exit 64
fi

if [[ ! "$flow_stream_topic" =~ ^[[:alnum:]_./-]+$ ]]; then
    printf 'Error: FLOW_STREAM_TOPIC contains unsupported characters.\n' >&2
    exit 64
fi

mkdir -p -- "$run_dir"

printf 'Zeek: %s\n' "$("$zeek_bin" --version 2>&1)"
printf 'Interface: %s\n' "$interface"
printf 'Log directory: %s\n' "$run_dir"
printf 'Flow stream: ws://%s:%s/v1/messages/json (topic %s, interval %s)\n' \
    "$flow_stream_host" "$flow_stream_port" "$flow_stream_topic" "$flow_stream_interval"
printf 'Press Ctrl+C to stop Zeek.\n'

cd -- "$run_dir"

# -C is appropriate for local live capture where checksum offloading can make
# otherwise valid packets appear to have invalid checksums. Zeek's standard
# base scripts produce protocol logs such as conn.log, dns.log, and ssl.log
# when matching traffic is observed.
exec "$zeek_bin" -C -i "$interface" "$flow_stream_policy" \
    "FlowStream::listen_addr=$flow_stream_host" \
    "FlowStream::listen_port=${flow_stream_port}/tcp" \
    "FlowStream::topic=$flow_stream_topic" \
    "FlowStream::snapshot_interval=$flow_stream_interval"
