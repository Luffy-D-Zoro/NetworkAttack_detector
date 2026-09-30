"""Run the direct Zeek event-to-flow/state pipeline."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from typing import TextIO

from src.coordinator import StreamingCoordinator
from src.flow.flow_manager import FlowManager
from src.ingestion.zeek_websocket import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_TOPIC,
    FlowSnapshot,
    iter_events,
    websocket_uri,
)

DEFAULT_INACTIVITY_TIMEOUT = 120.0
DEFAULT_CLEANUP_INTERVAL = 5.0
DEFAULT_INSPECTION_INTERVAL = 5.0
DEFAULT_CORRELATION_TIMEOUT = 300.0


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a number of seconds") from exc
    if seconds <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return seconds


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def print_active_flows(
    manager: FlowManager,
    observed_at: datetime,
    *,
    output: TextIO = sys.stdout,
) -> None:
    states = manager.inspect()
    payload = {
        "observed_at": _timestamp(observed_at),
        "active_flow_count": len(states),
        "active_flows": [state.to_dict() for state in states],
    }
    print(json.dumps(payload, sort_keys=True), file=output, flush=True)


def run_pipeline(
    *,
    uri: str,
    topic: str,
    inactivity_timeout: timedelta,
    cleanup_interval: timedelta,
    inspection_interval: timedelta,
    correlation_timeout: timedelta,
    output: TextIO = sys.stdout,
) -> None:
    if correlation_timeout < inactivity_timeout:
        raise ValueError("correlation timeout must be at least the inactivity timeout")

    manager = FlowManager(
        inactivity_timeout=inactivity_timeout,
        cleanup_interval=cleanup_interval,
    )
    coordinator = StreamingCoordinator(
        flow_manager=manager,
        correlation_timeout=correlation_timeout,
    )
    last_inspection_at: datetime | None = None

    for event in iter_events(uri, topic):
        coordinator.process(event)

        if not isinstance(event, FlowSnapshot):
            continue

        if (
            last_inspection_at is None
            or event.observed_at - last_inspection_at >= inspection_interval
        ):
            print_active_flows(manager, event.observed_at, output=output)
            last_inspection_at = event.observed_at


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.getenv("FLOW_STREAM_HOST", DEFAULT_HOST))
    parser.add_argument(
        "--port", type=_port, default=_port(os.getenv("FLOW_STREAM_PORT", str(DEFAULT_PORT)))
    )
    parser.add_argument("--topic", default=os.getenv("FLOW_STREAM_TOPIC", DEFAULT_TOPIC))
    parser.add_argument(
        "--inactivity-timeout",
        type=_positive_seconds,
        default=_positive_seconds(
            os.getenv("FLOW_INACTIVITY_TIMEOUT", str(DEFAULT_INACTIVITY_TIMEOUT))
        ),
        help="seconds without directional traffic before a flow expires",
    )
    parser.add_argument(
        "--cleanup-interval",
        type=_positive_seconds,
        default=_positive_seconds(
            os.getenv("FLOW_CLEANUP_INTERVAL", str(DEFAULT_CLEANUP_INTERVAL))
        ),
        help="minimum seconds between expiration scans",
    )
    parser.add_argument(
        "--inspection-interval",
        type=_positive_seconds,
        default=_positive_seconds(
            os.getenv("FLOW_INSPECTION_INTERVAL", str(DEFAULT_INSPECTION_INTERVAL))
        ),
        help="minimum seconds between active-flow JSON reports",
    )
    parser.add_argument(
        "--correlation-timeout",
        type=_positive_seconds,
        default=_positive_seconds(
            os.getenv("FLOW_CORRELATION_TIMEOUT", str(DEFAULT_CORRELATION_TIMEOUT))
        ),
        help="seconds to retain per-UID cumulative counter baselines",
    )
    args = parser.parse_args(argv)

    if args.correlation_timeout < args.inactivity_timeout:
        parser.error("--correlation-timeout must be at least --inactivity-timeout")

    try:
        run_pipeline(
            uri=websocket_uri(args.host, args.port),
            topic=args.topic,
            inactivity_timeout=timedelta(seconds=args.inactivity_timeout),
            cleanup_interval=timedelta(seconds=args.cleanup_interval),
            inspection_interval=timedelta(seconds=args.inspection_interval),
            correlation_timeout=timedelta(seconds=args.correlation_timeout),
        )
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
