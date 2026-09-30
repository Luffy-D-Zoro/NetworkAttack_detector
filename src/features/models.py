"""Immutable feature objects for Phase 3 statistical/rule detectors."""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
from typing import Mapping


@dataclass(frozen=True, slots=True)
class FeatureObject:
    subject: str
    timestamp: datetime

    def available_features(self) -> tuple[str, ...]:
        unavailable = {"subject", "timestamp"}
        return tuple(
            field.name
            for field in fields(self)
            if field.name not in unavailable and getattr(self, field.name) is not None
        )


@dataclass(frozen=True, slots=True)
class DDoSFeatures(FeatureObject):
    packets_per_second: float
    bytes_per_second: float
    connection_starts_per_second: float
    unique_observed_source_estimate: int
    source_cardinality_saturated: bool
    observed_source_entropy: float | None
    dominant_source_concentration: float | None
    udp_packet_fraction: float | None
    udp_byte_fraction: float | None
    protocol_packet_distribution: Mapping[int, float] | None
    destination_port_concentration: float | None
    syn_starts_per_second: float
    establishment_ratio: float | None
    rejection_ratio: float | None
    attempt_timeout_ratio: float | None
    resets_from_source: int
    resets_from_destination: int
    resets_unknown: int
    reset_from_source_fraction: float | None
    reset_from_destination_fraction: float | None
    recent_packet_rate_acceleration: float | None


@dataclass(frozen=True, slots=True)
class ScanFeatures(FeatureObject):
    attempts_per_second: float
    syn_starts_per_second: float
    unique_destination_ip_estimate: int
    unique_destination_port_estimate: int
    unique_destination_pair_estimate: int
    destination_ip_saturated: bool
    destination_port_saturated: bool
    destination_pair_saturated: bool
    ip_fanout_per_second: float
    port_fanout_per_second: float
    horizontal_fanout_ratio: float | None
    vertical_fanout_ratio: float | None
    protocol_distribution: Mapping[int, float] | None
    establishment_ratio: float | None
    rejection_ratio: float | None
    no_reply_ratio: float | None
    reset_ratio: float | None
    total_attempts: int


@dataclass(frozen=True, slots=True)
class ExfilFeatures(FeatureObject):
    bytes_per_second: float
    packets_per_second: float
    total_recent_bytes: int
    total_recent_packets: int
    active_bucket_count: int
    active_time_fraction: float
    sustained_transfer_duration_seconds: float
    byte_rate_variance: float | None
    byte_rate_burstiness: float | None
    protocol_byte_distribution: Mapping[int, float] | None
    reverse_observed: bool
    forward_to_reverse_byte_ratio: float | None
    forward_to_reverse_packet_ratio: float | None


@dataclass(frozen=True, slots=True)
class BeaconFeatures(FeatureObject):
    contact_count: int
    contact_frequency_per_second: float | None
    connection_interarrival_mean_seconds: float | None
    connection_interarrival_variance: float | None
    connection_interarrival_stddev: float | None
    connection_interarrival_coefficient_of_variation: float | None
    connection_robust_jitter_seconds: float | None
    episode_count: int
    episode_frequency_per_second: float | None
    episode_interarrival_mean_seconds: float | None
    episode_interarrival_variance: float | None
    episode_interarrival_stddev: float | None
    episode_interarrival_coefficient_of_variation: float | None
    episode_robust_jitter_seconds: float | None
    episode_packet_mean: float | None
    episode_packet_variance: float | None
    episode_byte_mean: float | None
    episode_byte_variance: float | None
    completed_connection_count: int
    connection_packet_mean: float | None
    connection_packet_variance: float | None
    connection_byte_mean: float | None
    connection_byte_variance: float | None
    duration_mean_seconds: float | None
    duration_variance: float | None
    timing_regularity: float | None


@dataclass(frozen=True, slots=True)
class DNSDomainFeatures:
    registrable_domain: str
    query_count: int
    queries_per_second: float
    mean_subdomain_length: float | None
    subdomain_length_variance: float | None
    max_subdomain_length: int | None
    mean_subdomain_entropy: float | None
    subdomain_entropy_variance: float | None
    max_subdomain_entropy: float | None
    unique_subdomain_estimate: int
    subdomain_cardinality_saturated: bool
    unique_subdomain_growth_per_second: float
    repetition_ratio: float | None
    qtype_distribution: Mapping[int, float] | None


@dataclass(frozen=True, slots=True)
class DNSFeatures(FeatureObject):
    total_queries: int
    queries_per_second: float
    mean_query_length: float | None
    query_length_variance: float | None
    max_query_length: int | None
    mean_label_count: float | None
    malformed_query_ratio: float | None
    qtype_distribution: Mapping[int, float] | None
    qclass_distribution: Mapping[int, float] | None
    unique_qname_estimate: int
    unique_registrable_domain_estimate: int
    qname_cardinality_saturated: bool
    registrable_domain_cardinality_saturated: bool
    source_domain_fanout_per_second: float
    result_count: int
    rcode_distribution: Mapping[int, float] | None
    nxdomain_ratio: float | None
    rejection_ratio: float | None
    no_reply_ratio: float | None
    mean_rtt_seconds: float | None
    rtt_variance: float | None
    answer_count_total: int | None
    mean_answer_count_per_reply: float | None
    domain_features: Mapping[str, DNSDomainFeatures]
    overflow_domain_features: DNSDomainFeatures | None
    domain_map_saturated: bool


@dataclass(frozen=True, slots=True)
class EncryptedTrafficFeatures(FeatureObject):
    security_family: str
    session_count: int
    encrypted_sessions_per_second: float
    active_session_count: int
    client_to_server_observed: bool
    server_to_client_observed: bool
    client_to_server_packets_per_second: float
    client_to_server_bytes_per_second: float
    server_to_client_packets_per_second: float
    server_to_client_bytes_per_second: float
    client_to_server_byte_ratio: float | None
    client_to_server_packet_ratio: float | None
    completed_session_count: int
    mean_session_duration_seconds: float | None
    session_duration_variance: float | None
    max_session_duration_seconds: float | None
    mean_session_packets: float | None
    session_packet_variance: float | None
    max_session_packets: int | None
    mean_session_bytes: float | None
    session_byte_variance: float | None
    max_session_bytes: int | None
    version_distribution: Mapping[str, float] | None
    cipher_distribution: Mapping[str, float] | None
    curve_distribution: Mapping[str, float] | None
    alpn_distribution: Mapping[str, float] | None
    categorical_saturated: bool
    unique_sni_estimate: int
    sni_cardinality_saturated: bool
    sni_repetition_ratio: float | None
    missing_sni_ratio: float | None
    certificate_fingerprint_distribution: Mapping[str, float] | None
    unique_certificate_fingerprint_count: int
    certificate_cardinality_saturated: bool
    certificate_fingerprint_novelty_ratio: float | None
    dominant_certificate_fingerprint_ratio: float | None
    establishment_ratio: float | None
    resumption_ratio: float | None
    alert_ratio: float | None
    incomplete_ratio: float | None
    repeated_service_active_bucket_count: int
    repeated_service_active_time_fraction: float
    session_start_rate_variance: float | None
    session_start_burstiness: float | None
