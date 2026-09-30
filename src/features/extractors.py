"""Deterministic extraction from the four Phase 3 Block A state systems."""

from __future__ import annotations

import math
import statistics
from collections import Counter
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Hashable, Iterable, Mapping, Sequence, TypeVar

from src.features.models import (
    BeaconFeatures,
    DDoSFeatures,
    DNSDomainFeatures,
    DNSFeatures,
    EncryptedTrafficFeatures,
    ExfilFeatures,
    ScanFeatures,
)
from src.states.beacon import BeaconKey, BeaconState, BeaconStateConfig
from src.states.ddos import DDoSState, DDoSStateConfig, SourceCounters
from src.states.dns import DNSDomainWindow, DNSState, DNSStateConfig
from src.states.encrypted import EncryptedKey, EncryptedState, EncryptedStateConfig
from src.states.exfil import ExfilKey, ExfilState, ExfilStateConfig, ExfilStateManager
from src.states.scan import ScanState, ScanStateConfig

Category = TypeVar("Category", bound=Hashable)


def _distribution(
    counts: Mapping[Category, int], total: int
) -> Mapping[Category, float] | None:
    if total <= 0:
        return None
    return MappingProxyType(
        {key: value / total for key, value in sorted(counts.items(), key=lambda item: str(item[0]))}
    )


def _entropy(counts: Iterable[int]) -> float | None:
    positive = [value for value in counts if value > 0]
    total = sum(positive)
    if total <= 0:
        return None
    return -sum((value / total) * math.log2(value / total) for value in positive)


def _ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator > 0 else None


def _mean(values: Sequence[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _variance(values: Sequence[float]) -> float | None:
    return statistics.pvariance(values) if len(values) >= 2 else None


def _moments(total: float, total_squares: float, count: int) -> tuple[float | None, float | None]:
    if count <= 0:
        return None, None
    mean = total / count
    if count < 2:
        return mean, None
    return mean, max(0.0, total_squares / count - mean * mean)


def _timing(values: Sequence[datetime]) -> tuple[float | None, float | None, float | None, float | None, float | None, float | None]:
    ordered = sorted(values)
    if len(ordered) < 2:
        return None, None, None, None, None, None
    intervals = [(right - left).total_seconds() for left, right in zip(ordered, ordered[1:])]
    mean = statistics.fmean(intervals)
    frequency = (len(ordered) - 1) / (ordered[-1] - ordered[0]).total_seconds() if ordered[-1] > ordered[0] else None
    if len(intervals) < 2:
        return frequency, mean, None, None, None, None
    variance = statistics.pvariance(intervals)
    stddev = math.sqrt(variance)
    coefficient = stddev / mean if mean > 0 else None
    jitter = None
    if len(intervals) >= 3:
        median = statistics.median(intervals)
        jitter = statistics.median(abs(value - median) for value in intervals)
    return frequency, mean, variance, stddev, coefficient, jitter


class DDoSFeatureExtractor:
    def __init__(self, config: DDoSStateConfig) -> None:
        self.config = config

    def extract(self, subject: object, state: DDoSState, timestamp: datetime) -> DDoSFeatures:
        buckets = tuple(state.buckets)
        seconds = self.config.window.total_seconds()
        packets = sum(bucket.packets for bucket in buckets)
        ip_bytes = sum(bucket.ip_bytes for bucket in buckets)
        starts = sum(bucket.connection_starts for bucket in buckets)
        syn_starts = sum(bucket.syn_starts for bucket in buckets)

        sources: dict[object, SourceCounters] = {}
        saturated = False
        overflow_packets = 0
        overflow_starts = 0
        overflow_unique_estimate = 0
        for bucket in buckets:
            saturated = saturated or bucket.observed_sources.saturated
            overflow_packets += bucket.source_overflow_packets
            overflow_starts += bucket.source_overflow_starts
            overflow_unique_estimate = max(overflow_unique_estimate, bucket.observed_sources.overflow_count)
            for source, counters in bucket.observed_sources.values.items():
                sources[source] = sources.get(source, SourceCounters()) + counters

        source_weights = [counter.packets for counter in sources.values()]
        overflow_weight = overflow_packets
        if sum(source_weights) + overflow_weight == 0:
            source_weights = [counter.connection_starts for counter in sources.values()]
            overflow_weight = overflow_starts
        if overflow_weight > 0:
            source_weights.append(overflow_weight)
        total_source_weight = sum(source_weights)

        protocol_packets: Counter[int] = Counter()
        protocol_bytes: Counter[int] = Counter()
        port_starts: Counter[int] = Counter()
        for bucket in buckets:
            protocol_packets.update(bucket.protocol_packets.values)
            protocol_bytes.update(bucket.protocol_bytes.values)
            port_starts.update(bucket.destination_ports.values)

        established = sum(bucket.tcp_established for bucket in buckets)
        rejected = sum(bucket.tcp_rejected for bucket in buckets)
        timed_out = sum(bucket.tcp_attempt_timeouts for bucket in buckets)
        reset_source = sum(bucket.tcp_resets_from_source for bucket in buckets)
        reset_destination = sum(bucket.tcp_resets_from_destination for bucket in buckets)
        reset_unknown = sum(bucket.tcp_resets_unknown for bucket in buckets)
        reset_total = reset_source + reset_destination + reset_unknown

        half = self.config.window / 2
        cutoff = timestamp - half
        start = timestamp - self.config.window
        recent_packets = sum(bucket.packets for bucket in buckets if bucket.bucket_start >= cutoff)
        prior_packets = sum(bucket.packets for bucket in buckets if start <= bucket.bucket_start < cutoff)
        recent_rate = recent_packets / half.total_seconds()
        prior_rate = prior_packets / half.total_seconds()

        return DDoSFeatures(
            subject=str(subject),
            timestamp=timestamp,
            packets_per_second=packets / seconds,
            bytes_per_second=ip_bytes / seconds,
            connection_starts_per_second=starts / seconds,
            unique_observed_source_estimate=len(sources) + overflow_unique_estimate,
            source_cardinality_saturated=saturated,
            observed_source_entropy=_entropy(source_weights),
            dominant_source_concentration=(max(source_weights) / total_source_weight if total_source_weight else None),
            udp_packet_fraction=_ratio(protocol_packets.get(17, 0), packets),
            udp_byte_fraction=_ratio(protocol_bytes.get(17, 0), ip_bytes),
            protocol_packet_distribution=_distribution(protocol_packets, packets),
            destination_port_concentration=(max(port_starts.values()) / starts if starts and port_starts else None),
            syn_starts_per_second=syn_starts / seconds,
            establishment_ratio=_ratio(established, syn_starts),
            rejection_ratio=_ratio(rejected, syn_starts),
            attempt_timeout_ratio=_ratio(timed_out, syn_starts),
            resets_from_source=reset_source,
            resets_from_destination=reset_destination,
            resets_unknown=reset_unknown,
            reset_from_source_fraction=_ratio(reset_source, reset_total),
            reset_from_destination_fraction=_ratio(reset_destination, reset_total),
            recent_packet_rate_acceleration=(recent_rate / prior_rate if prior_rate > 0 else None),
        )


class ScanFeatureExtractor:
    def __init__(self, config: ScanStateConfig) -> None:
        self.config = config

    def extract(self, subject: object, state: ScanState, timestamp: datetime) -> ScanFeatures:
        buckets = tuple(state.buckets)
        seconds = self.config.window.total_seconds()
        starts = sum(bucket.connection_starts for bucket in buckets)
        syn_starts = sum(bucket.syn_starts for bucket in buckets)
        destination_ips: set[object] = set()
        destination_ports: set[tuple[int, int]] = set()
        destination_pairs: set[bytes] = set()
        ip_overflow = port_overflow = pair_overflow = 0
        ip_saturated = port_saturated = pair_saturated = False
        protocols: Counter[int] = Counter()
        for bucket in buckets:
            destination_ips.update(bucket.destination_ips.values)
            destination_ports.update(bucket.destination_ports.values)
            destination_pairs.update(bucket.destination_pairs.digests)
            ip_overflow = max(ip_overflow, bucket.destination_ips.overflow_count)
            port_overflow = max(port_overflow, bucket.destination_ports.overflow_count)
            pair_overflow = max(pair_overflow, bucket.destination_pairs.overflow_count)
            ip_saturated = ip_saturated or bucket.destination_ips.saturated
            port_saturated = port_saturated or bucket.destination_ports.saturated
            pair_saturated = pair_saturated or bucket.destination_pairs.saturated
            protocols.update(bucket.protocol_starts.values)
        unique_ips = len(destination_ips) + ip_overflow
        unique_ports = len(destination_ports) + port_overflow
        unique_pairs = len(destination_pairs) + pair_overflow
        established = sum(bucket.tcp_established for bucket in buckets)
        rejected = sum(bucket.tcp_rejected for bucket in buckets)
        no_reply = sum(bucket.tcp_attempt_timeouts for bucket in buckets)
        resets = sum(bucket.tcp_resets for bucket in buckets)

        return ScanFeatures(
            subject=str(subject),
            timestamp=timestamp,
            attempts_per_second=starts / seconds,
            syn_starts_per_second=syn_starts / seconds,
            unique_destination_ip_estimate=unique_ips,
            unique_destination_port_estimate=unique_ports,
            unique_destination_pair_estimate=unique_pairs,
            destination_ip_saturated=ip_saturated,
            destination_port_saturated=port_saturated,
            destination_pair_saturated=pair_saturated,
            ip_fanout_per_second=unique_ips / seconds,
            port_fanout_per_second=unique_ports / seconds,
            horizontal_fanout_ratio=_ratio(unique_ips, unique_ports),
            vertical_fanout_ratio=_ratio(unique_ports, unique_ips),
            protocol_distribution=_distribution(protocols, starts),
            establishment_ratio=_ratio(established, syn_starts),
            rejection_ratio=_ratio(rejected, syn_starts),
            no_reply_ratio=_ratio(no_reply, syn_starts),
            reset_ratio=_ratio(resets, syn_starts),
            total_attempts=starts,
        )


class ExfilFeatureExtractor:
    def __init__(self, config: ExfilStateConfig) -> None:
        self.config = config

    def extract(self, key: ExfilKey, state: ExfilState, manager: ExfilStateManager, timestamp: datetime) -> ExfilFeatures:
        buckets = tuple(state.buckets)
        seconds = self.config.window.total_seconds()
        packets = sum(bucket.packets for bucket in buckets)
        ip_bytes = sum(bucket.ip_bytes for bucket in buckets)
        active = [bucket for bucket in buckets if bucket.packets > 0 or bucket.ip_bytes > 0]
        slot_count = max(1, math.ceil(self.config.window / self.config.bucket_width))
        width_seconds = self.config.bucket_width.total_seconds()
        rates = [bucket.ip_bytes / width_seconds for bucket in active]
        rates.extend([0.0] * max(0, slot_count - len(active)))
        variance = statistics.pvariance(rates) if len(rates) >= 2 else None
        mean_rate = statistics.fmean(rates) if rates else 0.0
        burstiness = math.sqrt(variance) / mean_rate if variance is not None and mean_rate > 0 else None
        protocols: Counter[int] = Counter()
        for bucket in buckets:
            protocols.update(bucket.protocol_bytes.values)
        duration = 0.0
        if active:
            duration = (max(bucket.bucket_start for bucket in active) - min(bucket.bucket_start for bucket in active)).total_seconds() + width_seconds

        reverse = manager.get_reverse(key)
        reverse_packets = reverse_bytes = 0
        if reverse is not None:
            reverse_packets = sum(bucket.packets for bucket in reverse.buckets)
            reverse_bytes = sum(bucket.ip_bytes for bucket in reverse.buckets)
        reverse_observed = reverse_packets > 0 or reverse_bytes > 0

        return ExfilFeatures(
            subject=f"{key[0]}->{key[1]}",
            timestamp=timestamp,
            bytes_per_second=ip_bytes / seconds,
            packets_per_second=packets / seconds,
            total_recent_bytes=ip_bytes,
            total_recent_packets=packets,
            active_bucket_count=len(active),
            active_time_fraction=len(active) / slot_count,
            sustained_transfer_duration_seconds=duration,
            byte_rate_variance=variance,
            byte_rate_burstiness=burstiness,
            protocol_byte_distribution=_distribution(protocols, ip_bytes),
            reverse_observed=reverse_observed,
            forward_to_reverse_byte_ratio=(
                _ratio(ip_bytes, reverse_bytes) if reverse_observed else None
            ),
            forward_to_reverse_packet_ratio=(
                _ratio(packets, reverse_packets) if reverse_observed else None
            ),
        )


class BeaconFeatureExtractor:
    def __init__(self, config: BeaconStateConfig) -> None:
        self.config = config

    def extract(self, key: BeaconKey, state: BeaconState, timestamp: datetime) -> BeaconFeatures:
        starts = tuple(state.connection_starts)
        episodes = tuple(state.episodes)
        completed = tuple(state.completed_connections)
        contact_frequency, contact_mean, contact_variance, contact_stddev, contact_cv, contact_jitter = _timing(starts)
        episode_frequency, episode_mean, episode_variance, episode_stddev, episode_cv, episode_jitter = _timing(tuple(sample.start_time for sample in episodes))
        episode_packets = [float(sample.packets) for sample in episodes]
        episode_bytes = [float(sample.ip_bytes) for sample in episodes]
        connection_packets = [float(sample.packets) for sample in completed]
        connection_bytes = [float(sample.ip_bytes) for sample in completed]
        durations = [sample.duration.total_seconds() for sample in completed]
        regularity = None if contact_cv is None else max(0.0, 1.0 - min(contact_cv, 1.0))

        return BeaconFeatures(
            subject=f"{key[0]}->{key[1]}:{key[2]}/{key[3]}",
            timestamp=timestamp,
            contact_count=len(starts),
            contact_frequency_per_second=contact_frequency,
            connection_interarrival_mean_seconds=contact_mean,
            connection_interarrival_variance=contact_variance,
            connection_interarrival_stddev=contact_stddev,
            connection_interarrival_coefficient_of_variation=contact_cv,
            connection_robust_jitter_seconds=contact_jitter,
            episode_count=len(episodes),
            episode_frequency_per_second=episode_frequency,
            episode_interarrival_mean_seconds=episode_mean,
            episode_interarrival_variance=episode_variance,
            episode_interarrival_stddev=episode_stddev,
            episode_interarrival_coefficient_of_variation=episode_cv,
            episode_robust_jitter_seconds=episode_jitter,
            episode_packet_mean=_mean(episode_packets),
            episode_packet_variance=_variance(episode_packets),
            episode_byte_mean=_mean(episode_bytes),
            episode_byte_variance=_variance(episode_bytes),
            completed_connection_count=len(completed),
            connection_packet_mean=_mean(connection_packets),
            connection_packet_variance=_variance(connection_packets),
            connection_byte_mean=_mean(connection_bytes),
            connection_byte_variance=_variance(connection_bytes),
            duration_mean_seconds=_mean(durations),
            duration_variance=_variance(durations),
            timing_regularity=regularity,
        )


class DNSFeatureExtractor:
    def __init__(self, config: DNSStateConfig) -> None:
        self.config = config

    def extract(self, subject: object, state: DNSState, timestamp: datetime) -> DNSFeatures:
        buckets = tuple(state.source_buckets)
        queries = sum(bucket.query_count for bucket in buckets)
        query_length_sum = sum(bucket.query_length_sum for bucket in buckets)
        query_length_squares = sum(bucket.query_length_sum_squares for bucket in buckets)
        query_length_mean, query_length_variance = _moments(
            query_length_sum, query_length_squares, queries
        )
        qtypes: Counter[int] = Counter()
        qclasses: Counter[int] = Counter()
        rcodes: Counter[int] = Counter()
        qnames: set[bytes] = set()
        domains: set[bytes] = set()
        qname_overflow = domain_overflow = 0
        qname_saturated = domain_saturated = False
        for bucket in buckets:
            qtypes.update(bucket.qtype_counts.values)
            qclasses.update(bucket.qclass_counts.values)
            rcodes.update(bucket.rcode_counts.values)
            qnames.update(bucket.unique_qname_hashes.digests)
            domains.update(bucket.unique_base_domain_hashes.digests)
            qname_overflow = max(qname_overflow, bucket.qname_hash_overflow)
            domain_overflow = max(domain_overflow, bucket.base_domain_hash_overflow)
            qname_saturated = qname_saturated or bucket.unique_qname_hashes.saturated
            domain_saturated = domain_saturated or bucket.unique_base_domain_hashes.saturated

        results = sum(bucket.result_count for bucket in buckets)
        replies = sum(bucket.reply_count for bucket in buckets)
        no_replies = sum(bucket.no_reply_count for bucket in buckets)
        rejected = sum(bucket.rejected_count for bucket in buckets)
        rtt_count = sum(bucket.rtt_count for bucket in buckets)
        rtt_sum = sum(bucket.rtt_sum for bucket in buckets)
        rtt_squares = sum(bucket.rtt_sum_squares for bucket in buckets)
        mean_rtt, rtt_variance = _moments(rtt_sum, rtt_squares, rtt_count)
        answer_total = sum(bucket.answer_count_sum for bucket in buckets)
        rcode_total = sum(rcodes.values())
        unique_domains = len(domains) + domain_overflow

        per_domain = {
            name: self._domain_features(name, window)
            for name, window in sorted(state.domains.items())
        }
        overflow_features = self._domain_features(
            "<overflow>", state.domain_overflow
        )
        if overflow_features.query_count == 0:
            overflow_features = None

        return DNSFeatures(
            subject=str(subject),
            timestamp=timestamp,
            total_queries=queries,
            queries_per_second=queries / self.config.source_window.total_seconds(),
            mean_query_length=query_length_mean,
            query_length_variance=query_length_variance,
            max_query_length=(
                max(bucket.max_query_length for bucket in buckets)
                if queries > 0
                else None
            ),
            mean_label_count=_ratio(
                sum(bucket.label_count_sum for bucket in buckets), queries
            ),
            malformed_query_ratio=_ratio(
                sum(bucket.malformed_query_count for bucket in buckets), queries
            ),
            qtype_distribution=_distribution(qtypes, sum(qtypes.values())),
            qclass_distribution=_distribution(qclasses, sum(qclasses.values())),
            unique_qname_estimate=len(qnames) + qname_overflow,
            unique_registrable_domain_estimate=unique_domains,
            qname_cardinality_saturated=qname_saturated,
            registrable_domain_cardinality_saturated=domain_saturated,
            source_domain_fanout_per_second=(
                unique_domains / self.config.source_window.total_seconds()
            ),
            result_count=results,
            rcode_distribution=_distribution(rcodes, rcode_total),
            nxdomain_ratio=_ratio(rcodes.get(3, 0), rcode_total),
            rejection_ratio=_ratio(rejected, results),
            no_reply_ratio=_ratio(no_replies, results),
            mean_rtt_seconds=mean_rtt,
            rtt_variance=rtt_variance,
            # Phase 2 retains only the answer sum, not an optional-field
            # presence count. Stay conservative when the sum is zero because
            # zero answers and absent answer metadata cannot be distinguished.
            answer_count_total=answer_total if answer_total > 0 else None,
            mean_answer_count_per_reply=(
                _ratio(answer_total, replies) if answer_total > 0 else None
            ),
            domain_features=MappingProxyType(per_domain),
            overflow_domain_features=overflow_features,
            domain_map_saturated=overflow_features is not None,
        )

    def _domain_features(
        self, name: str, window: DNSDomainWindow
    ) -> DNSDomainFeatures:
        buckets = tuple(window.buckets)
        queries = sum(bucket.query_count for bucket in buckets)
        length_mean, length_variance = _moments(
            sum(bucket.subdomain_length_sum for bucket in buckets),
            sum(bucket.subdomain_length_sum_squares for bucket in buckets),
            queries,
        )
        entropy_mean, entropy_variance = _moments(
            sum(bucket.subdomain_entropy_sum for bucket in buckets),
            sum(bucket.subdomain_entropy_sum_squares for bucket in buckets),
            queries,
        )
        subdomains: set[bytes] = set()
        overflow = 0
        saturated = False
        qtypes: Counter[int] = Counter()
        for bucket in buckets:
            subdomains.update(bucket.unique_subdomain_hashes.digests)
            overflow = max(overflow, bucket.subdomain_hash_overflow)
            saturated = saturated or bucket.unique_subdomain_hashes.saturated
            qtypes.update(bucket.qtype_counts.values)
        unique = len(subdomains) + overflow
        seconds = self.config.domain_window.total_seconds()
        return DNSDomainFeatures(
            registrable_domain=name,
            query_count=queries,
            queries_per_second=queries / seconds,
            mean_subdomain_length=length_mean,
            subdomain_length_variance=length_variance,
            max_subdomain_length=(
                max(bucket.max_subdomain_length for bucket in buckets)
                if queries > 0
                else None
            ),
            mean_subdomain_entropy=entropy_mean,
            subdomain_entropy_variance=entropy_variance,
            max_subdomain_entropy=(
                max(bucket.max_subdomain_entropy for bucket in buckets)
                if queries > 0
                else None
            ),
            unique_subdomain_estimate=unique,
            subdomain_cardinality_saturated=saturated,
            unique_subdomain_growth_per_second=unique / seconds,
            repetition_ratio=(
                max(0.0, 1.0 - unique / queries) if queries > 0 else None
            ),
            qtype_distribution=_distribution(qtypes, sum(qtypes.values())),
        )


class EncryptedTrafficFeatureExtractor:
    def __init__(self, config: EncryptedStateConfig) -> None:
        self.config = config

    def extract(
        self, key: EncryptedKey, state: EncryptedState, timestamp: datetime
    ) -> EncryptedTrafficFeatures:
        buckets = tuple(state.buckets)
        seconds = self.config.window.total_seconds()
        sessions = sum(bucket.session_starts for bucket in buckets)
        metadata_records = sum(bucket.metadata_records for bucket in buckets)
        c2s_packets = sum(bucket.client_to_server_packets for bucket in buckets)
        c2s_bytes = sum(bucket.client_to_server_ip_bytes for bucket in buckets)
        s2c_packets = sum(bucket.server_to_client_packets for bucket in buckets)
        s2c_bytes = sum(bucket.server_to_client_ip_bytes for bucket in buckets)

        completed = tuple(state.completed_sessions)
        durations = [sample.duration for sample in completed]
        session_packets = [
            sample.client_to_server_packets + sample.server_to_client_packets
            for sample in completed
        ]
        session_bytes = [
            sample.client_to_server_ip_bytes + sample.server_to_client_ip_bytes
            for sample in completed
        ]
        active_masks = [session.directions_observed_mask for session in state.active_sessions.values()]
        completed_masks = [sample.directions_observed_mask for sample in completed]
        c2s_observed = bool(
            c2s_packets
            or c2s_bytes
            or any(mask & 1 for mask in active_masks + completed_masks)
        )
        s2c_observed = bool(
            s2c_packets
            or s2c_bytes
            or any(mask & 2 for mask in active_masks + completed_masks)
        )

        versions, version_saturated = self._categories(buckets, "version_counts")
        ciphers, cipher_saturated = self._categories(buckets, "cipher_counts")
        curves, curve_saturated = self._categories(buckets, "curve_counts")
        alpns, alpn_saturated = self._categories(buckets, "alpn_counts")
        certificates, certificate_saturated = self._categories(
            buckets, "server_cert_fingerprints"
        )

        sni_hashes: set[bytes] = set()
        sni_overflow = 0
        sni_observations = 0
        sni_saturated = False
        certificate_values: set[str] = set()
        certificate_overflow = 0
        certificate_observations = 0
        for bucket in buckets:
            sni_hashes.update(bucket.server_name_hashes.values)
            sni_overflow = max(sni_overflow, bucket.server_name_hashes.overflow_count)
            sni_observations += sum(bucket.server_name_hashes.values.values())
            sni_observations += bucket.server_name_hashes.overflow_value
            sni_saturated = sni_saturated or bucket.server_name_hashes.saturated
            certificate_values.update(bucket.server_cert_fingerprints.values)
            certificate_overflow = max(
                certificate_overflow,
                bucket.server_cert_fingerprints.overflow_count,
            )
            certificate_observations += sum(
                bucket.server_cert_fingerprints.values.values()
            )
            certificate_observations += bucket.server_cert_fingerprints.overflow_value

        unique_sni = len(sni_hashes) + sni_overflow
        unique_certificates = len(certificate_values) + certificate_overflow
        established = sum(bucket.established_count for bucket in buckets)
        incomplete = sum(bucket.failed_or_incomplete_count for bucket in buckets)
        resumed = sum(bucket.resumed_count for bucket in buckets)
        alerts = sum(bucket.alert_count for bucket in buckets)
        outcomes = established + incomplete

        slot_count = max(1, math.ceil(self.config.window / self.config.bucket_width))
        active_bucket_count = sum(bucket.session_starts > 0 for bucket in buckets)
        width_seconds = self.config.bucket_width.total_seconds()
        start_rates = [bucket.session_starts / width_seconds for bucket in buckets]
        start_rates.extend([0.0] * max(0, slot_count - len(start_rates)))
        start_variance = _variance(start_rates)
        start_mean = statistics.fmean(start_rates) if start_rates else 0.0
        start_burstiness = (
            math.sqrt(start_variance) / start_mean
            if start_variance is not None and start_mean > 0
            else None
        )

        family = key[4]
        return EncryptedTrafficFeatures(
            subject=f"{key[0]}->{key[1]}:{key[2]}/{key[3]}/{family}",
            timestamp=timestamp,
            security_family=family,
            session_count=sessions,
            encrypted_sessions_per_second=sessions / seconds,
            active_session_count=len(state.active_sessions),
            client_to_server_observed=c2s_observed,
            server_to_client_observed=s2c_observed,
            client_to_server_packets_per_second=c2s_packets / seconds,
            client_to_server_bytes_per_second=c2s_bytes / seconds,
            server_to_client_packets_per_second=s2c_packets / seconds,
            server_to_client_bytes_per_second=s2c_bytes / seconds,
            client_to_server_byte_ratio=(
                _ratio(c2s_bytes, s2c_bytes)
                if c2s_observed and s2c_observed
                else None
            ),
            client_to_server_packet_ratio=(
                _ratio(c2s_packets, s2c_packets)
                if c2s_observed and s2c_observed
                else None
            ),
            completed_session_count=len(completed),
            mean_session_duration_seconds=_mean(durations),
            session_duration_variance=_variance(durations),
            max_session_duration_seconds=max(durations, default=None),
            mean_session_packets=_mean([float(value) for value in session_packets]),
            session_packet_variance=_variance(
                [float(value) for value in session_packets]
            ),
            max_session_packets=max(session_packets, default=None),
            mean_session_bytes=_mean([float(value) for value in session_bytes]),
            session_byte_variance=_variance(
                [float(value) for value in session_bytes]
            ),
            max_session_bytes=max(session_bytes, default=None),
            version_distribution=_distribution(versions, sum(versions.values())),
            cipher_distribution=_distribution(ciphers, sum(ciphers.values())),
            curve_distribution=_distribution(curves, sum(curves.values())),
            alpn_distribution=_distribution(alpns, sum(alpns.values())),
            categorical_saturated=any(
                (version_saturated, cipher_saturated, curve_saturated, alpn_saturated)
            ),
            unique_sni_estimate=unique_sni,
            sni_cardinality_saturated=sni_saturated,
            sni_repetition_ratio=(
                max(0.0, 1.0 - unique_sni / sni_observations)
                if sni_observations > 0
                else None
            ),
            missing_sni_ratio=(
                max(0.0, 1.0 - min(sni_observations, sessions) / sessions)
                if sessions > 0
                else None
            ),
            certificate_fingerprint_distribution=_distribution(
                certificates, sum(certificates.values())
            ),
            unique_certificate_fingerprint_count=unique_certificates,
            certificate_cardinality_saturated=certificate_saturated,
            certificate_fingerprint_novelty_ratio=_ratio(
                unique_certificates, certificate_observations
            ),
            dominant_certificate_fingerprint_ratio=(
                max(certificates.values()) / certificate_observations
                if certificates and certificate_observations > 0
                else None
            ),
            establishment_ratio=_ratio(established, outcomes),
            resumption_ratio=(
                _ratio(resumed, sessions)
                if family in {"tls", "dtls"}
                and sessions > 0
                and metadata_records >= sessions
                else None
            ),
            alert_ratio=_ratio(alerts, metadata_records),
            incomplete_ratio=_ratio(incomplete, outcomes),
            repeated_service_active_bucket_count=active_bucket_count,
            repeated_service_active_time_fraction=active_bucket_count / slot_count,
            session_start_rate_variance=start_variance,
            session_start_burstiness=start_burstiness,
        )

    @staticmethod
    def _categories(
        buckets: Sequence[object], attribute: str
    ) -> tuple[Counter[str], bool]:
        values: Counter[str] = Counter()
        saturated = False
        for bucket in buckets:
            counter = getattr(bucket, attribute)
            values.update(counter.values)
            saturated = saturated or counter.saturated
        return values, saturated
