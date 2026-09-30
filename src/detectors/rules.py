"""Configurable explainable prototype rules for four Phase 3 families."""

from __future__ import annotations

import math
from dataclasses import dataclass

from src.detectors.models import DetectorResult
from src.features.models import (
    BeaconFeatures,
    DDoSFeatures,
    DNSFeatures,
    EncryptedTrafficFeatures,
    ExfilFeatures,
    FeatureObject,
    ScanFeatures,
)


def _result(
    detector: str,
    features: FeatureObject,
    *,
    signals: tuple[tuple[bool, str], ...],
    trigger_score: float,
    minimum_evidence: int,
    required: bool,
    extra_evidence: tuple[str, ...] = (),
) -> DetectorResult:
    matched = tuple(message for condition, message in signals if condition)
    score = len(matched) / len(signals) if signals else 0.0
    triggered = required and len(matched) >= minimum_evidence and score >= trigger_score
    return DetectorResult(
        detector=detector,
        subject=features.subject,
        timestamp=features.timestamp,
        score=score,
        triggered=triggered,
        disposition="suspicious" if triggered else "benign_like",
        evidence=matched + extra_evidence,
        available_features=features.available_features(),
    )


def _insufficient(detector: str, features: FeatureObject, reason: str) -> DetectorResult:
    return DetectorResult(
        detector=detector,
        subject=features.subject,
        timestamp=features.timestamp,
        score=0.0,
        triggered=False,
        disposition="insufficient_data",
        evidence=(reason,),
        available_features=features.available_features(),
    )


def _validate_common(trigger_score: float, minimum_evidence: int) -> None:
    if not 0.0 <= trigger_score <= 1.0:
        raise ValueError("trigger score must be between zero and one")
    if minimum_evidence <= 0:
        raise ValueError("minimum evidence must be positive")


@dataclass(frozen=True, slots=True)
class DDoSDetectorConfig:
    minimum_packet_rate_for_evaluation: float = 1.0
    minimum_connection_rate_for_evaluation: float = 0.1
    packet_rate_threshold: float = 1_000.0
    byte_rate_threshold: float = 1_000_000.0
    observed_source_threshold: int = 50
    minimum_source_entropy: float = 3.0
    maximum_dominant_source_concentration: float = 0.25
    connection_rate_threshold: float = 20.0
    syn_rate_threshold: float = 20.0
    maximum_establishment_ratio: float = 0.5
    minimum_failure_ratio: float = 0.3
    udp_fraction_threshold: float = 0.7
    acceleration_threshold: float = 2.0
    trigger_score: float = 0.5
    minimum_evidence: int = 2


class DDoSDetector:
    name = "ddos_statistical"

    def __init__(self, config: DDoSDetectorConfig | None = None) -> None:
        self.config = config or DDoSDetectorConfig()
        _validate_common(self.config.trigger_score, self.config.minimum_evidence)

    def detect(self, features: DDoSFeatures) -> DetectorResult:
        estimated_packets = features.packets_per_second
        estimated_starts = features.connection_starts_per_second
        if estimated_packets < 0 or estimated_starts < 0:
            raise ValueError("rates must not be negative")
        if (
            features.packets_per_second < self.config.minimum_packet_rate_for_evaluation
            and features.connection_starts_per_second
            < self.config.minimum_connection_rate_for_evaluation
        ):
            return _insufficient(self.name, features, "too little recent packet/connection evidence")

        distributed = (
            features.unique_observed_source_estimate >= self.config.observed_source_threshold
            and features.observed_source_entropy is not None
            and features.observed_source_entropy >= self.config.minimum_source_entropy
            and features.dominant_source_concentration is not None
            and features.dominant_source_concentration <= self.config.maximum_dominant_source_concentration
        )
        failure_ratio = sum(
            value for value in (features.rejection_ratio, features.attempt_timeout_ratio) if value is not None
        )
        signals = (
            (
                features.packets_per_second >= self.config.packet_rate_threshold
                or features.bytes_per_second >= self.config.byte_rate_threshold,
                f"high destination volume ({features.packets_per_second:.2f} packets/s, {features.bytes_per_second:.2f} bytes/s)",
            ),
            (
                distributed,
                f"distributed observed-source profile ({features.unique_observed_source_estimate} sources, entropy {features.observed_source_entropy})",
            ),
            (
                features.connection_starts_per_second >= self.config.connection_rate_threshold
                or features.syn_starts_per_second >= self.config.syn_rate_threshold,
                f"high connection/SYN pressure ({features.connection_starts_per_second:.2f}/{features.syn_starts_per_second:.2f} per second)",
            ),
            (
                (features.establishment_ratio is not None and features.establishment_ratio <= self.config.maximum_establishment_ratio)
                and failure_ratio >= self.config.minimum_failure_ratio,
                f"low establishment with failures (establishment={features.establishment_ratio}, failure={failure_ratio:.3f})",
            ),
            (
                features.udp_packet_fraction is not None
                and features.udp_packet_fraction >= self.config.udp_fraction_threshold
                and features.packets_per_second >= self.config.packet_rate_threshold,
                f"UDP-dominant high-rate traffic ({features.udp_packet_fraction:.3f} packet fraction)",
            ),
            (
                features.recent_packet_rate_acceleration is not None
                and features.recent_packet_rate_acceleration >= self.config.acceleration_threshold,
                "recent packet-rate acceleration "
                f"({features.recent_packet_rate_acceleration:.2f}x)"
                if features.recent_packet_rate_acceleration is not None
                else "recent packet-rate acceleration unavailable",
            ),
        )
        saturation = ("observed-source cardinality saturated; estimate is lower-confidence",) if features.source_cardinality_saturated else ()
        return _result(
            self.name,
            features,
            signals=signals,
            trigger_score=self.config.trigger_score,
            minimum_evidence=self.config.minimum_evidence,
            required=distributed,
            extra_evidence=saturation,
        )


@dataclass(frozen=True, slots=True)
class ScanDetectorConfig:
    minimum_attempts: int = 20
    attempts_per_second_threshold: float = 1.0
    syn_starts_per_second_threshold: float = 1.0
    unique_destination_pair_threshold: int = 30
    horizontal_destination_ip_threshold: int = 20
    horizontal_ratio_threshold: float = 3.0
    vertical_destination_port_threshold: int = 20
    vertical_ratio_threshold: float = 3.0
    maximum_establishment_ratio: float = 0.4
    minimum_failure_ratio: float = 0.4
    trigger_score: float = 0.4
    minimum_evidence: int = 2


class ScanDetector:
    name = "scan_statistical"

    def __init__(self, config: ScanDetectorConfig | None = None) -> None:
        self.config = config or ScanDetectorConfig()
        _validate_common(self.config.trigger_score, self.config.minimum_evidence)

    def detect(self, features: ScanFeatures) -> DetectorResult:
        if features.total_attempts < self.config.minimum_attempts:
            return _insufficient(self.name, features, "too few connection attempts")
        horizontal = (
            features.unique_destination_ip_estimate >= self.config.horizontal_destination_ip_threshold
            and features.horizontal_fanout_ratio is not None
            and features.horizontal_fanout_ratio >= self.config.horizontal_ratio_threshold
        )
        vertical = (
            features.unique_destination_port_estimate >= self.config.vertical_destination_port_threshold
            and features.vertical_fanout_ratio is not None
            and features.vertical_fanout_ratio >= self.config.vertical_ratio_threshold
        )
        failure_ratio = sum(value for value in (features.rejection_ratio, features.no_reply_ratio) if value is not None)
        signals = (
            (
                features.attempts_per_second >= self.config.attempts_per_second_threshold
                or features.syn_starts_per_second >= self.config.syn_starts_per_second_threshold,
                f"high attempt/SYN rate ({features.attempts_per_second:.3f}/{features.syn_starts_per_second:.3f} per second)",
            ),
            (
                features.unique_destination_pair_estimate >= self.config.unique_destination_pair_threshold,
                f"broad destination-pair fan-out ({features.unique_destination_pair_estimate})",
            ),
            (horizontal, f"horizontal fan-out ({features.unique_destination_ip_estimate} IPs)"),
            (vertical, f"vertical fan-out ({features.unique_destination_port_estimate} ports)"),
            (
                features.establishment_ratio is not None
                and features.establishment_ratio <= self.config.maximum_establishment_ratio
                and failure_ratio >= self.config.minimum_failure_ratio,
                f"low establishment with rejected/no-reply outcomes ({failure_ratio:.3f})",
            ),
        )
        saturated = any((features.destination_ip_saturated, features.destination_port_saturated, features.destination_pair_saturated))
        extra = ("one or more fan-out structures saturated; estimates are lower-confidence",) if saturated else ()
        return _result(
            self.name,
            features,
            signals=signals,
            trigger_score=self.config.trigger_score,
            minimum_evidence=self.config.minimum_evidence,
            required=horizontal or vertical,
            extra_evidence=extra,
        )


@dataclass(frozen=True, slots=True)
class ExfilDetectorConfig:
    minimum_recent_bytes: int = 10_000_000
    byte_rate_threshold: float = 100_000.0
    minimum_sustained_duration_seconds: float = 300.0
    minimum_active_time_fraction: float = 0.5
    maximum_burstiness: float = 1.0
    directional_ratio_threshold: float = 5.0
    trigger_score: float = 0.5
    minimum_evidence: int = 2


class ExfilDetector:
    name = "exfil_statistical"

    def __init__(self, config: ExfilDetectorConfig | None = None) -> None:
        self.config = config or ExfilDetectorConfig()
        _validate_common(self.config.trigger_score, self.config.minimum_evidence)

    def detect(self, features: ExfilFeatures) -> DetectorResult:
        if features.total_recent_bytes <= 0:
            return _insufficient(self.name, features, "no recent directional bytes")
        volume = (
            features.total_recent_bytes >= self.config.minimum_recent_bytes
            and features.bytes_per_second >= self.config.byte_rate_threshold
        )
        sustained = (
            features.sustained_transfer_duration_seconds >= self.config.minimum_sustained_duration_seconds
            and features.active_time_fraction >= self.config.minimum_active_time_fraction
        )
        low_burstiness = (
            features.byte_rate_burstiness is not None
            and features.byte_rate_burstiness <= self.config.maximum_burstiness
        )
        directional = (
            features.reverse_observed
            and features.forward_to_reverse_byte_ratio is not None
            and features.forward_to_reverse_byte_ratio >= self.config.directional_ratio_threshold
        )
        signals = (
            (volume, f"high directional volume ({features.total_recent_bytes} bytes, {features.bytes_per_second:.2f} bytes/s)"),
            (sustained, f"sustained activity ({features.sustained_transfer_duration_seconds:.1f}s, active fraction {features.active_time_fraction:.3f})"),
            (low_burstiness, f"persistent rather than burst-only rate profile (burstiness {features.byte_rate_burstiness})"),
            (directional, f"forward/reverse byte ratio {features.forward_to_reverse_byte_ratio}"),
        )
        extra = () if features.reverse_observed else ("reverse direction not observed; directional ratio unavailable",)
        return _result(
            self.name,
            features,
            signals=signals,
            trigger_score=self.config.trigger_score,
            minimum_evidence=self.config.minimum_evidence,
            required=volume and sustained,
            extra_evidence=extra,
        )


@dataclass(frozen=True, slots=True)
class BeaconDetectorConfig:
    minimum_contacts: int = 6
    minimum_episodes: int = 4
    maximum_interarrival_coefficient_of_variation: float = 0.15
    maximum_jitter_fraction: float = 0.2
    minimum_timing_regularity: float = 0.85
    maximum_episode_size_coefficient_of_variation: float = 0.3
    maximum_connection_size_coefficient_of_variation: float = 0.3
    trigger_score: float = 0.5
    minimum_evidence: int = 2


class BeaconDetector:
    name = "beacon_statistical"

    def __init__(self, config: BeaconDetectorConfig | None = None) -> None:
        self.config = config or BeaconDetectorConfig()
        _validate_common(self.config.trigger_score, self.config.minimum_evidence)

    @staticmethod
    def _coefficient(mean: float | None, variance: float | None) -> float | None:
        if mean is None or variance is None or mean <= 0:
            return None
        return math.sqrt(variance) / mean

    def detect(self, features: BeaconFeatures) -> DetectorResult:
        if features.contact_count < self.config.minimum_contacts and features.episode_count < self.config.minimum_episodes:
            return _insufficient(self.name, features, "too few retained contacts and episodes")
        contact_regular = (
            features.connection_interarrival_coefficient_of_variation is not None
            and features.connection_interarrival_coefficient_of_variation <= self.config.maximum_interarrival_coefficient_of_variation
            and features.timing_regularity is not None
            and features.timing_regularity >= self.config.minimum_timing_regularity
            and features.connection_robust_jitter_seconds is not None
            and features.connection_interarrival_mean_seconds is not None
            and features.connection_robust_jitter_seconds
            <= features.connection_interarrival_mean_seconds * self.config.maximum_jitter_fraction
        )
        episode_regular = (
            features.episode_interarrival_coefficient_of_variation is not None
            and features.episode_interarrival_coefficient_of_variation <= self.config.maximum_interarrival_coefficient_of_variation
            and features.episode_robust_jitter_seconds is not None
            and features.episode_interarrival_mean_seconds is not None
            and features.episode_robust_jitter_seconds
            <= features.episode_interarrival_mean_seconds * self.config.maximum_jitter_fraction
        )
        episode_size_cv = self._coefficient(features.episode_byte_mean, features.episode_byte_variance)
        connection_size_cv = self._coefficient(features.connection_byte_mean, features.connection_byte_variance)
        signals = (
            (contact_regular, f"regular connection timing (CV={features.connection_interarrival_coefficient_of_variation}, jitter={features.connection_robust_jitter_seconds})"),
            (episode_regular, f"regular activity episodes (CV={features.episode_interarrival_coefficient_of_variation}, jitter={features.episode_robust_jitter_seconds})"),
            (
                episode_size_cv is not None and episode_size_cv <= self.config.maximum_episode_size_coefficient_of_variation,
                f"consistent episode sizes (CV={episode_size_cv})",
            ),
            (
                connection_size_cv is not None and connection_size_cv <= self.config.maximum_connection_size_coefficient_of_variation,
                f"consistent connection sizes (CV={connection_size_cv})",
            ),
        )
        return _result(
            self.name,
            features,
            signals=signals,
            trigger_score=self.config.trigger_score,
            minimum_evidence=self.config.minimum_evidence,
            required=contact_regular or episode_regular,
        )


@dataclass(frozen=True, slots=True)
class DNSDetectorConfig:
    minimum_queries: int = 10
    tunneling_minimum_domain_queries: int = 20
    tunneling_mean_subdomain_length: float = 25.0
    tunneling_mean_subdomain_entropy: float = 3.5
    tunneling_unique_subdomain_ratio: float = 0.7
    tunneling_txt_fraction: float = 0.4
    tunneling_minimum_indicators: int = 3
    dga_unique_domain_threshold: int = 20
    dga_domain_fanout_per_second: float = 0.05
    dga_unique_qname_ratio: float = 0.8
    dga_nxdomain_ratio: float = 0.4
    dga_mean_query_length: float = 12.0
    dga_minimum_indicators: int = 3
    abnormal_query_rate: float = 5.0
    abnormal_no_reply_ratio: float = 0.5
    abnormal_rejection_ratio: float = 0.3
    abnormal_malformed_ratio: float = 0.2
    abnormal_minimum_indicators: int = 2
    trigger_score: float = 0.5


class DNSDetector:
    """Explain DNS tunneling-, DGA-, and abnormal-query-like combinations."""

    name = "dns_statistical"

    def __init__(self, config: DNSDetectorConfig | None = None) -> None:
        self.config = config or DNSDetectorConfig()
        _validate_common(self.config.trigger_score, 1)
        if self.config.minimum_queries <= 0:
            raise ValueError("minimum DNS query count must be positive")

    def detect(self, features: DNSFeatures) -> DetectorResult:
        if features.total_queries < self.config.minimum_queries:
            return _insufficient(self.name, features, "too few retained DNS queries")

        evidence: list[str] = []
        tunnel_score = 0.0
        tunnel_triggered = False
        domain_candidates = list(features.domain_features.values())
        if features.overflow_domain_features is not None:
            domain_candidates.append(features.overflow_domain_features)
        for domain in domain_candidates:
            if domain.query_count < self.config.tunneling_minimum_domain_queries:
                continue
            unique_ratio = (
                1.0 - domain.repetition_ratio
                if domain.repetition_ratio is not None
                else None
            )
            txt_fraction = (
                domain.qtype_distribution.get(16, 0.0)
                if domain.qtype_distribution is not None
                else None
            )
            indicators = (
                (
                    domain.mean_subdomain_length is not None
                    and domain.mean_subdomain_length
                    >= self.config.tunneling_mean_subdomain_length,
                    f"tunneling-like long subdomains for {domain.registrable_domain} "
                    f"(mean={domain.mean_subdomain_length})",
                ),
                (
                    domain.mean_subdomain_entropy is not None
                    and domain.mean_subdomain_entropy
                    >= self.config.tunneling_mean_subdomain_entropy,
                    f"tunneling-like subdomain entropy for {domain.registrable_domain} "
                    f"(mean={domain.mean_subdomain_entropy})",
                ),
                (
                    unique_ratio is not None
                    and unique_ratio >= self.config.tunneling_unique_subdomain_ratio,
                    f"tunneling-like subdomain uniqueness for {domain.registrable_domain} "
                    f"(ratio={unique_ratio})",
                ),
                (
                    txt_fraction is not None
                    and txt_fraction >= self.config.tunneling_txt_fraction,
                    f"tunneling-like TXT concentration for {domain.registrable_domain} "
                    f"(fraction={txt_fraction})",
                ),
            )
            matched = [message for condition, message in indicators if condition]
            tunnel_score = max(tunnel_score, len(matched) / len(indicators))
            if len(matched) >= self.config.tunneling_minimum_indicators:
                tunnel_triggered = True
                evidence.extend(matched)

        unique_qname_ratio = _safe_ratio(
            features.unique_qname_estimate, features.total_queries
        )
        dga_signals = (
            (
                features.unique_registrable_domain_estimate
                >= self.config.dga_unique_domain_threshold,
                f"DGA-like registrable-domain fan-out "
                f"({features.unique_registrable_domain_estimate})",
            ),
            (
                features.source_domain_fanout_per_second
                >= self.config.dga_domain_fanout_per_second,
                f"DGA-like domain growth rate "
                f"({features.source_domain_fanout_per_second:.4f}/s)",
            ),
            (
                unique_qname_ratio is not None
                and unique_qname_ratio >= self.config.dga_unique_qname_ratio,
                f"DGA-like full-query uniqueness (ratio={unique_qname_ratio})",
            ),
            (
                features.nxdomain_ratio is not None
                and features.nxdomain_ratio >= self.config.dga_nxdomain_ratio,
                f"DGA-like NXDOMAIN ratio ({features.nxdomain_ratio})",
            ),
            (
                features.mean_query_length is not None
                and features.mean_query_length >= self.config.dga_mean_query_length,
                f"DGA-like query length (mean={features.mean_query_length})",
            ),
        )
        dga_evidence = [message for condition, message in dga_signals if condition]
        dga_score = len(dga_evidence) / len(dga_signals)
        dga_triggered = (
            dga_signals[0][0]
            and len(dga_evidence) >= self.config.dga_minimum_indicators
        )
        if dga_triggered:
            evidence.extend(dga_evidence)

        abnormal_signals = (
            (
                features.queries_per_second >= self.config.abnormal_query_rate,
                f"abnormal DNS query rate ({features.queries_per_second:.3f}/s)",
            ),
            (
                features.no_reply_ratio is not None
                and features.no_reply_ratio >= self.config.abnormal_no_reply_ratio,
                f"abnormal no-reply ratio ({features.no_reply_ratio})",
            ),
            (
                features.rejection_ratio is not None
                and features.rejection_ratio >= self.config.abnormal_rejection_ratio,
                f"abnormal rejection ratio ({features.rejection_ratio})",
            ),
            (
                features.malformed_query_ratio is not None
                and features.malformed_query_ratio
                >= self.config.abnormal_malformed_ratio,
                f"abnormal malformed-query ratio ({features.malformed_query_ratio})",
            ),
        )
        abnormal_evidence = [
            message for condition, message in abnormal_signals if condition
        ]
        abnormal_score = len(abnormal_evidence) / len(abnormal_signals)
        abnormal_triggered = (
            abnormal_signals[0][0]
            and len(abnormal_evidence) >= self.config.abnormal_minimum_indicators
        )
        if abnormal_triggered:
            evidence.extend(abnormal_evidence)

        score = max(tunnel_score, dga_score, abnormal_score)
        family_triggered = tunnel_triggered or dga_triggered or abnormal_triggered
        triggered = family_triggered and score >= self.config.trigger_score
        if features.qname_cardinality_saturated or features.registrable_domain_cardinality_saturated or features.domain_map_saturated:
            evidence.append("DNS cardinality/domain map saturated; estimates are lower-confidence")
        return DetectorResult(
            detector=self.name,
            subject=features.subject,
            timestamp=features.timestamp,
            score=score,
            triggered=triggered,
            disposition="suspicious" if triggered else "benign_like",
            evidence=tuple(evidence),
            available_features=features.available_features(),
        )


@dataclass(frozen=True, slots=True)
class EncryptedTrafficDetectorConfig:
    minimum_sessions: int = 5
    session_rate_threshold: float = 0.1
    byte_rate_threshold: float = 100_000.0
    directional_ratio_threshold: float = 10.0
    repeated_service_active_fraction: float = 0.5
    incomplete_ratio_threshold: float = 0.5
    alert_ratio_threshold: float = 0.2
    missing_sni_ratio_threshold: float = 0.8
    certificate_novelty_ratio_threshold: float = 0.8
    minimum_certificate_observations: int = 3
    risky_versions: tuple[str, ...] = ("SSLv2", "SSLv3", "TLSv10")
    risky_version_fraction: float = 0.5
    minimum_behavioral_indicators: int = 1
    minimum_metadata_outcome_indicators: int = 2
    minimum_total_indicators: int = 3
    trigger_score: float = 0.3


class EncryptedTrafficDetector:
    """Combine encrypted-flow behavior with observable protocol metadata."""

    name = "encrypted_traffic_statistical"

    def __init__(
        self, config: EncryptedTrafficDetectorConfig | None = None
    ) -> None:
        self.config = config or EncryptedTrafficDetectorConfig()
        _validate_common(self.config.trigger_score, 1)
        if self.config.minimum_sessions <= 0:
            raise ValueError("minimum encrypted session count must be positive")

    def detect(self, features: EncryptedTrafficFeatures) -> DetectorResult:
        if features.session_count < self.config.minimum_sessions:
            return _insufficient(
                self.name, features, "too few retained encrypted sessions"
            )

        directional_ratio = features.client_to_server_byte_ratio
        if directional_ratio is not None and directional_ratio < 1.0:
            directional_ratio = 1.0 / directional_ratio if directional_ratio > 0 else None
        total_byte_rate = (
            features.client_to_server_bytes_per_second
            + features.server_to_client_bytes_per_second
        )
        behavioral = (
            (
                features.encrypted_sessions_per_second
                >= self.config.session_rate_threshold,
                f"high encrypted-session frequency "
                f"({features.encrypted_sessions_per_second:.3f}/s)",
            ),
            (
                total_byte_rate >= self.config.byte_rate_threshold,
                f"high encrypted traffic rate ({total_byte_rate:.2f} bytes/s)",
            ),
            (
                directional_ratio is not None
                and directional_ratio >= self.config.directional_ratio_threshold,
                f"strong encrypted directional imbalance ({directional_ratio:.2f}x)"
                if directional_ratio is not None
                else "encrypted directional ratio unavailable",
            ),
            (
                features.repeated_service_active_time_fraction
                >= self.config.repeated_service_active_fraction,
                f"persistent repeated-service activity "
                f"(active fraction={features.repeated_service_active_time_fraction:.3f})",
            ),
        )
        risky_fraction = 0.0
        if features.version_distribution is not None:
            risky_fraction = sum(
                features.version_distribution.get(version, 0.0)
                for version in self.config.risky_versions
            )
        metadata_outcomes = (
            (
                features.incomplete_ratio is not None
                and features.incomplete_ratio
                >= self.config.incomplete_ratio_threshold,
                f"high incomplete encrypted-session ratio ({features.incomplete_ratio})",
            ),
            (
                features.alert_ratio is not None
                and features.alert_ratio >= self.config.alert_ratio_threshold,
                f"high encrypted-protocol alert ratio ({features.alert_ratio})",
            ),
            (
                features.missing_sni_ratio is not None
                and features.missing_sni_ratio
                >= self.config.missing_sni_ratio_threshold,
                f"frequent missing SNI ({features.missing_sni_ratio})",
            ),
            (
                features.unique_certificate_fingerprint_count
                >= self.config.minimum_certificate_observations
                and features.certificate_fingerprint_novelty_ratio is not None
                and features.certificate_fingerprint_novelty_ratio
                >= self.config.certificate_novelty_ratio_threshold,
                "high within-window certificate fingerprint novelty "
                f"({features.certificate_fingerprint_novelty_ratio})",
            ),
            (
                risky_fraction >= self.config.risky_version_fraction,
                f"risky encrypted-protocol version concentration ({risky_fraction})",
            ),
        )
        behavioral_evidence = [
            message for condition, message in behavioral if condition
        ]
        metadata_evidence = [
            message for condition, message in metadata_outcomes if condition
        ]
        evidence = behavioral_evidence + metadata_evidence
        total_signals = len(behavioral) + len(metadata_outcomes)
        score = len(evidence) / total_signals
        required = (
            len(behavioral_evidence) >= self.config.minimum_behavioral_indicators
            and len(metadata_evidence)
            >= self.config.minimum_metadata_outcome_indicators
            and len(evidence) >= self.config.minimum_total_indicators
        )
        triggered = required and score >= self.config.trigger_score
        if features.categorical_saturated or features.sni_cardinality_saturated or features.certificate_cardinality_saturated:
            evidence.append("encrypted metadata categories saturated; distributions are lower-confidence")
        return DetectorResult(
            detector=self.name,
            subject=features.subject,
            timestamp=features.timestamp,
            score=score,
            triggered=triggered,
            disposition="suspicious" if triggered else "benign_like",
            evidence=tuple(evidence),
            available_features=features.available_features(),
        )


def _safe_ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator > 0 else None
