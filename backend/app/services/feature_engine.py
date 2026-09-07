import math
from dataclasses import dataclass


@dataclass
class FlowFeatures:
    flow_duration: float = 0.0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_fwd_bytes: int = 0
    total_bwd_bytes: int = 0
    fwd_packet_length_mean: float = 0.0
    bwd_packet_length_mean: float = 0.0
    flow_iat_mean: float = 0.0
    flow_iat_std: float = 0.0
    syn_flag_count: int = 0
    ack_flag_count: int = 0
    byte_asymmetry_ratio: float = 0.0
    fwd_packet_length_std: float = 0.0
    bwd_packet_length_std: float = 0.0
    flow_iat_min: float = 0.0
    flow_iat_max: float = 0.0
    fwd_iat_mean: float = 0.0
    bwd_iat_mean: float = 0.0
    fwd_psh_count: int = 0
    bwd_psh_count: int = 0
    fin_flag_count: int = 0
    rst_flag_count: int = 0

    def to_vector(self) -> list[float]:
        return [
            self.flow_duration,
            self.total_fwd_packets,
            self.total_bwd_packets,
            self.total_fwd_bytes,
            self.total_bwd_bytes,
            self.fwd_packet_length_mean,
            self.bwd_packet_length_mean,
            self.flow_iat_mean,
            self.flow_iat_std,
            self.syn_flag_count,
            self.ack_flag_count,
            self.byte_asymmetry_ratio,
        ]

    def to_dict(self) -> dict:
        return {
            "flow_duration": self.flow_duration,
            "total_fwd_packets": self.total_fwd_packets,
            "total_bwd_packets": self.total_bwd_packets,
            "total_fwd_bytes": self.total_fwd_bytes,
            "total_bwd_bytes": self.total_bwd_bytes,
            "fwd_packet_length_mean": self.fwd_packet_length_mean,
            "bwd_packet_length_mean": self.bwd_packet_length_mean,
            "flow_iat_mean": self.flow_iat_mean,
            "flow_iat_std": self.flow_iat_std,
            "syn_flag_count": self.syn_flag_count,
            "ack_flag_count": self.ack_flag_count,
            "byte_asymmetry_ratio": self.byte_asymmetry_ratio,
            "fwd_packet_length_std": self.fwd_packet_length_std,
            "bwd_packet_length_std": self.bwd_packet_length_std,
            "flow_iat_min": self.flow_iat_min,
            "flow_iat_max": self.flow_iat_max,
            "fwd_iat_mean": self.fwd_iat_mean,
            "bwd_iat_mean": self.bwd_iat_mean,
            "fwd_psh_count": self.fwd_psh_count,
            "bwd_psh_count": self.bwd_psh_count,
            "fin_flag_count": self.fin_flag_count,
            "rst_flag_count": self.rst_flag_count,
        }


FEATURE_NAMES = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_iat_mean",
    "flow_iat_std",
    "syn_flag_count",
    "ack_flag_count",
    "byte_asymmetry_ratio",
]


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance) if variance > 0 else 0.0


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def compute_features(
    duration: float,
    fwd_packets: int,
    bwd_packets: int,
    fwd_bytes: int,
    bwd_bytes: int,
    forward_packet_lengths: list[int],
    backward_packet_lengths: list[int],
    forward_timestamps: list[float],
    backward_timestamps: list[float],
    syn_count: int,
    ack_count: int,
    fin_count: int,
    rst_count: int,
    psh_count: int,
) -> FlowFeatures:
    features = FlowFeatures()

    features.flow_duration = max(duration, 0.0)
    features.total_fwd_packets = fwd_packets
    features.total_bwd_packets = bwd_packets
    features.total_fwd_bytes = fwd_bytes
    features.total_bwd_bytes = bwd_bytes

    features.fwd_packet_length_mean = _mean(
        [float(x) for x in forward_packet_lengths]
    )
    features.bwd_packet_length_mean = _mean(
        [float(x) for x in backward_packet_lengths]
    )

    features.fwd_packet_length_std = _std(
        [float(x) for x in forward_packet_lengths]
    )
    features.bwd_packet_length_std = _std(
        [float(x) for x in backward_packet_lengths]
    )

    all_timestamps = sorted(forward_timestamps + backward_timestamps)
    iats = [
        all_timestamps[i] - all_timestamps[i - 1]
        for i in range(1, len(all_timestamps))
    ]
    features.flow_iat_mean = _mean(iats)
    features.flow_iat_std = _std(iats)
    features.flow_iat_min = min(iats) if iats else 0.0
    features.flow_iat_max = max(iats) if iats else 0.0

    fwd_iats = [
        forward_timestamps[i] - forward_timestamps[i - 1]
        for i in range(1, len(forward_timestamps))
    ]
    bwd_iats = [
        backward_timestamps[i] - backward_timestamps[i - 1]
        for i in range(1, len(backward_timestamps))
    ]
    features.fwd_iat_mean = _mean(fwd_iats)
    features.bwd_iat_mean = _mean(bwd_iats)

    features.syn_flag_count = syn_count
    features.ack_flag_count = ack_count
    features.fin_flag_count = fin_count
    features.rst_flag_count = rst_count
    features.fwd_psh_count = psh_count
    features.bwd_psh_count = 0

    features.byte_asymmetry_ratio = _safe_ratio(
        float(fwd_bytes - bwd_bytes), float(fwd_bytes + bwd_bytes + 1)
    )

    return features
