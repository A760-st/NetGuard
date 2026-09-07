import math
from app.services.feature_engine import compute_features, FlowFeatures


def test_compute_features_basic():
    features = compute_features(
        duration=10.0,
        fwd_packets=100,
        bwd_packets=50,
        fwd_bytes=10000,
        bwd_bytes=5000,
        forward_packet_lengths=[100] * 100,
        backward_packet_lengths=[100] * 50,
        forward_timestamps=[float(i) for i in range(100)],
        backward_timestamps=[float(i) for i in range(50)],
        syn_count=2,
        ack_count=80,
        fin_count=1,
        rst_count=0,
        psh_count=50,
    )

    assert features.flow_duration == 10.0
    assert features.total_fwd_packets == 100
    assert features.total_bwd_packets == 50
    assert features.total_fwd_bytes == 10000
    assert features.total_bwd_bytes == 5000
    assert features.fwd_packet_length_mean == 100.0
    assert features.bwd_packet_length_mean == 100.0
    assert features.syn_flag_count == 2
    assert features.ack_flag_count == 80


def test_byte_asymmetry_ratio():
    features = compute_features(
        duration=1.0,
        fwd_packets=10,
        bwd_packets=10,
        fwd_bytes=1000,
        bwd_bytes=100,
        forward_packet_lengths=[100] * 10,
        backward_packet_lengths=[10] * 10,
        forward_timestamps=[0.0, 0.1],
        backward_timestamps=[0.05, 0.15],
        syn_count=1,
        ack_count=10,
        fin_count=0,
        rst_count=0,
        psh_count=5,
    )

    expected = (1000 - 100) / (1000 + 100 + 1)
    assert abs(features.byte_asymmetry_ratio - expected) < 0.001


def test_byte_asymmetry_zero_bytes():
    features = compute_features(
        duration=0.0,
        fwd_packets=0,
        bwd_packets=0,
        fwd_bytes=0,
        bwd_bytes=0,
        forward_packet_lengths=[],
        backward_packet_lengths=[],
        forward_timestamps=[],
        backward_timestamps=[],
        syn_count=0,
        ack_count=0,
        fin_count=0,
        rst_count=0,
        psh_count=0,
    )

    assert features.byte_asymmetry_ratio == 0.0
    assert features.flow_duration == 0.0
    assert features.fwd_packet_length_mean == 0.0


def test_to_vector_length():
    features = compute_features(
        duration=5.0,
        fwd_packets=20,
        bwd_packets=10,
        fwd_bytes=2000,
        bwd_bytes=1000,
        forward_packet_lengths=[100] * 20,
        backward_packet_lengths=[100] * 10,
        forward_timestamps=[0.0, 1.0, 2.0],
        backward_timestamps=[0.5, 1.5],
        syn_count=1,
        ack_count=15,
        fin_count=1,
        rst_count=0,
        psh_count=10,
    )

    vector = features.to_vector()
    assert len(vector) == 12


def test_to_dict_keys():
    features = compute_features(
        duration=1.0,
        fwd_packets=5,
        bwd_packets=3,
        fwd_bytes=500,
        bwd_bytes=300,
        forward_packet_lengths=[100] * 5,
        backward_packet_lengths=[100] * 3,
        forward_timestamps=[0.0, 0.5],
        backward_timestamps=[0.25],
        syn_count=0,
        ack_count=5,
        fin_count=0,
        rst_count=0,
        psh_count=3,
    )

    d = features.to_dict()
    assert "flow_duration" in d
    assert "byte_asymmetry_ratio" in d
    assert "syn_flag_count" in d
    assert len(d) == 22


def test_negative_duration_clamped():
    features = compute_features(
        duration=-5.0,
        fwd_packets=1,
        bwd_packets=1,
        fwd_bytes=100,
        bwd_bytes=100,
        forward_packet_lengths=[100],
        backward_packet_lengths=[100],
        forward_timestamps=[0.0],
        backward_timestamps=[0.0],
        syn_count=0,
        ack_count=1,
        fin_count=0,
        rst_count=0,
        psh_count=0,
    )

    assert features.flow_duration == 0.0
