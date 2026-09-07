from app.detectors.ddos_detector import DDoSDetector
from app.detectors.recon_detector import ReconDetector
from app.detectors.c2_detector import C2BeaconDetector
from app.detectors.exfiltration_detector import ExfiltrationDetector
from app.services.feature_engine import compute_features
from app.services.pcap_parser import PcapPacket


def _make_flow(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol=6, **kwargs):
    class MockFlow:
        pass

    f = MockFlow()
    f.source_ip = src_ip
    f.destination_ip = dst_ip
    f.source_port = src_port
    f.destination_port = dst_port
    f.protocol = protocol
    f.first_seen = type("TS", (), {"timestamp": lambda self: 1000.0})()
    f.last_seen = type("TS", (), {"timestamp": lambda self: 1010.0})()
    f.forward_bytes = kwargs.get("forward_bytes", 1000)
    f.backward_bytes = kwargs.get("backward_bytes", 500)
    for k, v in kwargs.items():
        setattr(f, k, v)
    return f


def _make_features(syn=0, ack=0, duration=10.0, fwd_pkts=10, bwd_pkts=5, fwd_bytes=1000, bwd_bytes=500):
    return compute_features(
        duration=duration,
        fwd_packets=fwd_pkts,
        bwd_packets=bwd_pkts,
        fwd_bytes=fwd_bytes,
        bwd_bytes=bwd_bytes,
        forward_packet_lengths=[100] * fwd_pkts,
        backward_packet_lengths=[100] * bwd_pkts,
        forward_timestamps=[float(i) for i in range(fwd_pkts)],
        backward_timestamps=[float(i) for i in range(bwd_pkts)],
        syn_count=syn,
        ack_count=ack,
        fin_count=0,
        rst_count=0,
        psh_count=0,
    )


def test_ddos_detector_empty():
    detector = DDoSDetector()
    results = detector.detect([], {})
    assert results == []


def test_ddos_detector_normal_traffic():
    detector = DDoSDetector()
    flows = [_make_flow(src_ip=f"10.0.0.{i}") for i in range(5)]
    features_map = {detector._flow_key(f): _make_features() for f in flows}
    results = detector.detect(flows, features_map)
    assert len(results) == 0


def test_ddos_detector_high_concentration():
    detector = DDoSDetector()
    flows = [_make_flow(src_ip="10.0.0.1", dst_ip=f"192.168.1.{i}") for i in range(20)]
    features_map = {detector._flow_key(f): _make_features(syn=15, bwd_pkts=0) for f in flows}
    results = detector.detect(flows, features_map)
    assert len(results) > 0
    assert results[0].confidence > 0


def test_recon_detector_empty():
    detector = ReconDetector()
    results = detector.detect([], {})
    assert results == []


def test_recon_detector_high_fanout():
    detector = ReconDetector()
    flows = [_make_flow(src_ip="10.0.0.1", dst_port=1000 + i, dst_ip=f"192.168.1.{i % 5}") for i in range(25)]
    features_map = {detector._flow_key(f): _make_features(duration=0.1, fwd_pkts=1, bwd_pkts=0) for f in flows}
    results = detector.detect(flows, features_map)
    assert len(results) > 0


def test_c2_detector_empty():
    detector = C2BeaconDetector()
    results = detector.detect([], {})
    assert results == []


def test_exfiltration_detector_empty():
    detector = ExfiltrationDetector()
    results = detector.detect([], {})
    assert results == []


def test_exfiltration_detector_high_outbound():
    detector = ExfiltrationDetector()
    flows = [
        _make_flow(src_ip="10.0.0.1", dst_ip=f"1.2.3.{i}", forward_bytes=100000, backward_bytes=100)
        for i in range(5)
    ]
    features_map = {detector._flow_key(f): _make_features(fwd_bytes=100000, bwd_bytes=100) for f in flows}
    results = detector.detect(flows, features_map)
    assert len(results) > 0
