from app.services.pcap_parser import PcapPacket, parse_pcap
from app.services.flow_engine import build_flows, FlowRecord


def _make_packet(
    src_ip: str = "192.168.1.1",
    dst_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: int = 6,
    length: int = 100,
    timestamp: float = 1000.0,
    tcp_flags: int = 0,
    **kwargs,
) -> PcapPacket:
    pkt = PcapPacket(
        timestamp=timestamp,
        incl_len=length,
        orig_len=length,
        raw=b"",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=tcp_flags,
    )
    return pkt


def test_build_flows_single_direction():
    packets = [
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, timestamp=1.0),
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, timestamp=1.5),
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, timestamp=2.0),
    ]

    flows = build_flows(packets)
    assert len(flows) == 1
    assert flows[0].source_ip == "1.1.1.1"
    assert flows[0].destination_ip == "2.2.2.2"
    assert flows[0].forward_packets == 3


def test_build_flows_bidirectional():
    packets = [
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, timestamp=1.0),
        _make_packet(src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=1000, timestamp=1.5),
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, timestamp=2.0),
    ]

    flows = build_flows(packets)
    assert len(flows) == 1
    assert flows[0].forward_packets == 2
    assert flows[0].backward_packets == 1


def test_build_flows_multiple_pairs():
    packets = [
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, timestamp=1.0),
        _make_packet(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=2000, dst_port=443, timestamp=1.0),
    ]

    flows = build_flows(packets)
    assert len(flows) == 2


def test_build_flows_tcp_flags():
    SYN = 0x02
    ACK = 0x10

    packets = [
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", tcp_flags=SYN, timestamp=1.0),
        _make_packet(src_ip="2.2.2.2", dst_ip="1.1.1.1", tcp_flags=SYN | ACK, timestamp=1.5),
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", tcp_flags=ACK, timestamp=2.0),
    ]

    flows = build_flows(packets)
    assert len(flows) == 1
    assert flows[0].syn_count >= 1


def test_build_flows_duration():
    packets = [
        _make_packet(timestamp=100.0),
        _make_packet(timestamp=200.0),
    ]

    flows = build_flows(packets)
    assert flows[0].duration == 100.0


def test_build_flows_empty():
    flows = build_flows([])
    assert flows == []


def test_build_flows_byte_counts():
    packets = [
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", length=200, timestamp=1.0),
        _make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", length=300, timestamp=2.0),
    ]

    flows = build_flows(packets)
    assert flows[0].forward_bytes == 500
