from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
from app.services.pcap_parser import PcapPacket

FLOW_KEY = Tuple[str, str, int, int, int]


@dataclass
class FlowRecord:
    flow_id: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    duration: float = 0.0
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    forward_timestamps: list = field(default_factory=list)
    backward_timestamps: list = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    forward_packet_lengths: list = field(default_factory=list)
    backward_packet_lengths: list = field(default_factory=list)
    dns_query_names: list = field(default_factory=list)
    features: dict = field(default_factory=dict)


def _make_key(pkt: PcapPacket) -> Optional[FLOW_KEY]:
    if not pkt.src_ip or not pkt.dst_ip:
        return None
    return (
        pkt.src_ip,
        pkt.dst_ip,
        pkt.src_port,
        pkt.dst_port,
        pkt.protocol,
    )


def _reverse_key(key: FLOW_KEY) -> FLOW_KEY:
    return (key[1], key[0], key[3], key[2], key[4])


TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_FIN = 0x01
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_URG = 0x20


def build_flows(packets: list[PcapPacket]) -> list[FlowRecord]:
    flows: Dict[FLOW_KEY, FlowRecord] = {}
    key_map: Dict[FLOW_KEY, FLOW_KEY] = {}

    for pkt in packets:
        fwd_key = _make_key(pkt)
        if fwd_key is None:
            continue

        if fwd_key in flows:
            flow = flows[fwd_key]
            is_forward = True
        elif _reverse_key(fwd_key) in flows:
            real_key = _reverse_key(fwd_key)
            flow = flows[real_key]
            key_map[fwd_key] = real_key
            is_forward = False
        else:
            flow = FlowRecord(
                flow_id=f"{fwd_key[0]}:{fwd_key[2]}-{fwd_key[1]}:{fwd_key[3]}-{fwd_key[4]}",
                source_ip=fwd_key[0],
                destination_ip=fwd_key[1],
                source_port=fwd_key[2],
                destination_port=fwd_key[3],
                protocol=fwd_key[4],
                first_seen=pkt.timestamp,
            )
            flows[fwd_key] = flow
            is_forward = True

        flow.last_seen = pkt.timestamp
        flow.duration = flow.last_seen - flow.first_seen

        pkt_len = pkt.orig_len if pkt.orig_len > 0 else pkt.incl_len

        if is_forward:
            flow.forward_packets += 1
            flow.forward_bytes += pkt_len
            flow.forward_timestamps.append(pkt.timestamp)
            flow.forward_packet_lengths.append(pkt_len)
        else:
            flow.backward_packets += 1
            flow.backward_bytes += pkt_len
            flow.backward_timestamps.append(pkt.timestamp)
            flow.backward_packet_lengths.append(pkt_len)

        if pkt.protocol == 6:
            flags = pkt.tcp_flags
            if flags & TCP_SYN:
                flow.syn_count += 1
            if flags & TCP_ACK:
                flow.ack_count += 1
            if flags & TCP_FIN:
                flow.fin_count += 1
            if flags & TCP_RST:
                flow.rst_count += 1
            if flags & TCP_PSH:
                flow.psh_count += 1
            if flags & TCP_URG:
                flow.urg_count += 1

        if pkt.dns_queries:
            for qname in pkt.dns_queries:
                if qname not in flow.dns_query_names:
                    flow.dns_query_names.append(qname)

    result = list(flows.values())
    for flow in result:
        flow.duration = max(0.0, flow.last_seen - flow.first_seen)
        if flow.dns_query_names:
            flow.features["dns_query_names"] = flow.dns_query_names
        flow.flow_id = (
            f"{flow.source_ip}:{flow.source_port}-"
            f"{flow.destination_ip}:{flow.destination_port}-"
            f"{flow.protocol}"
        )

    return result
