import struct
import socket
from dataclasses import dataclass, field
from typing import Iterator


PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAP_MAGIC_LE_US = 0xD4C3B2A1
PCAP_MAGIC_LE_NS = 0x4D3CB2A1

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass
class PcapPacket:
    timestamp: float
    incl_len: int
    orig_len: int
    raw: bytes
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    tcp_flags: int = 0
    ip_header_len: int = 0
    payload_len: int = 0
    is_ipv6: bool = False
    eth_type: int = 0
    dns_queries: list = field(default_factory=list)


@dataclass
class PcapFile:
    version_major: int = 0
    version_minor: int = 0
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 0
    network: int = 0
    packets: list = field(default_factory=list)
    link_type: int = 0
    byte_order: str = "big"


def _parse_ipv4(data: bytes, pkt: PcapPacket) -> None:
    if len(data) < 20:
        return
    ihl = (data[0] & 0x0F) * 4
    pkt.ip_header_len = ihl
    proto = data[9]
    pkt.protocol = proto
    pkt.src_ip = socket.inet_ntoa(data[12:16])
    pkt.dst_ip = socket.inet_ntoa(data[16:20])

    transport = data[ihl:]
    if proto == PROTO_TCP and len(transport) >= 14:
        pkt.src_port = struct.unpack("!H", transport[0:2])[0]
        pkt.dst_port = struct.unpack("!H", transport[2:4])[0]
        pkt.tcp_flags = transport[13] if len(transport) > 13 else 0
        data_offset = ((transport[12] >> 4) & 0x0F) * 4
        pkt.payload_len = max(0, len(transport) - data_offset)
    elif proto == PROTO_UDP and len(transport) >= 8:
        pkt.src_port = struct.unpack("!H", transport[0:2])[0]
        pkt.dst_port = struct.unpack("!H", transport[2:4])[0]
        pkt.payload_len = max(0, len(transport) - 8)
        if pkt.dst_port == 53:
            pkt.dns_queries = _extract_dns_queries(transport[8:])


def _parse_ipv6(data: bytes, pkt: PcapPacket) -> None:
    if len(data) < 40:
        return
    pkt.is_ipv6 = True
    next_header = data[6]
    pkt.src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    pkt.dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    pkt.protocol = next_header

    offset = 40
    while next_header in (0, 43, 44, 60):
        if offset + 2 > len(data):
            return
        next_header = data[offset]
        ext_len = (data[offset + 1] + 1) * 8
        offset += ext_len

    transport = data[offset:]
    if next_header == PROTO_TCP and len(transport) >= 14:
        pkt.src_port = struct.unpack("!H", transport[0:2])[0]
        pkt.dst_port = struct.unpack("!H", transport[2:4])[0]
        pkt.tcp_flags = transport[13] if len(transport) > 13 else 0
        data_offset = ((transport[12] >> 4) & 0x0F) * 4
        pkt.payload_len = max(0, len(transport) - data_offset)
    elif next_header == PROTO_UDP and len(transport) >= 8:
        pkt.src_port = struct.unpack("!H", transport[0:2])[0]
        pkt.dst_port = struct.unpack("!H", transport[2:4])[0]
        pkt.payload_len = max(0, len(transport) - 8)
        if pkt.dst_port == 53:
            pkt.dns_queries = _extract_dns_queries(transport[8:])


def _read_dns_name(payload: bytes, offset: int) -> tuple:
    labels: list[str] = []
    pos = offset
    jumped = False
    scan_offset = offset

    while True:
        if scan_offset >= len(payload):
            return None
        length = payload[scan_offset]

        if length == 0:
            scan_offset += 1
            if not jumped:
                pos = scan_offset
            break

        if length & 0xC0 == 0xC0:
            if scan_offset + 1 >= len(payload):
                return None
            ptr = ((length & 0x3F) << 8) | payload[scan_offset + 1]
            if not jumped:
                pos = scan_offset + 2
                jumped = True
                scan_offset = ptr
                continue
            if ptr >= offset:
                return None
            scan_offset = ptr
            continue

        if scan_offset + 1 + length > len(payload):
            return None
        labels.append(
            payload[scan_offset + 1 : scan_offset + 1 + length].decode(
                "ascii", errors="ignore"
            )
        )
        scan_offset += 1 + length

    return ".".join(labels), pos


def _extract_dns_queries(payload: bytes) -> list:
    queries: list[str] = []
    if len(payload) < 12:
        return queries

    flags = struct.unpack("!H", payload[2:4])[0]
    if flags & 0x8000:
        return queries

    qdcount = struct.unpack("!H", payload[4:6])[0]
    if qdcount == 0 or qdcount > 200:
        return queries

    offset = 12
    for _ in range(qdcount):
        name = _read_dns_name(payload, offset)
        if name is None:
            break
        qname, offset = name
        if offset + 4 > len(payload):
            break
        if qname:
            queries.append(qname + ".")
        offset += 4

    return queries[:20]


def parse_pcap(file_path: str, max_packets: int = 0) -> PcapFile:
    pcap = PcapFile()

    with open(file_path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]

        if magic == PCAP_MAGIC_US:
            endian = ">"
        elif magic == PCAP_MAGIC_LE_US:
            endian = "<"
        elif magic == PCAP_MAGIC_NS:
            endian = ">"
        elif magic == PCAP_MAGIC_LE_NS:
            endian = "<"
        else:
            raise ValueError(f"Not a valid PCAP file: magic=0x{magic:08x}")

        pcap.byte_order = endian
        hdr = struct.unpack(f"{endian}HHiIII", f.read(20))
        pcap.version_major = hdr[0]
        pcap.version_minor = hdr[1]
        pcap.thiszone = hdr[2]
        pcap.sigfigs = hdr[3]
        pcap.snaplen = hdr[4]
        pcap.network = hdr[5]
        pcap.link_type = hdr[5]

        count = 0
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f"{endian}IIII", rec_hdr
            )
            timestamp = ts_sec + ts_usec / 1_000_000.0

            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break

            pkt = PcapPacket(
                timestamp=timestamp,
                incl_len=incl_len,
                orig_len=orig_len,
                raw=raw,
            )

            try:
                _parse_link_layer(raw, pkt, pcap.link_type)
            except Exception:
                pass

            pcap.packets.append(pkt)
            count += 1

            if max_packets > 0 and count >= max_packets:
                break

    return pcap


def _parse_link_layer(raw: bytes, pkt: PcapPacket, link_type: int) -> None:
    if link_type == 1:
        if len(raw) < 14:
            return
        eth_type = struct.unpack("!H", raw[12:14])[0]
        pkt.eth_type = eth_type
        if eth_type == ETHERTYPE_IPV4:
            _parse_ipv4(raw[14:], pkt)
        elif eth_type == ETHERTYPE_IPV6:
            _parse_ipv6(raw[14:], pkt)
    elif link_type == 101:
        if len(raw) < 1:
            return
        ip_ver = (raw[0] >> 4) & 0x0F
        if ip_ver == 4:
            _parse_ipv4(raw, pkt)
        elif ip_ver == 6:
            _parse_ipv6(raw, pkt)
    elif link_type == 113:
        if len(raw) < 4:
            return
        eth_type = struct.unpack("!H", raw[2:4])[0]
        pkt.eth_type = eth_type
        offset = 4
        while eth_type == 0x8100:
            if len(raw) < offset + 4:
                return
            eth_type = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
            offset += 4
        if eth_type == ETHERTYPE_IPV4:
            _parse_ipv4(raw[offset:], pkt)
        elif eth_type == ETHERTYPE_IPV6:
            _parse_ipv6(raw[offset:], pkt)
    elif link_type == 0:
        if len(raw) < 1:
            return
        ip_ver = (raw[0] >> 4) & 0x0F
        if ip_ver == 4:
            _parse_ipv4(raw, pkt)
        elif ip_ver == 6:
            _parse_ipv6(raw, pkt)
