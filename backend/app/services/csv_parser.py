"""Parse network-flow CSV files into FlowRecord objects and synthetic packets.

Expected columns (case-insensitive; aliases supported):
  source_ip / src_ip / src
  destination_ip / dst_ip / dst
  source_port / src_port / sport
  destination_port / dst_port / dport
  protocol / proto
  duration / flow_duration
  forward_packets / fwd_packets / tot_fwd_pkts
  backward_packets / bwd_packets / tot_bwd_pkts
  forward_bytes / fwd_bytes / totlen_fwd_pkts
  backward_bytes / bwd_bytes / totlen_bwd_pkts
  first_seen / timestamp (optional epoch seconds)
  dns_query / dns_query_names (optional)
"""

from __future__ import annotations

import csv
import io
from typing import Any

from app.services.flow_engine import FlowRecord
from app.services.pcap_parser import PcapPacket

COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "source_ip": ("source_ip", "src_ip", "src", "sip"),
    "destination_ip": ("destination_ip", "dst_ip", "dst", "dip"),
    "source_port": ("source_port", "src_port", "sport"),
    "destination_port": ("destination_port", "dst_port", "dport"),
    "protocol": ("protocol", "proto"),
    "duration": ("duration", "flow_duration", "flowduration"),
    "forward_packets": ("forward_packets", "fwd_packets", "tot_fwd_pkts", "total_fwd_packets"),
    "backward_packets": ("backward_packets", "bwd_packets", "tot_bwd_pkts", "total_bwd_packets"),
    "forward_bytes": ("forward_bytes", "fwd_bytes", "totlen_fwd_pkts", "total_length_of_fwd_packets"),
    "backward_bytes": ("backward_bytes", "bwd_bytes", "totlen_bwd_pkts", "total_length_of_bwd_packets"),
    "first_seen": ("first_seen", "timestamp", "ts", "start_time"),
    "dns_query": ("dns_query", "dns_query_names", "dns_qname", "query_name"),
    "traffic_label": ("traffic_label", "label", "attack_type", "category", "class"),
    "dataset": ("dataset", "dataset_name"),
}

PROTO_NAMES = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "6": 6,
    "17": 17,
    "1": 1,
}


def _normalize_header(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def _build_column_map(headers: list[str]) -> dict[str, str]:
    normalized = {_normalize_header(h): h for h in headers}
    mapping: dict[str, str] = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                mapping[canonical] = normalized[alias]
                break
    return mapping


def _get(row: dict[str, str], colmap: dict[str, str], key: str, default: str = "") -> str:
    header = colmap.get(key)
    if not header:
        return default
    return (row.get(header) or default).strip()


def _as_int(value: str, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _as_float(value: str, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_protocol(value: str) -> int:
    if not value:
        return 6
    key = value.strip().lower()
    if key in PROTO_NAMES:
        return PROTO_NAMES[key]
    return _as_int(value, 6)


def parse_flow_csv(file_path: str) -> tuple[list[FlowRecord], list[PcapPacket]]:
    """Parse a CSV of flow records. Returns (flows, synthetic_packets for quality stats)."""
    with open(file_path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        if not reader.fieldnames:
            raise ValueError("CSV has no header row")

        colmap = _build_column_map(list(reader.fieldnames))
        required = ("source_ip", "destination_ip")
        missing = [r for r in required if r not in colmap]
        if missing:
            raise ValueError(
                "Unable to process dataset because required network-flow fields are missing. "
                f"Missing: {', '.join(missing)}. Found headers: {', '.join(reader.fieldnames)}"
            )

        flows: list[FlowRecord] = []
        packets: list[PcapPacket] = []
        base_ts = 1_700_000_000.0

        for idx, row in enumerate(reader):
            src = _get(row, colmap, "source_ip")
            dst = _get(row, colmap, "destination_ip")
            if not src or not dst:
                continue

            sport = _as_int(_get(row, colmap, "source_port"), 0)
            dport = _as_int(_get(row, colmap, "destination_port"), 0)
            proto = _as_protocol(_get(row, colmap, "protocol", "6"))
            duration = max(0.0, _as_float(_get(row, colmap, "duration"), 0.0))
            fwd_pkts = max(0, _as_int(_get(row, colmap, "forward_packets"), 1))
            bwd_pkts = max(0, _as_int(_get(row, colmap, "backward_packets"), 0))
            fwd_bytes = max(0, _as_int(_get(row, colmap, "forward_bytes"), 0))
            bwd_bytes = max(0, _as_int(_get(row, colmap, "backward_bytes"), 0))
            first_seen = _as_float(_get(row, colmap, "first_seen"), base_ts + idx)
            last_seen = first_seen + duration
            dns_raw = _get(row, colmap, "dns_query")
            dns_names = [n.strip() for n in dns_raw.split(";") if n.strip()] if dns_raw else []
            traffic_label = _get(row, colmap, "traffic_label")
            dataset_name = _get(row, colmap, "dataset")

            # Synthetic per-packet lengths for feature stats (evenly split bytes)
            fwd_lens = _split_sizes(fwd_bytes, fwd_pkts)
            bwd_lens = _split_sizes(bwd_bytes, bwd_pkts)
            fwd_ts = _spread_timestamps(first_seen, last_seen, fwd_pkts)
            bwd_ts = _spread_timestamps(first_seen, last_seen, bwd_pkts)

            fr = FlowRecord(
                flow_id=f"{src}:{sport}-{dst}:{dport}-{proto}",
                source_ip=src,
                destination_ip=dst,
                source_port=sport,
                destination_port=dport,
                protocol=proto,
                first_seen=first_seen,
                last_seen=last_seen,
                duration=duration if duration > 0 else max(0.0, last_seen - first_seen),
                forward_packets=fwd_pkts,
                backward_packets=bwd_pkts,
                forward_bytes=fwd_bytes,
                backward_bytes=bwd_bytes,
                forward_packet_lengths=fwd_lens,
                backward_packet_lengths=bwd_lens,
                forward_timestamps=fwd_ts,
                backward_timestamps=bwd_ts,
                dns_query_names=dns_names,
                features={
                    **({"dns_query_names": dns_names} if dns_names else {}),
                    **({"traffic_label": traffic_label} if traffic_label else {}),
                    **({"dataset": dataset_name} if dataset_name else {}),
                },
            )
            flows.append(fr)

            # Synthetic packets for data-quality counters only
            for i, length in enumerate(fwd_lens):
                packets.append(
                    PcapPacket(
                        timestamp=fwd_ts[i] if i < len(fwd_ts) else first_seen,
                        incl_len=length,
                        orig_len=length,
                        raw=b"",
                        src_ip=src,
                        dst_ip=dst,
                        src_port=sport,
                        dst_port=dport,
                        protocol=proto,
                        payload_len=max(0, length - 40),
                        dns_queries=dns_names if proto == 17 and dport == 53 else [],
                    )
                )
            for i, length in enumerate(bwd_lens):
                packets.append(
                    PcapPacket(
                        timestamp=bwd_ts[i] if i < len(bwd_ts) else first_seen,
                        incl_len=length,
                        orig_len=length,
                        raw=b"",
                        src_ip=dst,
                        dst_ip=src,
                        src_port=dport,
                        dst_port=sport,
                        protocol=proto,
                        payload_len=max(0, length - 40),
                    )
                )

        if not flows:
            raise ValueError(
                "Unable to process dataset because no valid network-flow rows were found."
            )

        return flows, packets


def _split_sizes(total_bytes: int, count: int) -> list[int]:
    if count <= 0:
        return []
    if total_bytes <= 0:
        return [0] * count
    base = total_bytes // count
    rem = total_bytes % count
    return [base + (1 if i < rem else 0) for i in range(count)]


def _spread_timestamps(start: float, end: float, count: int) -> list[float]:
    if count <= 0:
        return []
    if count == 1 or end <= start:
        return [start] * count
    step = (end - start) / (count - 1)
    return [start + i * step for i in range(count)]
