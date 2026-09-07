import math
from collections import Counter
from typing import Optional
from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence


class DDoSDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "DDoSDetector"
        self.threat_class = ThreatClass.DDoS

    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        if not flows:
            return []

        results: list[DetectorResult] = []

        src_ip_counts = Counter()
        dst_ip_counts = Counter()
        dst_port_counts = Counter()
        syn_flows = []
        high_rate_flows = []

        for flow in flows:
            src_ip_counts[flow.source_ip] += 1
            dst_ip_counts[flow.destination_ip] += 1
            if flow.destination_port:
                dst_port_counts[flow.destination_port] += 1

            key = self._flow_key(flow)
            feat = features_map.get(key)
            if feat:
                if feat.syn_flag_count > 10 and feat.total_bwd_packets == 0:
                    syn_flows.append((flow, feat))
                if feat.flow_duration > 0 and feat.total_fwd_packets / max(
                    feat.flow_duration, 0.001
                ) > 100:
                    high_rate_flows.append((flow, feat))

        total_flows = len(flows)
        if total_flows < 3:
            return []

        max_src = max(src_ip_counts.values())
        max_dst = max(dst_ip_counts.values())
        src_entropy = self._entropy(list(src_ip_counts.values()))
        dst_entropy = self._entropy(list(dst_ip_counts.values()))

        confidence = 0.0
        evidence: list[Evidence] = []

        if max_src > total_flows * 0.3:
            conf = min(max_src / total_flows, 1.0)
            confidence = max(confidence, conf)
            top_src = max(src_ip_counts, key=src_ip_counts.get)
            evidence.append(
                Evidence(
                    feature="source_ip_concentration",
                    value=max_src,
                    baseline=int(total_flows * 0.1),
                    interpretation=f"Source {top_src} accounts for {max_src}/{total_flows} flows",
                )
            )

        if max_dst > total_flows * 0.4:
            conf = min(max_dst / total_flows, 1.0)
            confidence = max(confidence, conf)
            top_dst = max(dst_ip_counts, key=dst_ip_counts.get)
            evidence.append(
                Evidence(
                    feature="destination_concentration",
                    value=max_dst,
                    baseline=int(total_flows * 0.15),
                    interpretation=f"Destination {top_dst} received {max_dst}/{total_flows} flows",
                )
            )

        if len(syn_flows) > 5:
            syn_ratio = len(syn_flows) / total_flows
            conf = min(syn_ratio * 1.2, 1.0)
            confidence = max(confidence, conf)
            evidence.append(
                Evidence(
                    feature="syn_flood_indicator",
                    value=len(syn_flows),
                    baseline=2,
                    interpretation=f"{len(syn_flows)} flows with SYN but no response",
                )
            )

        if len(high_rate_flows) > 3:
            conf = min(len(high_rate_flows) / total_flows * 2, 1.0)
            confidence = max(confidence, conf)
            evidence.append(
                Evidence(
                    feature="high_packet_rate",
                    value=len(high_rate_flows),
                    baseline=1,
                    interpretation=f"{len(high_rate_flows)} flows with packet rate > 100 pps",
                )
            )

        if confidence > 0.3:
            src_concentration = max_src / total_flows
            dst_concentration = max_dst / total_flows

            if src_concentration > 0.5 or dst_concentration > 0.5:
                severity = Severity.CRITICAL
            elif confidence > 0.7:
                severity = Severity.HIGH
            elif confidence > 0.5:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            for flow, feat in high_rate_flows[:10]:
                results.append(
                    DetectorResult(
                        detector_name=self.name,
                        threat_class=self.threat_class,
                        confidence=min(confidence, 1.0),
                        severity=severity,
                        source_ip=flow.source_ip,
                        destination_ip=flow.destination_ip,
                        flow_id=self._flow_key(flow),
                        timestamp=flow.last_seen if hasattr(flow, "last_seen") else 0,
                        supporting_evidence=evidence,
                        features=feat.to_dict() if hasattr(feat, "to_dict") else {},
                    )
                )

            if not results:
                top_src = max(src_ip_counts, key=src_ip_counts.get)
                top_dst = max(dst_ip_counts, key=dst_ip_counts.get)
                results.append(
                    DetectorResult(
                        detector_name=self.name,
                        threat_class=self.threat_class,
                        confidence=min(confidence, 1.0),
                        severity=severity,
                        source_ip=top_src,
                        destination_ip=top_dst,
                        flow_id=f"aggregate-{top_src}-{top_dst}",
                        timestamp=0,
                        supporting_evidence=evidence,
                    )
                )

        return results

    def _flow_key(self, flow) -> str:
        return (
            f"{flow.source_ip}:{getattr(flow, 'source_port', 0)}-"
            f"{flow.destination_ip}:{getattr(flow, 'destination_port', 0)}-"
            f"{flow.protocol}"
        )

    def _entropy(self, values: list[int]) -> float:
        total = sum(values)
        if total == 0:
            return 0.0
        entropy = 0.0
        for v in values:
            if v > 0:
                p = v / total
                entropy -= p * math.log2(p)
        return entropy
