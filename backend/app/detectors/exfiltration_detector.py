from collections import defaultdict
from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence, as_timestamp


class ExfiltrationDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "ExfiltrationDetector"
        self.threat_class = ThreatClass.EXFILTRATION

    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        if not flows:
            return []

        results: list[DetectorResult] = []
        src_stats = defaultdict(lambda: {"out_bytes": 0, "in_bytes": 0, "flows": 0})

        for flow in flows:
            key = flow.source_ip
            feat = features_map.get(self._flow_key(flow))
            src_stats[key]["out_bytes"] += flow.forward_bytes
            src_stats[key]["in_bytes"] += flow.backward_bytes
            src_stats[key]["flows"] += 1

        for src_ip, stats in src_stats.items():
            if stats["flows"] < 3:
                continue

            total_out = stats["out_bytes"]
            total_in = stats["in_bytes"]
            ratio = (total_out - total_in) / (total_out + total_in + 1)

            confidence = 0.0
            evidence: list[Evidence] = []

            if ratio > 0.7 and total_out > 100000:
                conf = min(ratio, 1.0)
                confidence = max(confidence, conf)
                evidence.append(
                    Evidence(
                        feature="outbound_byte_ratio",
                        value=round(ratio, 3),
                        baseline=0.0,
                        interpretation=f"Host {src_ip} sent {total_out} bytes vs {total_in} received (ratio: {ratio:.2f})",
                    )
                )

            large_flows = 0
            long_flows = 0
            for flow in flows:
                if flow.source_ip == src_ip:
                    if flow.forward_bytes > 50000:
                        large_flows += 1
                    feat = features_map.get(self._flow_key(flow))
                    if feat and feat.flow_duration > 600:
                        long_flows += 1

            if large_flows >= 2:
                confidence = max(confidence, 0.4)
                evidence.append(
                    Evidence(
                        feature="large_outbound_flows",
                        value=large_flows,
                        baseline=0,
                        interpretation=f"{large_flows} flows with > 50KB outbound data",
                    )
                )

            if long_flows >= 1:
                confidence = max(confidence, 0.35)
                evidence.append(
                    Evidence(
                        feature="long_duration_transfer",
                        value=long_flows,
                        baseline=0,
                        interpretation=f"{long_flows} flows lasting > 10 minutes",
                    )
                )

            confidence = min(confidence, 1.0)
            if confidence > 0.3:
                for flow in flows:
                    if flow.source_ip == src_ip and flow.forward_bytes > 50000:
                        results.append(
                            DetectorResult(
                                detector_name=self.name,
                                threat_class=self.threat_class,
                                confidence=confidence,
                                severity=self._classify_severity(confidence),
                                source_ip=src_ip,
                                destination_ip=flow.destination_ip,
                                flow_id=self._flow_key(flow),
                                timestamp=as_timestamp(flow.last_seen),
                                supporting_evidence=evidence,
                            )
                        )
                        break

                if not results or all(
                    r.source_ip != src_ip for r in results
                ):
                    results.append(
                        DetectorResult(
                            detector_name=self.name,
                            threat_class=self.threat_class,
                            confidence=confidence,
                            severity=self._classify_severity(confidence),
                            source_ip=src_ip,
                            destination_ip="",
                            flow_id=f"exfil-{src_ip}",
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
