import math
from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence, as_timestamp


class DNSTunnelDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "DNSTunnelDetector"
        self.threat_class = ThreatClass.DNS_TUNNEL

    def _query_entropy(self, query: str) -> float:
        if not query:
            return 0.0
        freq = {}
        for c in query:
            freq[c] = freq.get(c, 0) + 1
        length = len(query)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _label_analysis(self, query: str) -> dict:
        labels = query.rstrip(".").split(".")
        label_lengths = [len(l) for l in labels]
        max_label_len = max(label_lengths) if label_lengths else 0
        avg_label_len = sum(label_lengths) / len(label_lengths) if label_lengths else 0
        return {
            "label_count": len(labels),
            "max_label_length": max_label_len,
            "avg_label_length": avg_label_len,
            "total_length": len(query),
        }

    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        results: list[DetectorResult] = []

        for flow in flows:
            if flow.destination_port != 53:
                continue

            feat = features_map.get(self._flow_key(flow))
            if not feat:
                continue

            evidence: list[Evidence] = []
            confidence = 0.0

            if feat.total_fwd_bytes > 200:
                confidence += 0.2
                evidence.append(
                    Evidence(
                        feature="dns_query_size",
                        value=feat.total_fwd_bytes,
                        baseline=50,
                        interpretation=f"DNS query payload {feat.total_fwd_bytes} bytes exceeds normal",
                    )
                )

            if feat.flow_duration > 0:
                rate = feat.total_fwd_packets / feat.flow_duration
                if rate > 5:
                    confidence += 0.2
                    evidence.append(
                        Evidence(
                            feature="dns_query_rate",
                            value=round(rate, 2),
                            baseline=1.0,
                            interpretation=f"DNS query rate {rate:.1f} queries/sec is abnormally high",
                        )
                    )

            if hasattr(flow, "features") and flow.features:
                query_names = list(flow.features.get("dns_query_names", []) or [])
            else:
                query_names = []
            if not query_names and getattr(flow, "dns_query_names", None):
                query_names = list(flow.dns_query_names)
            for qname in query_names[:5]:
                    analysis = self._label_analysis(qname)
                    entropy = self._query_entropy(qname)

                    if analysis["max_label_length"] > 30:
                        confidence += 0.2
                        evidence.append(
                            Evidence(
                                feature="long_dns_label",
                                value=analysis["max_label_length"],
                                baseline=20,
                                interpretation=f"DNS label length {analysis['max_label_length']} chars in '{qname[:50]}'",
                            )
                        )

                    if entropy > 3.8:
                        confidence += 0.15
                        evidence.append(
                            Evidence(
                                feature="high_dns_entropy",
                                value=round(entropy, 3),
                                baseline=2.5,
                                interpretation=f"Query entropy {entropy:.2f} suggests encoded data",
                            )
                        )

            if feat.total_fwd_packets > 20 and feat.total_bwd_packets > 10:
                confidence += 0.15

            confidence = min(confidence, 1.0)
            if confidence > 0.3:
                results.append(
                    DetectorResult(
                        detector_name=self.name,
                        threat_class=self.threat_class,
                        confidence=confidence,
                        severity=self._classify_severity(confidence),
                        source_ip=flow.source_ip,
                        destination_ip=flow.destination_ip,
                        flow_id=self._flow_key(flow),
                        timestamp=as_timestamp(flow.last_seen),
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
