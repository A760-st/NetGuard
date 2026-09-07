import math
from collections import defaultdict
from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence, as_timestamp


class C2BeaconDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "C2BeaconDetector"
        self.threat_class = ThreatClass.C2_BEACON

    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        if not flows:
            return []

        results: list[DetectorResult] = []

        pair_flows = defaultdict(list)
        for flow in flows:
            pair_key = (flow.source_ip, flow.destination_ip)
            pair_flows[pair_key].append(flow)

        for (src_ip, dst_ip), pair_flow_list in pair_flows.items():
            if len(pair_flow_list) < 5:
                continue

            timestamps = sorted([as_timestamp(f.first_seen) for f in pair_flow_list])
            iats = [
                timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))
            ]

            if not iats:
                continue

            iat_mean = sum(iats) / len(iats)
            iat_std = math.sqrt(
                sum((x - iat_mean) ** 2 for x in iats) / len(iats)
            ) if len(iats) > 1 else 0

            iat_cv = iat_std / iat_mean if iat_mean > 0 else float("inf")

            pkt_sizes = []
            for f in pair_flow_list:
                key = self._flow_key(f)
                feat = features_map.get(key)
                if feat:
                    pkt_sizes.append(feat.total_fwd_bytes)

            periodicity_score = 0.0
            if iat_cv < 0.5 and iat_mean > 1.0:
                periodicity_score = max(0, 1.0 - iat_cv)

            small_set_score = 0.0
            if len(pair_flow_list) > 10 and iat_mean > 5:
                small_set_score = 0.3

            size_consistency = 0.0
            if pkt_sizes and len(pkt_sizes) > 3:
                size_mean = sum(pkt_sizes) / len(pkt_sizes)
                size_std = math.sqrt(
                    sum((x - size_mean) ** 2 for x in pkt_sizes) / len(pkt_sizes)
                ) if len(pkt_sizes) > 1 else 0
                if size_mean > 0 and size_std / size_mean < 0.3:
                    size_consistency = 0.3

            confidence = periodicity_score * 0.5 + small_set_score + size_consistency
            confidence = min(confidence, 1.0)

            if confidence > 0.3:
                evidence = [
                    Evidence(
                        feature="inter_arrival_time_mean",
                        value=round(iat_mean, 3),
                        baseline=0,
                        interpretation=f"Mean IAT {iat_mean:.2f}s with coefficient of variation {iat_cv:.3f}",
                    ),
                    Evidence(
                        feature="periodicity_score",
                        value=round(periodicity_score, 3),
                        baseline=0,
                        interpretation="Low IAT variance suggests periodic beaconing",
                    ),
                ]

                if len(pair_flow_list) > 10:
                    evidence.append(
                        Evidence(
                            feature="repeated_connections",
                            value=len(pair_flow_list),
                            baseline=3,
                            interpretation=f"{len(pair_flow_list)} connections between same src/dst pair",
                        )
                    )

                severity = self._classify_severity(confidence)
                if len(pair_flow_list) > 20 and periodicity_score > 0.7:
                    severity = Severity.HIGH

                results.append(
                    DetectorResult(
                        detector_name=self.name,
                        threat_class=self.threat_class,
                        confidence=confidence,
                        severity=severity,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        flow_id=f"c2-{src_ip}-{dst_ip}",
                        timestamp=timestamps[-1] if timestamps else 0,
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
