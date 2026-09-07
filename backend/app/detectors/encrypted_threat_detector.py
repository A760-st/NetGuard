from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence, as_timestamp


class EncryptedThreatDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "EncryptedThreatDetector"
        self.threat_class = ThreatClass.ENCRYPTED_THREAT

    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        results: list[DetectorResult] = []

        for flow in flows:
            if flow.protocol not in (6, 17):
                continue
            if flow.destination_port not in (443, 8443, 4433):
                continue

            feat = features_map.get(self._flow_key(flow))
            if not feat:
                continue

            evidence: list[Evidence] = []
            confidence = 0.0

            if feat.total_fwd_bytes > 0 and feat.total_bwd_bytes > 0:
                ratio = feat.byte_asymmetry_ratio
                if abs(ratio) > 0.8:
                    confidence += 0.25
                    direction = "outbound" if ratio > 0 else "inbound"
                    evidence.append(
                        Evidence(
                            feature="encrypted_byte_asymmetry",
                            value=round(ratio, 3),
                            baseline=0.0,
                            interpretation=f"Highly asymmetric encrypted {direction} traffic (ratio: {ratio:.2f})",
                        )
                    )

            if feat.flow_duration > 300 and feat.total_fwd_bytes > 100000:
                confidence += 0.2
                evidence.append(
                    Evidence(
                        feature="long_encrypted_transfer",
                        value=feat.flow_duration,
                        baseline=60,
                        interpretation=f"Long-duration encrypted transfer ({feat.flow_duration:.0f}s, {feat.total_fwd_bytes} bytes)",
                    )
                )

            if feat.rst_flag_count > 3:
                confidence += 0.15
                evidence.append(
                    Evidence(
                        feature="excessive_rst_flags",
                        value=feat.rst_flag_count,
                        baseline=0,
                        interpretation=f"{feat.rst_flag_count} RST flags in encrypted flow",
                    )
                )

            if feat.flow_iat_std > 0 and feat.flow_iat_mean > 0:
                cv = feat.flow_iat_std / feat.flow_iat_mean
                if cv > 2.0:
                    confidence += 0.1

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
