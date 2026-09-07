from collections import Counter, defaultdict
from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence


class ReconDetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "ReconDetector"
        self.threat_class = ThreatClass.RECON

    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        if not flows:
            return []

        results: list[DetectorResult] = []
        src_dst_ports = defaultdict(set)
        src_dst_hosts = defaultdict(set)
        src_short_flows = defaultdict(int)

        for flow in flows:
            key = (flow.source_ip,)
            if flow.destination_port:
                src_dst_ports[flow.source_ip].add(flow.destination_port)
            src_dst_hosts[flow.source_ip].add(flow.destination_ip)
            feat = features_map.get(self._flow_key(flow))
            if feat and feat.flow_duration < 1.0 and feat.total_fwd_packets <= 3:
                src_short_flows[flow.source_ip] += 1

        for src_ip, ports in src_dst_ports.items():
            port_count = len(ports)
            host_count = len(src_dst_hosts[src_ip])
            short_flows = src_short_flows.get(src_ip, 0)

            if port_count < 5 and host_count < 3:
                continue

            confidence = 0.0
            evidence: list[Evidence] = []

            if port_count >= 20:
                conf = min(port_count / 100, 1.0)
                confidence = max(confidence, conf)
                evidence.append(
                    Evidence(
                        feature="destination_port_fanout",
                        value=port_count,
                        baseline=5,
                        interpretation=f"Source {src_ip} contacted {port_count} unique destination ports",
                    )
                )
            elif port_count >= 10:
                conf = 0.4
                confidence = max(confidence, conf)

            if host_count >= 10:
                conf = min(host_count / 50, 1.0)
                confidence = max(confidence, conf)
                evidence.append(
                    Evidence(
                        feature="destination_host_fanout",
                        value=host_count,
                        baseline=3,
                        interpretation=f"Source {src_ip} contacted {host_count} unique destination hosts",
                    )
                )

            if short_flows >= 15:
                conf = min(short_flows / 50, 1.0)
                confidence = max(confidence, conf)
                evidence.append(
                    Evidence(
                        feature="short_lived_flows",
                        value=short_flows,
                        baseline=2,
                        interpretation=f"{short_flows} short-lived connection attempts from {src_ip}",
                    )
                )

            if port_count >= 10 and host_count == 1:
                confidence = max(confidence, 0.7)
                evidence.append(
                    Evidence(
                        feature="sequential_port_pattern",
                        value=port_count,
                        baseline=3,
                        interpretation=f"Source {src_ip} scanning {port_count} ports on single host",
                    )
                )

            if confidence > 0.3:
                severity = self._classify_severity(confidence)
                if port_count >= 50 or host_count >= 20:
                    severity = Severity.CRITICAL
                elif port_count >= 20 or host_count >= 10:
                    severity = Severity.HIGH

                results.append(
                    DetectorResult(
                        detector_name=self.name,
                        threat_class=self.threat_class,
                        confidence=min(confidence, 1.0),
                        severity=severity,
                        source_ip=src_ip,
                        destination_ip=list(src_dst_hosts[src_ip])[0] if src_dst_hosts[src_ip] else "",
                        flow_id=f"recon-{src_ip}",
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
