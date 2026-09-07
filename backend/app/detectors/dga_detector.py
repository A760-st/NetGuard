import math
from collections import Counter, defaultdict
from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence, as_timestamp


class DGADetector(BaseDetector):
    def __init__(self):
        super().__init__()
        self.name = "DGADetector"
        self.threat_class = ThreatClass.DGA

    def _domain_entropy(self, domain: str) -> float:
        if not domain:
            return 0.0
        freq = Counter(domain.lower())
        length = len(domain)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _dga_score(self, domain: str) -> float:
        if not domain or len(domain) < 5:
            return 0.0

        score = 0.0
        domain = domain.lower().split(".")[0]

        entropy = self._domain_entropy(domain)
        if entropy > 3.5:
            score += 0.3
        elif entropy > 3.0:
            score += 0.15

        if len(domain) > 15:
            score += 0.15

        vowel_count = sum(1 for c in domain if c in "aeiou")
        vowel_ratio = vowel_count / len(domain) if domain else 0
        if vowel_ratio < 0.15:
            score += 0.2

        consec_consonants = 0
        max_consec = 0
        for c in domain:
            if c.isalpha() and c not in "aeiou":
                consec_consonants += 1
                max_consec = max(max_consec, consec_consonants)
            else:
                consec_consonants = 0
        if max_consec > 4:
            score += 0.15

        has_digits = any(c.isdigit() for c in domain)
        digit_count = sum(1 for c in domain if c.isdigit())
        if has_digits and digit_count / len(domain) > 0.3:
            score += 0.1

        unique_chars = len(set(domain))
        if unique_chars / len(domain) > 0.8 and len(domain) > 10:
            score += 0.1

        return min(score, 1.0)

    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        results: list[DetectorResult] = []

        dns_queries = []
        for flow in flows:
            feat = features_map.get(self._flow_key(flow))
            if feat and flow.destination_port == 53:
                dns_queries.append((flow, feat))

            if hasattr(flow, "features") and flow.features:
                query_names = flow.features.get("dns_query_names", [])
                for qname in query_names:
                    score = self._dga_score(qname)
                    if score > 0.4:
                        results.append(
                            DetectorResult(
                                detector_name=self.name,
                                threat_class=self.threat_class,
                                confidence=score,
                                severity=self._classify_severity(score),
                                source_ip=flow.source_ip,
                                destination_ip=flow.destination_ip,
                                flow_id=self._flow_key(flow),
                                timestamp=as_timestamp(flow.last_seen),
                                supporting_evidence=[
                                    Evidence(
                                        feature="domain_dga_score",
                                        value=round(score, 3),
                                        baseline=0.2,
                                        interpretation=f"Domain '{qname}' has DGA score {score:.2f}",
                                    ),
                                    Evidence(
                                        feature="domain_entropy",
                                        value=round(self._domain_entropy(qname), 3),
                                        baseline=2.5,
                                        interpretation=f"High entropy ({self._domain_entropy(qname):.2f}) suggests random generation",
                                    ),
                                ],
                            )
                        )

        return results

    def _flow_key(self, flow) -> str:
        return (
            f"{flow.source_ip}:{getattr(flow, 'source_port', 0)}-"
            f"{flow.destination_ip}:{getattr(flow, 'destination_port', 0)}-"
            f"{flow.protocol}"
        )
