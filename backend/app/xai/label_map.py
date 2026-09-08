"""Map original dataset labels to NetGuard threat classes without mixing them."""

from __future__ import annotations

NETGUARD_CLASS_BY_LABEL: dict[str, str | None] = {
    "exfiltration": "Exfiltration",
    "data_exfiltration": "Exfiltration",
    "ftp-patator": "Exfiltration",
    "ssh-patator": "Exfiltration",
    "c2_beacon": "C2_Beacon",
    "c2": "C2_Beacon",
    "botnet": "C2_Beacon",
    "heartbleed": "C2_Beacon",
    "reconnaissance": "Reconnaissance",
    "portscan": "Reconnaissance",
    "port_scan": "Reconnaissance",
    "dns_tunnel": "DNS_Tunnel",
    "dns_tunnelling": "DNS_Tunnel",
    "dns_tunneling": "DNS_Tunnel",
    "ddos": "DDoS",
    "dos": "DDoS",
    "dos hulk": "DDoS",
    "dos goldeneye": "DDoS",
    "dos slowloris": "DDoS",
    "dga": "DGA",
    "infiltration": "Exfiltration",
    "web attack": "Encrypted_Threat",
    "normal": None,
    "benign": None,
}


def normalize_label(raw: str | None) -> str | None:
    if not raw:
        return None
    return raw.strip()


def map_dataset_label(raw: str | None) -> dict[str, str | None]:
    original = normalize_label(raw)
    if not original:
        return {
            "original_label": None,
            "netguard_class": None,
            "mapping_reason": None,
        }
    key = original.lower().replace("-", "_").replace(" ", "_")
    mapped = NETGUARD_CLASS_BY_LABEL.get(key)
    if mapped is None and key not in NETGUARD_CLASS_BY_LABEL:
        # Unknown original label: do not invent a mapping
        return {
            "original_label": original,
            "netguard_class": None,
            "mapping_reason": (
                f"Dataset ground truth is '{original}'. "
                "No NetGuard mapping is defined for this label."
            ),
        }
    if mapped is None:
        return {
            "original_label": original,
            "netguard_class": None,
            "mapping_reason": (
                f"Dataset ground truth identifies this traffic as '{original}'. "
                "NetGuard does not treat this label as a threat class."
            ),
        }
    return {
        "original_label": original,
        "netguard_class": mapped,
        "mapping_reason": (
            f"Dataset ground truth identifies this traffic as '{original}'. "
            f"NetGuard maps this behavior to {mapped} based on the observed "
            "flow/detection pattern, independently of the ground-truth label."
        ),
    }
