"""
DNS Threat & Tunneling Analyzer.
Calculates Shannon Entropy and flags suspicious Domain Generation Algorithms (DGA) or Data Exfiltration.
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DNSFinding:
    domain: str
    query_count: int = 0
    max_subdomain_len: int = 0
    max_entropy: float = 0.0
    client_ips: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    reasons: List[str] = field(default_factory=list)


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy for a string."""
    if not text:
        return 0.0
    
    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


class DNSHunter:
    def __init__(self, entropy_threshold: float = 3.8, length_threshold: int = 35):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.domains: Dict[str, DNSFinding] = {}

    def process_query(self, client_ip: str, domain: str) -> Optional[DNSFinding]:
        """Processes a single DNS query and flags suspicious indicators."""
        clean_domain = domain.rstrip(".").lower()
        if not clean_domain:
            return None

        parts = clean_domain.split(".")
        subdomains = parts[:-2] if len(parts) > 2 else []
        subdomain_str = ".".join(subdomains)

        entropy = calculate_entropy(subdomain_str) if subdomain_str else calculate_entropy(parts[0])
        max_sub_len = len(subdomain_str)

        # Base registered domain (e.g. example.com)
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else clean_domain

        if base_domain not in self.domains:
            self.domains[base_domain] = DNSFinding(domain=base_domain)

        finding = self.domains[base_domain]
        finding.query_count += 1
        if client_ip not in finding.client_ips:
            finding.client_ips.append(client_ip)

        finding.max_entropy = max(finding.max_entropy, entropy)
        finding.max_subdomain_len = max(finding.max_subdomain_len, max_sub_len)

        # Evaluation
        if entropy >= self.entropy_threshold and max_sub_len > 15:
            finding.is_suspicious = True
            msg = f"High Shannon entropy ({entropy}) in subdomain (Possible exfil/DGA)"
            if msg not in finding.reasons:
                finding.reasons.append(msg)

        if max_sub_len >= self.length_threshold:
            finding.is_suspicious = True
            msg = f"Abnormally long subdomain ({max_sub_len} chars, possible DNS tunneling)"
            if msg not in finding.reasons:
                finding.reasons.append(msg)

        if finding.query_count > 50 and entropy > 3.5:
            finding.is_suspicious = True
            msg = f"High frequency queries ({finding.query_count}) with high entropy"
            if msg not in finding.reasons:
                finding.reasons.append(msg)

        return finding
