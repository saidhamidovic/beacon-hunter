"""
Statistical Beaconing & Flow Analyzer for C2 Detection.
"""

import math
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional


@dataclass
class FlowStats:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    total_packets: int = 0
    total_bytes: int = 0
    timestamps: List[float] = field(default_factory=list)
    pulse_timestamps: List[float] = field(default_factory=list)
    intervals: List[float] = field(default_factory=list)
    mean_interval: float = 0.0
    std_dev: float = 0.0
    cv: float = 0.0              # Coefficient of variation (std_dev / mean)
    jitter_pct: float = 0.0
    beacon_score: float = 0.0    # 0 to 100
    ja3_hashes: List[str] = field(default_factory=list)
    threat_level: str = "LOW"
    reasons: List[str] = field(default_factory=list)


class BeaconAnalyzer:
    def __init__(self, min_pulses: int = 4, burst_threshold: float = 1.0):
        """
        :param min_pulses: Minimum distinct connection pulses needed to analyze beaconing.
        :param burst_threshold: Packets within this window (seconds) are considered part of the same pulse.
        """
        self.min_pulses = min_pulses
        self.burst_threshold = burst_threshold

    def group_pulses(self, timestamps: List[float]) -> List[float]:
        """
        Groups rapid packet bursts into distinct connection check-in pulses.
        A beacon check-in typically consists of a cluster of packets (SYN, TLS, HTTP, FIN).
        We take the leading timestamp of each cluster.
        """
        if not timestamps:
            return []
        
        sorted_ts = sorted(timestamps)
        pulses = [sorted_ts[0]]

        for ts in sorted_ts[1:]:
            if (ts - pulses[-1]) >= self.burst_threshold:
                pulses.append(ts)
        return pulses

    def analyze_flow(self, flow: FlowStats) -> FlowStats:
        """
        Computes statistical periodicity and threat score for a communication flow.
        """
        pulses = self.group_pulses(flow.timestamps)
        flow.pulse_timestamps = pulses

        if len(pulses) < self.min_pulses:
            flow.threat_level = "INFO"
            flow.reasons.append(f"Insufficient pulses ({len(pulses)}/{self.min_pulses}) to determine periodicity")
            return flow

        # Calculate delta times between consecutive pulses
        intervals = [pulses[i + 1] - pulses[i] for i in range(len(pulses) - 1)]
        flow.intervals = intervals

        n = len(intervals)
        mean = sum(intervals) / n
        flow.mean_interval = mean

        # Standard deviation and Coefficient of Variation
        variance = sum((x - mean) ** 2 for x in intervals) / n
        std_dev = math.sqrt(variance)
        flow.std_dev = std_dev

        cv = (std_dev / mean) if mean > 0 else 1.0
        flow.cv = cv
        flow.jitter_pct = round(cv * 100, 1)

        # Base beaconing score calculation
        # Low CV (< 0.2) means highly regular intervals -> typical C2 heartbeat
        score = 0.0

        if cv < 0.10:
            score += 70.0
            flow.reasons.append(f"Extreme interval regularity (Jitter ~{flow.jitter_pct}%, CV={cv:.3f})")
        elif cv < 0.25:
            score += 55.0
            flow.reasons.append(f"High interval regularity / low jitter ({flow.jitter_pct}%, CV={cv:.3f})")
        elif cv < 0.40:
            score += 35.0
            flow.reasons.append(f"Moderate periodicity detected (Jitter {flow.jitter_pct}%)")
        else:
            score += 5.0

        # Pulse consistency multiplier
        pulse_boost = min(len(pulses) * 3, 20)  # Max +20 for persistent sessions
        score += pulse_boost
        if len(pulses) >= 8:
            flow.reasons.append(f"Persistent heartbeat observed across {len(pulses)} distinct check-ins")

        # Port context
        if flow.dst_port in [443, 80, 8080, 8443, 53]:
            # Common ports for covert C2
            score += 5.0
        elif flow.dst_port > 1024:
            score += 10.0
            flow.reasons.append(f"Periodic communication over non-standard high port ({flow.dst_port})")

        # Cap score at 100
        flow.beacon_score = min(round(score, 1), 100.0)

        # Threat classification
        if flow.beacon_score >= 80.0:
            flow.threat_level = "CRITICAL"
        elif flow.beacon_score >= 60.0:
            flow.threat_level = "HIGH"
        elif flow.beacon_score >= 40.0:
            flow.threat_level = "MEDIUM"
        else:
            flow.threat_level = "LOW"

        return flow
