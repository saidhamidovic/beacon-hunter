#!/usr/bin/env python3
"""
Synthetic PCAP Generator for BeaconHunter Testing.
Creates a realistic traffic capture containing:
1. Normal user web browsing (randomized intervals, non-periodic).
2. Realistic C2 Beaconing (periodic intervals with ~10% jitter).
3. High-entropy DNS Tunneling / Data exfiltration.
"""

import os
import random
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.utils import wrpcap


def generate_synthetic_pcap(output_path: str = "samples/c2_traffic_sample.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = []
    
    base_time = 1700000000.0  # Stable baseline timestamp
    client_ip = "192.168.1.105"

    print("[*] Generating synthetic benign and malicious traffic...")

    # -------------------------------------------------------------
    # 1. Normal Web Traffic (Bursty, non-periodic)
    # -------------------------------------------------------------
    benign_servers = ["142.250.190.46", "140.82.121.3", "151.101.1.140"]
    cur_time = base_time

    for _ in range(15):
        # Human browsing has irregular delays (between 5 and 65 seconds)
        cur_time += random.uniform(5.0, 65.0)
        target = random.choice(benign_servers)

        sport = random.randint(49152, 65535)
        p1 = IP(src=client_ip, dst=target) / TCP(sport=sport, dport=443, flags="S")
        p1.time = cur_time

        p2 = IP(src=target, dst=client_ip) / TCP(sport=443, dport=sport, flags="SA")
        p2.time = cur_time + 0.02

        p3 = IP(src=client_ip, dst=target) / TCP(sport=sport, dport=443, flags="A")
        p3.time = cur_time + 0.03

        packets.extend([p1, p2, p3])

    # -------------------------------------------------------------
    # 2. C2 Beaconing Traffic (Cobalt Strike / Sliver style)
    # Target: 198.51.100.44:8443 (Periodic 30s interval with ~10% jitter)
    # -------------------------------------------------------------
    c2_ip = "198.51.100.44"
    c2_port = 8443
    beacon_interval = 30.0  # 30 seconds
    jitter_range = 3.0      # +/- 3 seconds (10% jitter)
    cur_time = base_time + 10.0

    print("[*] Injecting simulated C2 beaconing (30s interval, 10% jitter, 10 pulses)...")

    for _ in range(10):
        # Add jitter
        interval = beacon_interval + random.uniform(-jitter_range, jitter_range)
        cur_time += interval

        sport = random.randint(50000, 60000)
        syn = IP(src=client_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="S")
        syn.time = cur_time

        syn_ack = IP(src=c2_ip, dst=client_ip) / TCP(sport=c2_port, dport=sport, flags="SA")
        syn_ack.time = cur_time + 0.015

        ack = IP(src=client_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="A")
        ack.time = cur_time + 0.02

        payload = IP(src=client_ip, dst=c2_ip) / TCP(sport=sport, dport=c2_port, flags="PA") / b"POST /api/v1/heartbeat HTTP/1.1\r\nHost: c2.internal\r\n\r\n"
        payload.time = cur_time + 0.03

        packets.extend([syn, syn_ack, ack, payload])

    # -------------------------------------------------------------
    # 3. DNS Traffic (Mix of legitimate and High-Entropy Exfil)
    # -------------------------------------------------------------
    dns_server = "192.168.1.1"

    # Legitimate queries
    legit_domains = ["google.com", "github.com", "microsoft.com", "weather.com"]
    for d in legit_domains:
        t = base_time + random.uniform(1.0, 300.0)
        dns_pkt = IP(src=client_ip, dst=dns_server) / UDP(sport=random.randint(50000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=d))
        dns_pkt.time = t
        packets.append(dns_pkt)

    # Malicious high-entropy DNS tunneling queries
    print("[*] Injecting simulated high-entropy DNS exfiltration queries...")
    exfil_subdomains = [
        "a9f4c3b2e1d7045a89bc21.exfil.threat-actor.org",
        "7b8c9d0e1f2a3b4c5d6e7f.exfil.threat-actor.org",
        "f1e2d3c4b5a69788776655.exfil.threat-actor.org",
        "4a5b6c7d8e9f0a1b2c3d4e.exfil.threat-actor.org",
        "deadbeef0123456789abcdef.exfil.threat-actor.org",
    ]

    for sub in exfil_subdomains:
        t = base_time + random.uniform(20.0, 250.0)
        exfil_pkt = IP(src=client_ip, dst=dns_server) / UDP(sport=random.randint(50000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=sub))
        exfil_pkt.time = t
        packets.append(exfil_pkt)

    # Sort all packets strictly by timestamp
    packets.sort(key=lambda p: float(p.time))

    wrpcap(output_path, packets)
    print(f"[✔] Successfully generated sample PCAP with {len(packets)} packets at: {output_path}")


if __name__ == "__main__":
    generate_synthetic_pcap()
