#!/usr/bin/env python3
"""
BeaconHunter - Advanced Network Threat Hunting & C2 Beaconing Detector.
Author: Said Hamidovic
"""

import sys
import os
import argparse
import json
from collections import defaultdict
from typing import Dict, List, Any

# Scapy imports
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

# Core modules
from core.analyzer import BeaconAnalyzer, FlowStats
from core.ja3 import extract_ja3_from_raw, lookup_ja3
from core.dns_hunter import DNSHunter
from core.reporter import ThreatReporter


def main():
    parser = argparse.ArgumentParser(
        description="BeaconHunter - C2 Beaconing, JA3 Fingerprinting & DNS Tunneling Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python hunter.py samples/c2_traffic.pcap --export-md report.md"
    )
    parser.add_argument("pcap", help="Path to PCAP / PCAPNG packet capture file")
    parser.add_argument("--threshold", type=float, default=40.0, help="Minimum beacon score to display (0-100, default: 40.0)")
    parser.add_argument("--export-md", help="Export findings to a professional Markdown incident report")
    parser.add_argument("--json", help="Export raw analysis findings to a JSON file")

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"[!] Error: File '{args.pcap}' not found.")
        sys.exit(1)

    reporter = ThreatReporter()
    reporter.print_banner()

    reporter.console.print(f"[bold cyan][*][/bold cyan] Ingesting and parsing packet stream from: [bold]{args.pcap}[/bold]...")

    flows: Dict[tuple, FlowStats] = {}
    dns_hunter = DNSHunter()
    ja3_matches: List[Dict[str, Any]] = []

    packet_count = 0
    first_ts = None
    last_ts = None

    try:
        # Stream packets using PcapReader for memory efficiency
        with PcapReader(args.pcap) as reader:
            for pkt in reader:
                packet_count += 1
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto_name = "OTHER"
                dst_port = 0

                ts = float(pkt.time)
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                # Layer 4 handling
                if pkt.haslayer(TCP):
                    proto_name = "TCP"
                    dst_port = pkt[TCP].dport
                    payload = bytes(pkt[TCP].payload)

                    # Inspect for TLS Client Hello / JA3
                    if dst_port in [443, 8443] or len(payload) > 5:
                        ja3_hash = extract_ja3_from_raw(payload)
                        if ja3_hash:
                            match = lookup_ja3(ja3_hash)
                            if match:
                                ja3_matches.append({
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "dst_port": dst_port,
                                    "hash": ja3_hash,
                                    "threat": match[0],
                                    "desc": match[1]
                                })

                elif pkt.haslayer(UDP):
                    proto_name = "UDP"
                    dst_port = pkt[UDP].dport

                    # Inspect DNS
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                        dns_hunter.process_query(src_ip, qname)

                # Flow key: (src_ip, dst_ip, dst_port, proto)
                flow_key = (src_ip, dst_ip, dst_port, proto_name)

                if flow_key not in flows:
                    flows[flow_key] = FlowStats(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=proto_name
                    )

                f = flows[flow_key]
                f.total_packets += 1
                f.total_bytes += len(pkt)
                f.timestamps.append(ts)

    except KeyboardInterrupt:
        reporter.console.print("\n[yellow][!] Processing interrupted by user. Analyzing gathered packets...[/yellow]")
    except Exception as e:
        reporter.console.print(f"[bold red][!] Error parsing PCAP:[/bold red] {e}")
        sys.exit(1)

    duration = (last_ts - first_ts) if (last_ts and first_ts) else 0.0

    reporter.console.print(f"[bold green][✔][/bold green] Processed {packet_count:,} packets across {len(flows)} communication flows.")
    reporter.console.print("[bold cyan][*][/bold cyan] Computing statistical periodicity, delta jitter and threat indicators...")

    # Run statistical analysis on flows
    analyzer = BeaconAnalyzer()
    analyzed_flows: List[FlowStats] = []

    for flow in flows.values():
        res = analyzer.analyze_flow(flow)
        analyzed_flows.append(res)

    dns_results = list(dns_hunter.domains.values())

    # Display findings
    reporter.display_results(
        flows=analyzed_flows,
        dns_findings=dns_results,
        ja3_matches=ja3_matches,
        total_packets=packet_count,
        duration=duration
    )

    # Export Markdown Report if requested
    if args.export_md:
        reporter.export_markdown(
            output_file=args.export_md,
            flows=analyzed_flows,
            dns_findings=dns_results,
            ja3_matches=ja3_matches,
            pcap_file=args.pcap
        )

    # Export JSON if requested
    if args.json:
        json_data = {
            "summary": {
                "total_packets": packet_count,
                "duration_seconds": duration,
                "flows_count": len(analyzed_flows),
            },
            "flows": [
                {
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "dst_port": f.dst_port,
                    "protocol": f.protocol,
                    "pulses": len(f.pulse_timestamps),
                    "mean_interval_sec": round(f.mean_interval, 2),
                    "jitter_percent": f.jitter_pct,
                    "beacon_score": f.beacon_score,
                    "threat_level": f.threat_level,
                    "reasons": f.reasons
                }
                for f in analyzed_flows if f.beacon_score >= args.threshold
            ],
            "ja3_matches": ja3_matches,
            "dns_anomalies": [
                {
                    "domain": d.domain,
                    "query_count": d.query_count,
                    "max_entropy": d.max_entropy,
                    "reasons": d.reasons
                }
                for d in dns_results if d.is_suspicious
            ]
        }
        with open(args.json, "w") as jf:
            json.dump(json_data, jf, indent=2)
        reporter.console.print(f"[bold green]✔ JSON findings exported to:[/bold green] [cyan]{args.json}[/cyan]")


if __name__ == "__main__":
    main()
