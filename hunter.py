#!/usr/bin/env python3
"""
BeaconHunter - Dual-Mode Network Threat Hunting & Intrusion Detection Engine.
Supports:
1. Offline PCAP Forensics (--pcap / positional argument)
2. Live Real-Time Network Sniffing & Exploitation Alerting (--sniff / -i)
Author: Said Hamidovic
"""

import sys
import os
import argparse
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

# Scapy imports
from scapy.utils import PcapReader
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.interfaces import get_if_list
from scapy.config import conf

# Core modules
from core.analyzer import BeaconAnalyzer, FlowStats
from core.ja3 import extract_ja3_from_raw, lookup_ja3
from core.dns_hunter import DNSHunter
from core.zerologon_hunter import ZeroLogonHunter
from core.reporter import ThreatReporter


class ThreatHunterEngine:
    def __init__(self, reporter: ThreatReporter, live_mode: bool = False):
        self.reporter = reporter
        self.live_mode = live_mode
        self.flows: Dict[tuple, FlowStats] = {}
        self.dns_hunter = DNSHunter()
        self.ja3_matches: List[Dict[str, Any]] = []
        self.zerologon_hunter = ZeroLogonHunter(alert_callback=self._live_alert)
        self.packet_count = 0
        self.first_ts = None
        self.last_ts = None

    def _live_alert(self, level: str, message: str):
        """Callback for real-time live intrusion events."""
        now = datetime.now().strftime("%H:%M:%S")
        prefix_map = {
            "CRITICAL": "[bold white on red] 🚨 CRITICAL [/bold white on red]",
            "WARNING": "[bold black on yellow] ⚠️  WARNING [/bold black on yellow]",
            "SUCCESS": "[bold white on green] ✔️  SUCCESS [/bold white on green]",
            "INFO": "[bold white on blue] ℹ️  INFO [/bold white on blue]"
        }
        prefix = prefix_map.get(level, f"[{level}]")
        self.reporter.console.print(f"[{now}] {prefix} {message}")

    def process_packet(self, pkt):
        self.packet_count += 1
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_name = "OTHER"
        dst_port = 0
        src_port = 0

        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts

        # Layer 4 handling
        if pkt.haslayer(TCP):
            proto_name = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            payload = bytes(pkt[TCP].payload)

            # 1. ZeroLogon (CVE-2020-1472 / MS-NRPC) Inspection
            if dst_port in [445, 135] or src_port in [445, 135] or len(payload) > 16:
                self.zerologon_hunter.process_packet(src_ip, dst_ip, src_port, dst_port, payload, ts)

            # 2. TLS Client Hello / JA3 Inspection
            if dst_port in [443, 8443] or len(payload) > 5:
                ja3_hash = extract_ja3_from_raw(payload)
                if ja3_hash:
                    match = lookup_ja3(ja3_hash)
                    if match:
                        record = {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "hash": ja3_hash,
                            "threat": match[0],
                            "desc": match[1]
                        }
                        if record not in self.ja3_matches:
                            self.ja3_matches.append(record)
                            if self.live_mode:
                                self._live_alert("WARNING", f"Malicious JA3 Fingerprint: {match[0]} ({match[1]}) from {src_ip} -> {dst_ip}")

        elif pkt.haslayer(UDP):
            proto_name = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            # 3. DNS Tunneling & Exfiltration Inspection
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                finding = self.dns_hunter.process_query(src_ip, qname)
                if finding and finding.is_suspicious and self.live_mode:
                    if finding.query_count in [1, 10, 25, 50]:
                        self._live_alert("WARNING", f"DNS Tunneling / High Entropy detected for domain: [bold cyan]{finding.domain}[/bold cyan] ({finding.max_entropy} entropy)")

        # Aggregate flow for Beaconing analysis
        flow_key = (src_ip, dst_ip, dst_port, proto_name)
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStats(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto_name
            )

        f = self.flows[flow_key]
        f.total_packets += 1
        f.total_bytes += len(pkt)
        f.timestamps.append(ts)


def run_pcap_mode(pcap_path: str, args, reporter: ThreatReporter):
    if not os.path.isfile(pcap_path):
        reporter.console.print(f"[bold red][!] Error:[/bold red] PCAP file '{pcap_path}' not found.")
        sys.exit(1)

    engine = ThreatHunterEngine(reporter, live_mode=False)
    reporter.console.print(f"[bold cyan][*] Ingesting and parsing offline PCAP:[/bold cyan] [bold]{pcap_path}[/bold]...")

    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                engine.process_packet(pkt)
    except KeyboardInterrupt:
        reporter.console.print("\n[yellow][!] Processing halted by user.[/yellow]")
    except Exception as e:
        reporter.console.print(f"[bold red][!] Error parsing PCAP:[/bold red] {e}")
        sys.exit(1)

    finalize_results(engine, pcap_path, args, reporter)


def run_live_sniff_mode(interface: Optional[str], bpf_filter: Optional[str], args, reporter: ThreatReporter):
    if not interface:
        interface = str(conf.iface)

    engine = ThreatHunterEngine(reporter, live_mode=True)
    reporter.console.print(f"[bold green][*] Mode:[/bold green] [bold white]LIVE NETWORK SNIFFING & THREAT DETECTION[/bold white]")
    reporter.console.print(f"[bold cyan][*] Listening on interface:[/bold cyan] [bold yellow]{interface}[/bold yellow]")
    if bpf_filter:
        reporter.console.print(f"[bold cyan][*] BPF Filter:[/bold cyan] [bold]{bpf_filter}[/bold]")
    reporter.console.print("[dim]Press Ctrl+C at any time to stop sniffing and generate summary report...[/dim]\n")

    try:
        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=engine.process_packet,
            store=0
        )
    except KeyboardInterrupt:
        reporter.console.print("\n[bold yellow][*] Live capture stopped by user. Generating analysis...[/bold yellow]")
    except PermissionError:
        reporter.console.print("[bold red][!] Permission denied:[/bold red] Live sniffing requires root/administrator privileges (run with sudo).")
        sys.exit(1)
    except Exception as e:
        reporter.console.print(f"[bold red][!] Sniffing error:[/bold red] {e}")
        sys.exit(1)

    finalize_results(engine, f"live:{interface}", args, reporter)


def finalize_results(engine: ThreatHunterEngine, source_name: str, args, reporter: ThreatReporter):
    duration = (engine.last_ts - engine.first_ts) if (engine.last_ts and engine.first_ts) else 0.0

    reporter.console.print(f"[bold green][✔][/bold green] Analyzed {engine.packet_count:,} packets across {len(engine.flows)} flows.")
    reporter.console.print("[bold cyan][*][/bold cyan] Computing statistical periodicity, delta jitter and threat indicators...")

    # Run beaconing analysis
    analyzer = BeaconAnalyzer()
    analyzed_flows = [analyzer.analyze_flow(f) for f in engine.flows.values()]
    dns_results = list(engine.dns_hunter.domains.values())
    zl_sessions = list(engine.zerologon_hunter.sessions.values())

    # Display final results
    reporter.display_results(
        flows=analyzed_flows,
        dns_findings=dns_results,
        ja3_matches=engine.ja3_matches,
        total_packets=engine.packet_count,
        duration=duration,
        zerologon_sessions=zl_sessions
    )

    # Export Markdown Report
    if args.export_md:
        reporter.export_markdown(
            output_file=args.export_md,
            flows=analyzed_flows,
            dns_findings=dns_results,
            ja3_matches=engine.ja3_matches,
            pcap_file=source_name,
            zerologon_sessions=zl_sessions
        )

    # Export JSON
    if args.json:
        json_data = {
            "summary": {
                "source": source_name,
                "total_packets": engine.packet_count,
                "duration_seconds": duration,
                "flows_count": len(analyzed_flows),
            },
            "zerologon_attacks": [
                {
                    "attacker_ip": s.client_ip,
                    "dc_ip": s.server_ip,
                    "zero_challenges": s.all_zero_challenges,
                    "zero_authentications": s.all_zero_authentications,
                    "bypass_success": s.auth_success_detected,
                    "password_reset_called": s.password_resets > 0,
                    "is_exploited": s.is_exploited
                }
                for s in zl_sessions if s.all_zero_authentications > 0 or s.is_exploited
            ],
            "beaconing_flows": [
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
            "ja3_matches": engine.ja3_matches,
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


def main():
    parser = argparse.ArgumentParser(
        description="BeaconHunter - Dual-Mode Threat Hunter (C2 Beaconing, ZeroLogon CVE-2020-1472, JA3, DNS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  1. Offline PCAP Analysis:\n"
               "     python hunter.py samples/c2_traffic.pcap --export-md report.md\n\n"
               "  2. Live Sniffing & Real-Time Alerting (requires sudo):\n"
               "     sudo python hunter.py --sniff -i eth0\n"
               "     sudo python hunter.py --sniff -i eth0 --bpf 'tcp port 445 or tcp port 135'\n"
    )
    parser.add_argument("pcap", nargs="?", help="Path to PCAP / PCAPNG packet capture file (for offline mode)")
    parser.add_argument("--sniff", "--live", action="store_true", help="Enable active live network sniffing mode")
    parser.add_argument("-i", "--interface", help="Network interface for live sniffing (e.g. eth0, en0, wlan0)")
    parser.add_argument("--bpf", help="BPF filter for live sniffing (e.g. 'tcp port 445 or udp port 53')")
    parser.add_argument("--threshold", type=float, default=40.0, help="Minimum beacon score to display (0-100, default: 40.0)")
    parser.add_argument("--export-md", help="Export findings to a professional Markdown incident report")
    parser.add_argument("--json", help="Export raw analysis findings to a JSON file")

    args = parser.parse_args()

    reporter = ThreatReporter()
    reporter.print_banner()

    # Determine mode
    if args.sniff:
        run_live_sniff_mode(args.interface, args.bpf, args, reporter)
    elif args.pcap:
        run_pcap_mode(args.pcap, args, reporter)
    else:
        # Show help and interface list if no arguments given
        reporter.console.print("[bold yellow][!] No input specified.[/bold yellow] Provide a PCAP file or use '--sniff' for live monitoring.")
        reporter.console.print(f"[dim]Available network interfaces: {', '.join(get_if_list())}[/dim]\n")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
