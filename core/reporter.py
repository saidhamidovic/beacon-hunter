"""
Terminal & Report Generation with Rich.
Exports terminal tables and professional Markdown incident reports.
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from core.analyzer import FlowStats
from core.dns_hunter import DNSFinding


BANNER = r"""
[bold cyan]
  ____                                 _   _             _            
 | __ )  ___  __ _  ___ ___  _ __     | | | |_   _ _ __ | |_ ___ _ __ 
 |  _ \ / _ \/ _` |/ __/ _ \| '_ \ ___| |_| | | | | '_ \| __/ _ \ '__|
 | |_) |  __/ (_| | (_| (_) | | | |___|  _  | |_| | | | | ||  __/ |   
 |____/ \___|\__,_|\___\___/|_| |_|   |_| |_|\__,_|_| |_|\__\___|_|   
[/bold cyan]
[dim]Advanced C2 Beaconing, JA3 Fingerprinting & DNS Tunneling Hunter v1.0[/dim]
"""


class ThreatReporter:
    def __init__(self):
        self.console = Console()

    def print_banner(self):
        self.console.print(BANNER)

    def display_results(
        self,
        flows: List[FlowStats],
        dns_findings: List[DNSFinding],
        ja3_matches: List[Dict[str, Any]],
        total_packets: int,
        duration: float
    ):
        self.console.print()
        
        # Summary Box
        critical_flows = [f for f in flows if f.threat_level in ["CRITICAL", "HIGH"]]
        suspicious_dns = [d for d in dns_findings if d.is_suspicious]

        summary_text = Text()
        summary_text.append(f"Total Packets: {total_packets:,}  |  ", style="bold white")
        summary_text.append(f"Analyzed Flows: {len(flows)}  |  ", style="bold white")
        summary_text.append(f"Capture Duration: {duration:.1f}s\n", style="bold white")
        summary_text.append(f"🚨 Critical/High Beacons: {len(critical_flows)}   ", style="bold red" if critical_flows else "bold green")
        summary_text.append(f"🔍 Suspicious DNS Domains: {len(suspicious_dns)}   ", style="bold yellow" if suspicious_dns else "bold green")
        summary_text.append(f"🎯 Known JA3 Threat Matches: {len(ja3_matches)}", style="bold magenta" if ja3_matches else "bold green")

        self.console.print(Panel(summary_text, title="[bold white]Investigation Summary[/bold white]", border_style="blue"))
        self.console.print()

        # 1. C2 Beaconing Flow Table
        table = Table(title="[bold red]Detected Potential C2 Beaconing Flows[/bold red]", header_style="bold magenta")
        table.add_column("Threat Level", justify="center")
        table.add_column("Client IP", style="cyan")
        table.add_column("Destination", style="bold")
        table.add_column("Proto", justify="center")
        table.add_column("Pulses", justify="right")
        table.add_column("Mean Intvl", justify="right")
        table.add_column("Jitter", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Key Findings", style="dim")

        sorted_flows = sorted(flows, key=lambda x: x.beacon_score, reverse=True)
        display_flows = [f for f in sorted_flows if f.beacon_score >= 30.0]

        if not display_flows:
            self.console.print("[dim green]✔ No periodic beaconing detected above threshold.[/dim green]\n")
        else:
            for f in display_flows:
                style_map = {
                    "CRITICAL": "[bold red]CRITICAL[/bold red]",
                    "HIGH": "[bold orange1]HIGH[/bold orange1]",
                    "MEDIUM": "[yellow]MEDIUM[/yellow]",
                    "LOW": "[green]LOW[/green]",
                    "INFO": "[dim]INFO[/dim]",
                }
                level_str = style_map.get(f.threat_level, f.threat_level)
                dst_str = f"{f.dst_ip}:{f.dst_port}"
                intvl_str = f"{f.mean_interval:.1f}s"
                jitter_str = f"{f.jitter_pct:.1f}%"
                score_str = f"{f.beacon_score:.0f}/100"
                findings = "; ".join(f.reasons[:2])

                table.add_row(
                    level_str,
                    f.src_ip,
                    dst_str,
                    f.protocol,
                    str(len(f.pulse_timestamps)),
                    intvl_str,
                    jitter_str,
                    score_str,
                    findings
                )
            self.console.print(table)
            self.console.print()

        # 2. Known JA3 Matches Table
        if ja3_matches:
            ja3_table = Table(title="[bold magenta]Known C2 / Threat JA3 Fingerprints[/bold magenta]", header_style="bold cyan")
            ja3_table.add_column("Client IP", style="cyan")
            ja3_table.add_column("Destination", style="bold")
            ja3_table.add_column("JA3 Hash", style="yellow")
            ja3_table.add_column("Matched Threat", style="bold red")
            ja3_table.add_column("Description", style="white")

            for match in ja3_matches:
                ja3_table.add_row(
                    match["src_ip"],
                    f"{match['dst_ip']}:{match['dst_port']}",
                    match["hash"][:16] + "...",
                    match["threat"],
                    match["desc"]
                )
            self.console.print(ja3_table)
            self.console.print()

        # 3. DNS Anomalies Table
        if suspicious_dns:
            dns_table = Table(title="[bold yellow]Suspicious DNS Queries (Tunneling / DGA)[/bold yellow]", header_style="bold yellow")
            dns_table.add_column("Domain", style="bold cyan")
            dns_table.add_column("Query Count", justify="right")
            dns_table.add_column("Max Entropy", justify="right")
            dns_table.add_column("Max Subdomain Len", justify="right")
            dns_table.add_column("Indicators", style="dim")

            for d in suspicious_dns:
                entropy_style = "[bold red]" if d.max_entropy >= 3.8 else "[white]"
                dns_table.add_row(
                    d.domain,
                    str(d.query_count),
                    f"{entropy_style}{d.max_entropy:.2f}[/]",
                    f"{d.max_subdomain_len} chars",
                    "; ".join(d.reasons)
                )
            self.console.print(dns_table)
            self.console.print()

    def export_markdown(
        self,
        output_file: str,
        flows: List[FlowStats],
        dns_findings: List[DNSFinding],
        ja3_matches: List[Dict[str, Any]],
        pcap_file: str
    ):
        """Exports an enterprise-grade Markdown SOC Incident Report."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        critical_flows = [f for f in flows if f.threat_level in ["CRITICAL", "HIGH"]]
        suspicious_dns = [d for d in dns_findings if d.is_suspicious]

        md = f"""# 🛡️ BeaconHunter Forensics & Threat Hunting Report
**Generated on:** {now}  
**Source PCAP:** `{pcap_file}`  

---

## 1. Executive Summary

BeaconHunter analyzed the provided packet capture for automated Command-and-Control (C2) heartbeats, periodic beaconing heuristics, known malicious JA3 TLS fingerprints, and DNS data tunneling/exfiltration.

* **High/Critical C2 Beacons Detected:** `{len(critical_flows)}`
* **Suspicious DNS Queries (Tunneling/DGA):** `{len(suspicious_dns)}`
* **Known Malicious JA3 Matches:** `{len(ja3_matches)}`

### MITRE ATT&CK® Mapping
* **T1071.001 - Application Layer Protocol: Web Protocols** (Periodic HTTP/HTTPS Beaconing)
* **T1071.004 - Application Layer Protocol: DNS** (High-entropy queries & data exfiltration)
* **T1573 - Encrypted Channel** (Symmetric/Asymmetric C2 encryption & JA3 profiling)

---

## 2. Critical & High Periodic Flows (C2 Candidates)

| Threat Level | Source IP | Destination | Proto | Pulses | Mean Interval | Jitter (%) | Beacon Score | Indicators |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
"""

        for f in critical_flows:
            md += f"| **{f.threat_level}** | `{f.src_ip}` | `{f.dst_ip}:{f.dst_port}` | {f.protocol} | {len(f.pulse_timestamps)} | {f.mean_interval:.1f}s | {f.jitter_pct:.1f}% | `{f.beacon_score:.0f}/100` | {'; '.join(f.reasons)} |\n"

        if not critical_flows:
            md += "| *None* | - | - | - | - | - | - | - | No critical periodic flows detected |\n"

        md += "\n---\n\n## 3. Known JA3 TLS Fingerprint Matches\n\n"
        if ja3_matches:
            md += "| Client IP | Destination | JA3 Hash | Identified Threat | Description |\n| :--- | :--- | :--- | :--- | :--- |\n"
            for m in ja3_matches:
                md += f"| `{m['src_ip']}` | `{m['dst_ip']}:{m['dst_port']}` | `{m['hash']}` | **{m['threat']}** | {m['desc']} |\n"
        else:
            md += "*No matching malicious JA3 fingerprints detected.*\n"

        md += "\n---\n\n## 4. Suspicious DNS Activity (Tunneling & DGA)\n\n"
        if suspicious_dns:
            md += "| Base Domain | Queries | Max Entropy | Max Subdomain Length | Observed Anomalies |\n| :--- | :---: | :---: | :---: | :--- |\n"
            for d in suspicious_dns:
                md += f"| `{d.domain}` | {d.query_count} | `{d.max_entropy:.2f}` | {d.max_subdomain_len} chars | {'; '.join(d.reasons)} |\n"
        else:
            md += "*No high-entropy or anomalous DNS queries detected.*\n"

        md += "\n---\n*Report compiled by BeaconHunter v1.0 - Author: Said Hamidovic*\n"

        with open(output_file, "w") as f:
            f.write(md)

        self.console.print(f"[bold green]✔ Forensic report successfully exported to:[/bold green] [cyan]{output_file}[/cyan]")
