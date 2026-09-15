"""
Exploit & CVE Signature Detection Engine.
Matches network traffic payloads against known exploit patterns, CVEs, and Exploit-DB signatures.
"""

import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any


@dataclass
class ExploitMatch:
    rule_id: str
    name: str
    cve: str
    edb_id: str
    mitre_attack: str
    severity: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    timestamp: float
    description: str
    snippet: str


class ExploitSignatureEngine:
    def __init__(self, rules_file: Optional[str] = None, alert_callback: Optional[Callable[[str, str], None]] = None):
        self.alert_callback = alert_callback
        self.rules: List[Dict[str, Any]] = []
        self.compiled_rules: List[Dict[str, Any]] = []
        self.matches: List[ExploitMatch] = []

        default_rules = os.path.join(os.path.dirname(__file__), "..", "rules", "exploit_signatures.json")
        target_rules = rules_file or default_rules
        self.load_rules(target_rules)

    def load_rules(self, rules_file: str):
        """Loads and compiles signatures from a JSON rule definition file."""
        if not os.path.isfile(rules_file):
            return

        try:
            with open(rules_file, "r") as f:
                self.rules = json.load(f)

            self.compiled_rules = []
            for r in self.rules:
                p_type = r.get("pattern_type", "regex")
                pattern = r.get("pattern", "")

                compiled_obj = None
                if p_type == "regex":
                    compiled_obj = re.compile(pattern.encode("utf-8", errors="ignore"))
                elif p_type == "hex":
                    try:
                        compiled_obj = bytes.fromhex(pattern)
                    except Exception:
                        compiled_obj = pattern.encode("ascii")
                elif p_type == "string":
                    compiled_obj = pattern.encode("utf-8", errors="ignore")

                self.compiled_rules.append({
                    "meta": r,
                    "compiled": compiled_obj,
                    "type": p_type
                })
        except Exception as e:
            print(f"[!] Error loading exploit rules: {e}")

    def inspect_payload(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        payload: bytes,
        timestamp: float
    ) -> Optional[ExploitMatch]:
        """Scans packet payload against all loaded exploit signatures."""
        if not payload or len(payload) < 4:
            return None

        for rule in self.compiled_rules:
            meta = rule["meta"]
            ports = meta.get("ports", [])
            proto = meta.get("protocol", "ANY")

            # Check protocol and port filters if specified
            if proto != "ANY" and proto != protocol:
                continue
            if ports and (dst_port not in ports and src_port not in ports):
                continue

            matched = False
            snippet = ""
            p_type = rule["type"]
            compiled = rule["compiled"]

            if p_type == "regex" and compiled:
                m = compiled.search(payload)
                if m:
                    matched = True
                    start, end = max(0, m.start() - 10), min(len(payload), m.end() + 20)
                    snippet = payload[start:end].decode("utf-8", errors="replace").strip()

            elif p_type in ["hex", "string"] and compiled:
                idx = payload.find(compiled)
                if idx != -1:
                    matched = True
                    start, end = max(0, idx - 10), min(len(payload), idx + len(compiled) + 20)
                    snippet = payload[start:end].hex() if p_type == "hex" else payload[start:end].decode("utf-8", errors="replace").strip()

            if matched:
                match_obj = ExploitMatch(
                    rule_id=meta["id"],
                    name=meta["name"],
                    cve=meta["cve"],
                    edb_id=meta.get("edb_id", "N/A"),
                    mitre_attack=meta.get("mitre_attack", "N/A"),
                    severity=meta.get("severity", "HIGH"),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    timestamp=timestamp,
                    description=meta.get("description", ""),
                    snippet=snippet[:60]
                )

                # Avoid duplicate identical alerts in short window
                if not any(m.rule_id == match_obj.rule_id and m.src_ip == src_ip and m.dst_ip == dst_ip for m in self.matches):
                    self.matches.append(match_obj)
                    if self.alert_callback:
                        msg = (
                            f"[bold red]EXPLOIT DETECTED:[/bold red] [bold white]{match_obj.name}[/bold white] "
                            f"([yellow]{match_obj.cve}[/yellow] | [cyan]{match_obj.edb_id}[/cyan]) "
                            f"from {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                        )
                        self.alert_callback(match_obj.severity, msg)
                    return match_obj

        return None
