"""
ZeroLogon (CVE-2020-1472 / MS-NRPC) Exploit & Anomaly Detector.
Monitors SMB/RPC traffic for all-zero client challenges, authentication brute-forcing,
and unauthorized NetrServerPasswordSet2 machine account password resets.
"""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable
from rich.console import Console

# MS-NRPC (Netlogon) Interface UUID: 12345678-1234-abcd-ef00-01234567cffb
NETLOGON_UUID_LE = b"\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\xcf\xfb"
ALL_ZEROS_8 = b"\x00\x00\x00\x00\x00\x00\x00\x00"

# MS-NRPC Opnums
OPNUM_REQ_CHALLENGE = 4         # NetrServerReqChallenge
OPNUM_AUTH3 = 26                # NetrServerAuthenticate3
OPNUM_PASSWORD_SET2 = 30        # NetrServerPasswordSet2 (Exploit payload)


@dataclass
class ZeroLogonSession:
    client_ip: str
    server_ip: str
    bind_detected: bool = False
    all_zero_challenges: int = 0
    all_zero_authentications: int = 0
    password_resets: int = 0
    auth_success_detected: bool = False
    start_time: float = 0.0
    last_time: float = 0.0
    is_exploited: bool = False
    alerts_triggered: List[str] = field(default_factory=list)


class ZeroLogonHunter:
    def __init__(self, console: Optional[Console] = None, alert_callback: Optional[Callable[[str, str], None]] = None):
        self.console = console or Console()
        self.alert_callback = alert_callback
        # Key: (client_ip, server_ip)
        self.sessions: Dict[Tuple[str, str], ZeroLogonSession] = {}

    def _get_session(self, client_ip: str, server_ip: str, timestamp: float) -> ZeroLogonSession:
        key = (client_ip, server_ip)
        if key not in self.sessions:
            self.sessions[key] = ZeroLogonSession(
                client_ip=client_ip,
                server_ip=server_ip,
                start_time=timestamp,
                last_time=timestamp
            )
        session = self.sessions[key]
        session.last_time = timestamp
        return session

    def process_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, timestamp: float) -> Optional[str]:
        """
        Inspects TCP payload for MSRPC / Netlogon CVE-2020-1472 indicators.
        Returns an alert message string if a critical event occurred.
        """
        if not payload or len(payload) < 16:
            return None

        # Look for Netlogon UUID Bind (Port 445 SMB or Port 135/Dynamic RPC)
        if NETLOGON_UUID_LE in payload or b"netlogon" in payload.lower():
            session = self._get_session(src_ip, dst_ip, timestamp)
            if not session.bind_detected:
                session.bind_detected = True
                msg = f"[bold yellow][*] MSRPC Bind to Netlogon UUID detected from {src_ip} -> {dst_ip}[/bold yellow]"
                if self.alert_callback:
                    self.alert_callback("INFO", msg)
                return msg

        # Search for DCERPC PDU header (Major: 0x05, Minor: 0x00)
        rpc_idx = payload.find(b"\x05\x00")
        while rpc_idx != -1 and rpc_idx + 24 <= len(payload):
            pdu_type = payload[rpc_idx + 2]

            # 0x00 = DCERPC Request
            if pdu_type == 0x00 and rpc_idx + 24 <= len(payload):
                try:
                    opnum = struct.unpack("<H", payload[rpc_idx + 22 : rpc_idx + 24])[0]
                    req_payload = payload[rpc_idx + 24:]
                    session = self._get_session(src_ip, dst_ip, timestamp)

                    # 1. NetrServerReqChallenge (Opnum 4)
                    if opnum == OPNUM_REQ_CHALLENGE:
                        if ALL_ZEROS_8 in req_payload:
                            session.all_zero_challenges += 1
                            if session.all_zero_challenges == 1:
                                msg = f"[bold orange1][!] ZeroLogon Indicator: All-Zero Client Challenge (\\x00*8) sent by {src_ip} -> {dst_ip} (Opnum 4)[/bold orange1]"
                                session.alerts_triggered.append(msg)
                                if self.alert_callback:
                                    self.alert_callback("WARNING", msg)
                                return msg

                    # 2. NetrServerAuthenticate3 (Opnum 26)
                    elif opnum == OPNUM_AUTH3:
                        if ALL_ZEROS_8 in req_payload:
                            session.all_zero_authentications += 1
                            # Trigger milestone alerts
                            if session.all_zero_authentications in [10, 50, 100, 200, 300]:
                                duration = max(session.last_time - session.start_time, 0.1)
                                rate = session.all_zero_authentications / duration
                                msg = f"[bold red][!] CVE-2020-1472 Brute-Force in Progress: {session.all_zero_authentications} all-zero auth attempts from {src_ip} ({rate:.1f} req/s)[/bold red]"
                                session.alerts_triggered.append(msg)
                                if self.alert_callback:
                                    self.alert_callback("CRITICAL", msg)
                                return msg

                    # 3. NetrServerPasswordSet2 (Opnum 30) - THE EXPLOIT PAYLOAD!
                    elif opnum == OPNUM_PASSWORD_SET2:
                        session.password_resets += 1
                        session.is_exploited = True
                        msg = (
                            f"[blink bold white on red]🚨 CRITICAL ALERT: CVE-2020-1472 (ZeroLogon) EXPLOITED! 🚨[/blink bold white on red]\n"
                            f"  [bold red]Attacker:[/bold red] {src_ip}\n"
                            f"  [bold red]Victim DC:[/bold red] {dst_ip}\n"
                            f"  [bold red]Payload:[/bold red] NetrServerPasswordSet2 executed (Machine account password reset to empty string!)"
                        )
                        session.alerts_triggered.append(msg)
                        if self.alert_callback:
                            self.alert_callback("CRITICAL", msg)
                        return msg

                except Exception:
                    pass

            # 0x02 = DCERPC Response
            elif pdu_type == 0x02 and rpc_idx + 28 <= len(payload):
                try:
                    # In MSRPC responses, status code is typically at the end of the PDU
                    # 0x00000000 = STATUS_SUCCESS
                    # 0xc0000022 = STATUS_ACCESS_DENIED
                    session = self._get_session(dst_ip, src_ip, timestamp)
                    if session.all_zero_authentications > 0:
                        status_code = struct.unpack("<I", payload[rpc_idx + 24 : rpc_idx + 28])[0]
                        if status_code == 0x00000000:
                            session.auth_success_detected = True
                            msg = f"[bold green][✔] ZeroLogon Cryptographic Collision Bypassed! DC {src_ip} returned STATUS_SUCCESS to {dst_ip}![/bold green]"
                            session.alerts_triggered.append(msg)
                            if self.alert_callback:
                                self.alert_callback("SUCCESS", msg)
                            return msg
                except Exception:
                    pass

            # Move past this PDU
            rpc_idx = payload.find(b"\x05\x00", rpc_idx + 2)

        return None
