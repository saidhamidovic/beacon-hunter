"""
JA3 Fingerprinting Engine for TLS Client Hello Packets.
Extracts TLS parameters and hashes them according to Salesforce JA3 specification.
"""

import hashlib
import struct
from typing import Optional, Tuple, Dict

# Reference database of notable known JA3 hashes
KNOWN_JA3_DATABASE: Dict[str, Tuple[str, str]] = {
    # Cobalt Strike default malleable profiles
    "a0e9f5d64349fb13191bc781f81f42e1": ("Cobalt Strike", "Default C2 malleable profile"),
    "b32309a26951912be7dba376398abc3b": ("Cobalt Strike", "Win10 TLS Client Hello default"),
    "3b5074b1b082c616609d6fa3771317ff": ("Sliver C2", "Default implant TLS handshake"),
    "6734f37431670b3ab4292b8f60f29984": ("Metasploit", "Meterpreter reverse_https payload"),
    "72a589da586844d7f0818ce684948eea": ("TrickBot / Emotet", "Banking trojan / dropper C2"),
    "b845763567822fe8c3a15291b8686cf1": ("PowerShell / WinRM", "Invoke-WebRequest / Empire agent"),
    "35f3b772097e33550dc9a7213897c485": ("Go C2 Agent", "Standard Go net/http client (Havoc/Sliver)"),
    "c12f54eb865ad61e2f7b8fb5cb02f1f5": ("Python Requests", "Scripted automated bot/implant"),
}

GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def is_grease(val: int) -> bool:
    return val in GREASE_TABLE


def extract_ja3_from_raw(payload: bytes) -> Optional[str]:
    """
    Parses raw TLS Record layer bytes to compute the JA3 fingerprint.
    Specification: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    """
    try:
        if len(payload) < 5:
            return None

        content_type = payload[0]
        if content_type != 22:  # Handshake
            return None

        legacy_version = struct.unpack("!H", payload[1:3])[0]
        record_len = struct.unpack("!H", payload[3:5])[0]

        if len(payload) < 5 + record_len:
            return None

        # Handshake Header
        handshake = payload[5:]
        handshake_type = handshake[0]
        if handshake_type != 1:  # Client Hello
            return None

        # Client Version
        client_version = struct.unpack("!H", handshake[4:6])[0]

        # Skip Random (32 bytes)
        idx = 6 + 32

        # Session ID Length
        session_id_len = handshake[idx]
        idx += 1 + session_id_len

        # Cipher Suites
        cipher_suites_len = struct.unpack("!H", handshake[idx:idx+2])[0]
        idx += 2
        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            cs = struct.unpack("!H", handshake[idx+i:idx+i+2])[0]
            if not is_grease(cs):
                cipher_suites.append(str(cs))
        idx += cipher_suites_len

        # Compression Methods
        comp_methods_len = handshake[idx]
        idx += 1 + comp_methods_len

        # Extensions
        extensions = []
        elliptic_curves = []
        ec_point_formats = []

        if idx < len(handshake):
            ext_total_len = struct.unpack("!H", handshake[idx:idx+2])[0]
            idx += 2
            end_idx = idx + ext_total_len

            while idx + 4 <= end_idx and idx + 4 <= len(handshake):
                ext_type = struct.unpack("!H", handshake[idx:idx+2])[0]
                ext_len = struct.unpack("!H", handshake[idx+2:idx+4])[0]
                idx += 4

                if not is_grease(ext_type):
                    extensions.append(str(ext_type))

                # Supported Groups / Elliptic Curves (extension 10)
                if ext_type == 10 and ext_len >= 2:
                    curves_len = struct.unpack("!H", handshake[idx:idx+2])[0]
                    for c_idx in range(2, min(curves_len + 2, ext_len), 2):
                        curve = struct.unpack("!H", handshake[idx+c_idx:idx+c_idx+2])[0]
                        if not is_grease(curve):
                            elliptic_curves.append(str(curve))

                # EC Point Formats (extension 11)
                elif ext_type == 11 and ext_len >= 1:
                    formats_len = handshake[idx]
                    for f_idx in range(1, min(formats_len + 1, ext_len)):
                        ec_point_formats.append(str(handshake[idx+f_idx]))

                idx += ext_len

        # Build raw JA3 string
        ja3_str = ",".join([
            str(client_version),
            "-".join(cipher_suites),
            "-".join(extensions),
            "-".join(elliptic_curves),
            "-".join(ec_point_formats)
        ])

        # Compute MD5
        return hashlib.md5(ja3_str.encode("ascii")).hexdigest()

    except Exception:
        return None


def lookup_ja3(hash_val: str) -> Optional[Tuple[str, str]]:
    """Checks if a JA3 hash matches known threats."""
    return KNOWN_JA3_DATABASE.get(hash_val.lower())
