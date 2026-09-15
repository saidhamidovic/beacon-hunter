# 🛰️ BeaconHunter

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Scapy-Packet%20Engine-red?style=for-the-badge" alt="Scapy" />
  <img src="https://img.shields.io/badge/Threat%20Hunter-Live%20%26%20PCAP-blueviolet?style=for-the-badge" alt="Live & PCAP" />
  <img src="https://img.shields.io/badge/Exploit--DB-Signature%20Engine-critical?style=for-the-badge" alt="Exploit-DB" />
  <img src="https://img.shields.io/badge/ZeroLogon-CVE--2020--1472-orange?style=for-the-badge" alt="ZeroLogon" />
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1068%20%7C%20T1190-E03C11?style=for-the-badge" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License" />
</p>

An advanced, dual-mode network threat hunting and intrusion detection engine designed for **live real-time network sniffing and offline PCAP forensics**. 

Detects **Exploit-DB & CVE signatures (Log4Shell, EternalBlue, PrintNightmare, Spring4Shell, Web Shells)**, **ZeroLogon (CVE-2020-1472) Netlogon exploits**, **Command-and-Control (C2) beaconing (Cobalt Strike / Sliver)**, **TLS JA3 fingerprints**, and **high-entropy DNS tunneling**.

Developed by [Said Hamidovic](https://github.com/saidhamidovic) (*Specialist inom nätverkssäkerhet*).

---

## ⚡ Two Operational Modes

### 1. 🔍 Offline PCAP Forensics Mode
Analyze packet captures (`.pcap` / `.pcapng`) from Wireshark or network taps to perform forensic incident investigations and generate executive Markdown/JSON reports.
```bash
python hunter.py samples/c2_traffic_sample.pcap --export-md incident_report.md
```

### 2. 🚨 Live Real-Time Network Sniffing Mode
Attach BeaconHunter directly to any physical or virtual network interface (e.g. `eth0`, `en0`) to monitor network traffic in real time. Perfect for live lab demonstrations, CTFs, and active monitoring.
```bash
# Sniff all traffic on interface
sudo python hunter.py --sniff -i eth0

# Target SMB/Netlogon specifically during ZeroLogon demonstrations
sudo python hunter.py --sniff -i eth0 --bpf "tcp port 445 or tcp port 135"

# Target Web Exploits (Log4Shell, Reverse Shells, SQLi)
sudo python hunter.py --sniff -i eth0 --bpf "tcp port 80 or tcp port 8080 or tcp port 443"
```

---

## 🛡️ Key Detection Engines

### ⚔️ Exploit-DB & Known CVE Signature Engine (`rules/exploit_signatures.json`)
Fast pattern and regex matching against packet payloads for known high-impact CVEs and Exploit-DB PoC payloads:
* **CVE-2021-44228 (Log4Shell / EDB-50592):** JNDI injection via LDAP/RMI/DNS headers (`${jndi:...}`).
* **CVE-2017-0144 (EternalBlue / MS17-010 / EDB-42315):** SMBv1 Trans2 multiplex buffer overflow.
* **CVE-2019-0708 (BlueKeep / EDB-47344):** RDP MS_T120 channel corruption.
* **CVE-2021-34527 (PrintNightmare / EDB-50073):** Print Spooler `RpcAddPrinterDriverEx` driver drop.
* **CVE-2022-22965 (Spring4Shell / EDB-50931):** AccessLogValve manipulation.
* **Generic Remote Shells:** Bash interactive one-liners (`/bin/bash -i >& /dev/tcp/`), Netcat `-e`, mkfifo.
* **PowerShell Obfuscation:** Encoded commands (`-enc`, `-w hidden`) in network payloads.
* **Path Traversal / LFI:** Directory traversal patterns accessing `/etc/passwd` or `win.ini`.
* **SQL Injection:** Union-based and boolean authentication bypass payloads.

> **Extensible Rules:** You can easily add custom signatures to `rules/exploit_signatures.json` or supply custom rule sets using `--rules my_rules.json`.

### 💥 ZeroLogon (CVE-2020-1472 / MS-NRPC)
* **All-Zero Client Challenge:** Detects `NetrServerReqChallenge` (Opnum 4) containing 8 zero bytes (`\x00`*8).
* **Auth Brute-Force Rate:** Tracks rapid succession of `NetrServerAuthenticate3` (Opnum 26) zero-credential authentication attempts.
* **Cryptographic Bypass:** Catches when the Domain Controller returns `STATUS_SUCCESS` (`0x00000000`).
* **Weaponization Alert:** Detects the execution of `NetrServerPasswordSet2` (Opnum 30) where the Domain Controller's machine account password is reset to an empty string.

### 🛰️ C2 Beaconing Heuristics (Cobalt Strike, Sliver, Havoc)
* **Pulse Clustering:** Aggregates TCP/TLS packet bursts into distinct communication pulses.
* **Coefficient of Variation ($CV$):** Evaluates delta-time ($\Delta t$) variance. Low variance ($CV < 0.25$) flags periodic C2 heartbeats even with jitter applied.

### 🎯 TLS Client Hello JA3 Fingerprinting
* Hashes TLS parameters against known threat profiles (Cobalt Strike, Metasploit, Sliver, Emotet).

### 🌐 High-Entropy DNS Tunneling
* Evaluates Shannon Entropy ($H \ge 3.8$) on DNS query subdomains to detect data exfiltration and Domain Generation Algorithms (DGA).

---

## 📋 MITRE ATT&CK® Mapping

| Technique ID | Name | Detection Logic |
| :--- | :--- | :--- |
| **T1068** | *Exploitation for Privilege Escalation* | ZeroLogon (CVE-2020-1472) Netlogon exploit |
| **T1210** | *Exploitation of Remote Services* | EternalBlue (CVE-2017-0144), BlueKeep (CVE-2019-0708) |
| **T1190** | *Exploit Public-Facing Application* | Log4Shell (CVE-2021-44228), Spring4Shell, SQLi |
| **T1059.004** | *Command and Scripting Interpreter: Unix Shell* | Interactive `/bin/bash` reverse shell injection |
| **T1059.001** | *Command and Scripting Interpreter: PowerShell* | Encoded PowerShell stagers (`-enc`) |
| **T1083** | *File and Directory Discovery* | Path Traversal / LFI (`../../etc/passwd`) |
| **T1071.001** | *Application Layer Protocol: Web* | Periodic outbound HTTP/HTTPS C2 heartbeats |
| **T1071.004** | *Application Layer Protocol: DNS* | High-entropy subdomain tunneling & exfiltration |
| **T1573.002** | *Encrypted Channel: Asymmetric* | JA3 TLS Client Hello fingerprint matching |

---

## 🚀 Quickstart

### Installation
```bash
git clone https://github.com/saidhamidovic/beacon-hunter.git
cd beacon-hunter

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Run Synthetic Test (Includes ZeroLogon, Log4Shell, Reverse Shells & C2 Traffic)
```bash
# Generate complete multi-threat test PCAP
python generate_sample.py

# Run offline analysis and export report
python hunter.py samples/c2_traffic_sample.pcap --export-md samples/sample_report.md
```

---

## 📊 Sample Output

```text
╭─────────────────────────── Investigation Summary ────────────────────────────╮
│ Total Packets: 159  |  Analyzed Flows: 34  |  Capture Duration: 496.6s       │
│ 🚨 Critical/High Beacons: 1   🔍 Suspicious DNS Domains: 1                   │
│ 💥 ZeroLogon Attacks: 1       ⚔️ Exploit-DB/CVE Hits: 3                      │
╰──────────────────────────────────────────────────────────────────────────────╯

              ⚔️ Detected Exploit-DB & Known CVE Signatures ⚔️                
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ CVE/EDB ID ┃ Exploit Name       ┃ Attacker   ┃ Target     ┃ MITRE ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │ CVE-2021-… │ Log4Shell JNDI RCE │ 192.168.1… │ 192.168.1… │ T1190 │
│   HIGH   │ GENERIC-R… │ Unix Reverse Shell │ 192.168.1… │ 192.168.1… │ T1059 │
│   HIGH   │ GENERIC-L… │ Path Traversal/LFI │ 192.168.1… │ 192.168.1… │ T1083 │
└──────────┴────────────┴────────────────────┴────────────┴────────────┴───────┘
```

---

## 📜 License
Released under the [MIT License](LICENSE).
