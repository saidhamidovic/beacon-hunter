# 🛰️ BeaconHunter

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Scapy-Packet%20Engine-red?style=for-the-badge" alt="Scapy" />
  <img src="https://img.shields.io/badge/Security-Threat%20Hunting-0052CC?style=for-the-badge" alt="Threat Hunting" />
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1071-E03C11?style=for-the-badge" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License" />
</p>

An advanced, statistical network threat-hunting engine designed to detect **Command-and-Control (C2) beaconing, TLS JA3 client fingerprints, and high-entropy DNS tunneling** from raw packet captures (`.pcap` / `.pcapng`).

Developed by [Said Hamidovic](https://github.com/saidhamidovic) (*Specialist inom nätverkssäkerhet*).

---

## 🎯 The Problem

Modern threat actors and post-exploitation frameworks (Cobalt Strike, Sliver, Havoc, Metasploit) use encrypted HTTPS or DNS channels to maintain persistence. Because payloads are encrypted, traditional signature-based Intrusion Detection Systems (IDS) often fail to detect outbound communication.

**BeaconHunter** solves this by focusing on **behavioral and statistical heuristics**:
1. **Pulse Clustering & Delta-Time Analysis:** Groups rapid TCP/TLS packets into distinct communication "pulses".
2. **Coefficient of Variation (CV) & Jitter Analysis:** Measures the statistical periodicity of check-in intervals ($\Delta t$). Low variance ($CV < 0.25$) strongly indicates automated beaconing, even when jitter is applied.
3. **JA3 Fingerprinting:** Extracts TLS Client Hello parameters and hashes them against known C2 malleable profiles.
4. **Shannon Entropy DNS Analysis:** Evaluates subdomain randomness ($H \ge 3.8$) to detect data exfiltration and Domain Generation Algorithms (DGA).

---

## 🛡️ MITRE ATT&CK® Mapping

| Technique ID | Name | Detection Logic |
| :--- | :--- | :--- |
| **T1071.001** | *Application Layer Protocol: Web* | Periodic outbound HTTP/HTTPS heartbeats |
| **T1071.004** | *Application Layer Protocol: DNS* | High-entropy subdomain tunneling & exfiltration |
| **T1573.002** | *Encrypted Channel: Asymmetric Cryptography* | JA3 TLS Client Hello fingerprint matching |
| **T1568** | *Dynamic Resolution: DGA* | Algorithmic domain queries |

---

## 🚀 Quickstart

### 1. Installation
```bash
git clone https://github.com/saidhamidovic/beacon-hunter.git
cd beacon-hunter

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Generate Synthetic Test Traffic (Optional)
BeaconHunter comes with a built-in synthetic PCAP generator that creates realistic benign web traffic, a periodic C2 beacon (30s interval, 10% jitter), and high-entropy DNS exfiltration queries:
```bash
python generate_sample.py
```

### 3. Run Threat Hunting Analysis
```bash
python hunter.py samples/c2_traffic_sample.pcap --export-md report.md
```

---

## 📊 Sample Output

```text
╭─────────────────────────── Investigation Summary ────────────────────────────╮
│ Total Packets: 94  |  Analyzed Flows: 30  |  Capture Duration: 477.4s        │
│ 🚨 Critical/High Beacons: 1   🔍 Suspicious DNS Domains: 1   🎯 Known JA3    │
╰──────────────────────────────────────────────────────────────────────────────╯

                     Detected Potential C2 Beaconing Flows                      
┏━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┓
┃ Threat ┃ Client ┃ Destination        ┃ Proto ┃ Pulses ┃  Intvl ┃ Jitter ┃  Score ┃
┡━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━┩
│ CRITI… │ 192.1… │ 198.51.100.44:8443 │  TCP  │     10 │  30.1s │   4.7% │ 95/100 │
└────────┴────────┴────────────────────┴───────┴────────┴────────┴────────┴────────┘
```

---

## ⚙️ CLI Options

| Flag | Description | Default |
| :--- | :--- | :---: |
| `pcap` | Path to `.pcap` or `.pcapng` file | *(Required)* |
| `--threshold` | Minimum beacon score to display (0–100) | `40.0` |
| `--export-md <file>` | Export detailed SOC Incident Report in Markdown | `None` |
| `--json <file>` | Export structured analysis results to JSON | `None` |

---

## 📁 Architecture

```text
beacon-hunter/
├── core/
│   ├── analyzer.py       # Statistical periodicity, jitter & scoring engine
│   ├── ja3.py            # TLS Client Hello JA3 extractor & threat database
│   ├── dns_hunter.py     # Shannon entropy & DNS exfiltration detector
│   └── reporter.py       # Rich terminal tables & Markdown incident report exporter
├── samples/              # PCAP test captures
├── generate_sample.py    # Synthetic test generator
├── hunter.py             # Main CLI entrypoint
└── requirements.txt      # scapy, rich, cryptography
```

---

## 📜 License
Released under the [MIT License](LICENSE).
