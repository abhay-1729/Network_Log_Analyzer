# 🛡️ NetSentinel — Network Log Analyzer & Intrusion Detection System

<p align="center">
  <strong>A comprehensive, Python-based Network Intrusion Detection System (NIDS) that analyzes network traffic logs to detect suspicious activities, cyber attacks, and security anomalies.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue?logo=python" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" />
  <img src="https://img.shields.io/badge/Version-1.0.0-orange" />
</p>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [How It Works](#-how-it-works)
- [Detection Capabilities](#-detection-capabilities)
- [Configuration Guide](#-configuration-guide)
- [Output & Reports](#-output--reports)
- [Extending the System](#-extending-the-system)
- [FAQ](#-faq)

---

## 🔍 Overview

**NetSentinel** is a signature-based and anomaly-based Network Intrusion Detection System (NIDS) designed to process network traffic logs and identify potential security threats. It works as an offline log analyzer — you feed it log files (CSV, JSON, or Syslog format), and it produces detailed security alerts and reports.

### What Problems Does It Solve?

| Problem | NetSentinel Solution |
|---------|---------------------|
| Hard to spot attacks in massive log files | Automated analysis with 15+ detection rules |
| Unknown threats hiding in normal traffic | Statistical anomaly detection (z-score analysis) |
| Communication with known bad actors | Threat intelligence feed integration |
| No visibility into network patterns | Traffic statistics, top talkers, protocol analysis |
| Manual log review is time-consuming | Generates HTML dashboard reports with charts |
| Alert fatigue from too many duplicates | Built-in alert deduplication and severity filtering |

### Key Design Principles

1. **Modular Architecture** — Each component is independent and replaceable
2. **Configuration-Driven** — All thresholds and rules are in YAML files, not hardcoded
3. **Multi-Format Support** — Handles CSV, JSON, and Syslog formats automatically
4. **Actionable Output** — Every alert includes recommendations and MITRE ATT&CK mapping

---

## 🏗️ Architecture

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NetSentinel NIDS                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────┐   ┌───────────┐   ┌──────────────┐   ┌───────────┐    │
│  │  INPUT   │   │   PARSE   │   │   ANALYZE    │   │  OUTPUT   │    │
│  │          │──>│           │──>│              │──>│           │    │
│  │ Log Files│   │Log Parser │   │  Detection   │   │  Alerts   │    │
│  │ CSV/JSON/│   │           │   │  Engine      │   │  Reports  │    │
│  │ Syslog   │   │           │   │              │   │  Dashboard│    │
│  └──────────┘   └───────────┘   └──────────────┘   └───────────┘    │
│                                        │                            │
│                              ┌─────────┴───────────┐                │
│                              │                     │                │
│                     ┌────────▼────────┐   ┌───────▼───────┐         │
│                     │  Rule-Based     │   │  Statistical  │         │
│                     │  Detection      │   │  Anomaly      │         │
│                     │  (15 rules)     │   │  Detection    │         │
│                     └────────┬────────┘   └───────┬───────┘         │ 
│                              │                     │                │
│                     ┌────────▼─────────────────────▼───────┐        │
│                     │        Threat Intelligence           │        │
│                     │   (Malicious IPs, Domains, TOR)      │        │
│                     └──────────────────────────────────────┘        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow Pipeline

```
                    ┌───────────────────┐
                    │   Raw Log Files   │
                    │  (CSV/JSON/Syslog)│
                    └────────┬──────────┘
                             │
                    ┌────────▼──────────┐
                    │    Log Parser     │
                    │  ─ Format detect  │
                    │  ─ Field mapping  │
                    │  ─ Normalization  │
                    └────────┬──────────┘
                             │
                    ┌────────▼──────────┐
                    │  NetworkEvent[]   │  ← Normalized data objects
                    └───┬────────┬──────┘
                        │        │
           ┌────────────▼─┐  ┌──▼─────────────────────┐
           │   Traffic    │  │   Detection            │
           │   Analyzer   │  │   Engine               │
           │              │  │                        │
           │ ─ Statistics │  │ ─ Port Scans           │
           │ ─ Top Talkers│  │ ─ Brute Force          │
           │ ─ Protocols  │  │ ─ DDoS                 │
           │ ─ Baselines  │  │ ─ Exfiltration         │
           └───────┬──────┘  │ ─ Beaconing            │
                   │         │ ─ Threat Intelligence  │
                   │         │ ─ Anomalies            │
                   │         └────────┬───────────────┘
                   │                   │
                   │          ┌────────▼─────────┐
                   │          │  Alert Manager   │
                   │          │  ─ Deduplication │
                   │          │  ─ Prioritization│
                   │          │  ─ Console Output│
                   │          └────────┬─────────┘
                   │                   │
                   └────────┬──────────┘
                            │
                   ┌────────▼─────────┐
                   │ Report Generator │
                   │  ─ HTML Report   │──> 📊 Interactive Dashboard
                   │  ─ JSON Report   │──> 📄 Machine-Readable Data
                   │  ─ Charts        │──> 📈 Severity/Protocol/Category
                   └──────────────────┘
```

### Component Interaction Diagram

```
  main.py (Orchestrator)
    │
    ├── ConfigManager ─────────── settings.yaml
    │                              detection_rules.yaml
    │                              threat_feeds/*.txt
    │
    ├── LogParser ─────────────── data/logs/*.csv
    │     │                        data/logs/*.json
    │     │                        data/logs/*.log
    │     ▼
    │   List[NetworkEvent]
    │     │
    │     ├──── TrafficAnalyzer ──> TrafficStats
    │     │
    │     └──── DetectionEngine
    │             │
    │             ├── ThreatIntelligence
    │             │     ├── malicious_ips.txt
    │             │     ├── malicious_domains.txt
    │             │     └── tor_exit_nodes.txt
    │             │
    │             └──> List[Alert]
    │                    │
    │                    ▼
    │              AlertManager
    │                    │
    │                    ├──> Console Output (formatted)
    │                    └──> output/alerts/alerts.json
    │
    ├── ReportGenerator
    │     ├──> output/reports/report_*.html
    │     └──> output/reports/report_*.json
    │
    └── Dashboard (CLI UI)
```

---

## ✨ Features

### Detection Capabilities

| # | Detection Type | Method | MITRE ATT&CK |
|---|---------------|--------|---------------|
| 1 | **Port Scanning** | Threshold (unique ports/IP/window) | T1046 |
| 2 | **SSH Brute Force** | Failed auth count on port 22 | T1110 |
| 3 | **RDP Brute Force** | Failed auth count on port 3389 | T1110 |
| 4 | **HTTP Login Bruteforce** | 401/403 response counting | T1110 |
| 5 | **Volumetric DDoS** | Requests/sec + unique sources | T1498 |
| 6 | **SYN Flood** | SYN-to-SYNACK ratio analysis | T1498 |
| 7 | **Malicious IP Contact** | Threat intelligence feed match | T1071 |
| 8 | **DNS Tunneling** | Query length + frequency analysis | T1071.004 |
| 9 | **Data Exfiltration** | Large outbound byte threshold | T1048 |
| 10 | **C2 Beaconing** | Periodic connection regularity (CV) | T1071 |
| 11 | **Protocol Mismatch** | Standard protocol on wrong port | T1571 |
| 12 | **After-Hours Activity** | Time-based event clustering | T1078 |
| 13 | **TOR Exit Node Comms** | TOR IP feed matching | T1090.003 |
| 14 | **ICMP Flood** | ICMP packet rate threshold | T1498 |
| 15 | **Statistical Anomaly** | Z-score deviation from baseline | — |

### Input Support

- **CSV** — Column-name auto-mapping (handles 10+ naming conventions)
- **JSON** — Array format and Newline-Delimited JSON (NDJSON)
- **Syslog** — Standard syslog + firewall-specific patterns
- **Auto-detection** — Automatically identifies file format

### Output & Reporting

- **Console Alerts** — Color-coded, severity-prioritized terminal output
- **HTML Reports** — Dark-themed dashboard with Chart.js visualizations
- **JSON Reports** — Machine-readable format for SIEM integration
- **Alert Log** — Persistent JSON alert storage

---

## 📁 Project Structure

```
Network_Log_Analyzer/
│
├── main.py                          # 🚀 Main entry point & pipeline orchestrator
├── requirements.txt                 # 📦 Python dependencies
├── setup.py                         # 📦 Package setup
├── .gitignore                       # Git ignore rules
├── README.md                        # 📖 This documentation
│
├── config/                          # ⚙️ Configuration
│   ├── settings.yaml                # Main application settings
│   ├── detection_rules.yaml         # Detection rule definitions (15 rules)
│   └── threat_feeds/                # Threat intelligence data
│       ├── malicious_ips.txt        # Known bad IP addresses
│       ├── malicious_domains.txt    # Known bad domains
│       └── tor_exit_nodes.txt       # TOR exit node IPs
│
├── src/                             # 📂 Source code modules
│   ├── __init__.py
│   ├── config_manager.py            # Configuration loading & validation
│   ├── models.py                    # Data classes (NetworkEvent, Alert, etc.)
│   ├── log_parser.py                # Multi-format log parser
│   ├── detection_engine.py          # Core intrusion detection logic
│   ├── traffic_analyzer.py          # Traffic statistics & baselines
│   ├── alert_manager.py             # Alert processing & console output
│   ├── report_generator.py          # HTML & JSON report generation
│   ├── dashboard.py                 # CLI dashboard interface
│   └── generate_sample_data.py      # Sample log generator (with attacks)
│
├── data/                            # 📊 Input data (created at runtime)
│   └── logs/                        # Network log files go here
│
├── output/                          # 📤 Output (created at runtime)
│   ├── alerts/                      # Alert JSON files
│   ├── reports/                     # HTML & JSON reports
│   ├── visualizations/              # Generated charts
│   └── app_logs/                    # Application logs
│
└── docs/                            # 📚 Additional documentation
    ├── ARCHITECTURE.md              # Detailed architecture docs
    └── DETECTION_GUIDE.md           # Detection rules reference
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.9+** (3.10+ recommended)
- **pip** package manager

### Steps

```bash
# 1. Navigate to project directory
cd Network_Log_Analyzer

# 2. Create virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## ⚡ Quick Start

### Option 1: Generate Sample Data & Analyze (Recommended for first run)

```bash
python main.py --generate-sample
```

This will:
1. Generate ~6,400 realistic network events with 7 embedded attack scenarios
2. Parse all log files
3. Run all detection rules
4. Display alerts in the terminal
5. Generate HTML and JSON reports

### Option 2: Analyze Your Own Logs

```bash
# Place your log files in data/logs/ directory, then:
python main.py

# Or specify a custom directory:
python main.py --log-dir /path/to/your/logs
```

### Option 3: Just Generate Sample Data

```bash
python main.py --generate-sample --only
```

### All CLI Options

```
python main.py --help

Options:
  --log-dir PATH       Directory containing network log files
  --config PATH        Path to custom configuration YAML
  --generate-sample    Generate sample log data for testing
  --only               Only generate data, don't analyze
  --no-report          Skip report generation
  --quiet              Suppress console output
```

---

## ⚙️ How It Works

### Step-by-Step Pipeline

```
STEP 1: CONFIGURATION
    │
    │  Load settings.yaml → thresholds, rules, threat feeds
    │  Load detection_rules.yaml → 15 signature rules
    │  Load threat_feeds/ → malicious IPs, domains, TOR nodes
    │
    ▼
STEP 2: LOG PARSING
    │
    │  Scan log directory for supported files (.csv, .json, .log)
    │  Auto-detect format based on file extension / content
    │  Parse each file using format-specific parser
    │  Normalize all entries into NetworkEvent objects
    │  Sort all events chronologically
    │
    ▼
STEP 3: TRAFFIC ANALYSIS
    │
    │  Compute aggregate statistics (total events, bytes, IPs)
    │  Calculate protocol distribution
    │  Identify top talkers (source IPs by volume)
    │  Identify top destinations and ports
    │  Calculate events/second baseline
    │
    ▼
STEP 4: INTRUSION DETECTION
    │
    │  ┌─ Rule-Based Detection ──────────────────────┐
    │  │  Check for port scanning patterns           │
    │  │  Check for brute force login attempts       │
    │  │  Check for DDoS signatures                  │
    │  │  Check for data exfiltration volume         │
    │  │  Check for C2 beaconing regularity          │
    │  │  Check for after-hours activity             │
    │  └─────────────────────────────────────────────┘
    │
    │  ┌─ Threat Intelligence ───────────────────────┐
    │  │  Match source/dest IPs against malicious IPs│
    │  │  Match domains against malicious domains    │
    │  │  Check for TOR exit node communication      │
    │  └─────────────────────────────────────────────┘
    │
    │  ┌─ Anomaly Detection ─────────────────────────┐
    │  │  Calculate z-scores for traffic volume/IP   │
    │  │  Flag IPs exceeding configured threshold    │
    │  └─────────────────────────────────────────────┘
    │
    ▼
STEP 5: ALERT MANAGEMENT
    │
    │  Deduplicate similar alerts within time window
    │  Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
    │  Display formatted alerts in terminal
    │  Save alerts to JSON file
    │
    ▼
STEP 6: REPORT GENERATION
    │
    │  Calculate risk score (0-100)
    │  Generate executive summary
    │  Create HTML report with Chart.js visualizations
    │  Create JSON report for machine processing
    │  Write reports to output/reports/
    │
    ▼
DONE ✅
```

---

## 🔎 Detection Capabilities — Deep Dive

### 1. Port Scanning Detection

**What it detects:** An attacker probing multiple ports on a target to discover open services.

**How it works:**
- Groups events by source IP
- Uses sliding time window (default: 60 seconds)
- Counts unique destination ports per source IP  
- Triggers when threshold exceeded (default: 15 unique ports)
- Classifies as horizontal (multiple targets) or vertical (single target) scan

**Example alert:**
```
Port scan detected from 45.33.49.197: 50 unique ports probed
across 1 destination(s) within 60s window.
```

### 2. Brute Force Detection

**What it detects:** Repeated failed authentication attempts (SSH, RDP, HTTP).

**How it works:**
- Filters events with `action=failed/denied` on authentication ports
- Groups by (source_ip, destination_ip, port) tuple
- Sliding window counts failures (default: 5 in 5 minutes)
- Maps ports to service names (SSH=22, RDP=3389, etc.)

### 3. C2 Beaconing Detection

**What it detects:** Malware calling back to Command & Control servers at regular intervals.

**How it works:**
- Groups connections by (source, destination) IP pairs
- Calculates time intervals between connections
- Computes coefficient of variation (CV) of intervals
- Low CV = regular pattern = likely beaconing
- Default threshold: CV < 15% with 10+ connections

### 4. Statistical Anomaly Detection

**What it detects:** Any IP generating significantly more traffic than the baseline.

**How it works:**
- Counts events per source IP
- Calculates mean and standard deviation
- Computes z-score for each IP
- Flags IPs with z-score > threshold (default: 3.0)
- Sensitivity adjustable: low (3.5), medium (3.0), high (2.0)

---

## ⚙️ Configuration Guide

### Main Settings (`config/settings.yaml`)

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `detection.thresholds.port_scan.unique_ports` | 15 | Ports to trigger alert |
| `detection.thresholds.brute_force.failed_attempts` | 5 | Failed logins before alert |
| `detection.thresholds.ddos.requests_per_second` | 1000 | RPS threshold for DDoS |
| `detection.thresholds.data_exfiltration.outbound_bytes_threshold` | 100 MB | Max outbound before alert |
| `detection.anomaly.z_score_threshold` | 3.0 | Std deviations for anomaly |
| `detection.anomaly.sensitivity` | medium | low / medium / high |
| `alerts.min_severity` | LOW | Minimum severity to show |
| `alerts.dedup_window_seconds` | 300 | Alert dedup window |

### Custom Detection Rules (`config/detection_rules.yaml`)

Add your own rules following this template:

```yaml
- id: "RULE-CUSTOM-001"
  name: "My Custom Detection"
  description: "Detects specific suspicious pattern"
  category: "reconnaissance"
  severity: "HIGH"
  enabled: true
  conditions:
    protocol: "TCP"
    dst_port: 4444
    count_min: 3
    time_window_seconds: 120
  action: "alert"
```

### Threat Intelligence Feeds

Add known malicious IPs/domains to the text files in `config/threat_feeds/`:
- One entry per line
- Lines starting with `#` are comments
- Files are loaded at startup

---

## 📊 Output & Reports

### Console Output

The terminal shows color-coded alerts with severity badges:

```
══════════════════════════════════════════════════════════
  🚨 SECURITY ALERTS - NetSentinel NIDS
══════════════════════════════════════════════════════════

  Severity Summary:
    CRITICAL   │ ████████ (8)
    HIGH       │ ███████████ (11)
    MEDIUM     │ ████ (4)

  Alert #1
  ┌─────────────────────────────────────────────────
  │ ID:        ALERT-A1B2C3D4
  │ Rule:      [RULE-008] Known Malicious IP Contact
  │ Severity:  CRITICAL
  │ Source:    192.168.1.100
  │ Target:    198.51.100.23
  │ Description:
  │   Communication detected with known malicious IP...
  │ 💡 Recommendation:
  │   Block the IP at the firewall immediately...
  └─────────────────────────────────────────────────
```

### HTML Report

The HTML report includes:
- **Executive Summary** with risk score gauge
- **Summary Cards** (events, alerts, processing time)
- **Interactive Charts** (severity donut, category bar, protocol pie)
- **Alerts Table** with severity badges and descriptions
- **Top Talkers** and **Top Ports** tables
- **Recommendations** list

Open the generated HTML file in any browser:
```
output/reports/report_20260224_180000.html
```

### JSON Report

Machine-readable format for integration with SIEMs or other tools:
```
output/reports/report_20260224_180000.json
output/alerts/alerts.json
```

---

## 🔌 Extending the System

### Adding a New Detection Rule

1. Add the rule definition to `config/detection_rules.yaml`
2. Implement the detection method in `src/detection_engine.py`:

```python
def _detect_my_pattern(self, events: List[NetworkEvent]):
    """Detect my custom pattern."""
    for event in events:
        if self._matches_my_criteria(event):
            self._create_alert(
                rule_id="RULE-CUSTOM-001",
                rule_name="My Custom Detection",
                category=AttackCategory.RECONNAISSANCE.value,
                severity=Severity.HIGH,
                src_ip=event.src_ip,
                description="Custom pattern detected...",
                evidence={"key": "value"},
                recommendation="Investigate this...",
                mitre_id="T1234",
                timestamp=event.timestamp,
            )
```

3. Call your method from `analyze()`:
```python
self._detect_my_pattern(events)
```

### Adding a New Log Format

1. Add a parser method in `src/log_parser.py`:
```python
def _parse_my_format(self, path: Path) -> Generator[NetworkEvent, None, None]:
    # Parse your format and yield NetworkEvent objects
    pass
```

2. Register the format in `parse_file()`:
```python
elif ext == ".myformat":
    events = list(self._parse_my_format(path))
```

### Adding Threat Intelligence Feeds

Simply add IPs or domains to the text files in `config/threat_feeds/`:

```text
# malicious_ips.txt
203.0.113.100
198.51.100.50
```

---

## ❓ FAQ

**Q: What log formats are supported?**  
A: CSV, JSON (array and NDJSON), and Syslog. CSV column names are auto-mapped from 10+ naming conventions.

**Q: Can it analyze live traffic?**  
A: Currently it's an offline analyzer. Real-time monitoring via `watch_mode` is planned for v2.0.

**Q: How do I reduce false positives?**  
A: Adjust thresholds in `config/settings.yaml`, change anomaly sensitivity to "low", or increase min_severity to "MEDIUM".

**Q: Can I export alerts to a SIEM?**  
A: Yes, alerts are saved as JSON (`output/alerts/alerts.json`) which can be ingested by Splunk, ELK, or any SIEM.

**Q: How are risk scores calculated?**  
A: Each alert severity has a weight (CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3). Scores are summed and capped at 100.

**Q: Does it support pcap files?**  
A: Not directly. Convert pcaps to CSV using tools like `tshark` or `zeek` first, then analyze with NetSentinel.

---

## 📜 License

MIT License — see LICENSE file for details.

---

<p align="center">
  <strong>Built for security professionals who need fast, reliable network log analysis.</strong><br>
  <em>NetSentinel v1.0.0</em>
</p>

