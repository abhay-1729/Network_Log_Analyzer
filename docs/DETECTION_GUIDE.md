# NetSentinel — Detection Rules Reference Guide

This document provides detailed documentation for every detection rule
implemented in NetSentinel, including how each works, what it catches,
and how to tune it.

---

## Rule Index

| Rule ID | Name | Category | Default Severity |
|---------|------|----------|-----------------|
| RULE-001 | TCP SYN Port Scan | Reconnaissance | HIGH |
| RULE-002 | UDP Port Scan | Reconnaissance | MEDIUM |
| RULE-003 | SSH Brute Force | Brute Force | HIGH |
| RULE-004 | RDP Brute Force | Brute Force | HIGH |
| RULE-005 | HTTP Login Brute Force | Brute Force | MEDIUM |
| RULE-006 | Volumetric DDoS | DDoS | CRITICAL |
| RULE-007 | SYN Flood | DDoS | CRITICAL |
| RULE-008 | Known Malicious IP Contact | Threat Intel | CRITICAL |
| RULE-009 | DNS Tunneling Suspected | Exfiltration | HIGH |
| RULE-010 | Large Data Transfer | Exfiltration | HIGH |
| RULE-011 | C2 Beaconing Pattern | C2 | CRITICAL |
| RULE-012 | Unusual Port Usage | Evasion | MEDIUM |
| RULE-013 | After-Hours Activity | Insider Threat | MEDIUM |
| RULE-014 | TOR Exit Node Communication | Anonymization | HIGH |
| RULE-015 | ICMP Flood | DDoS | HIGH |
| ANOMALY-001 | Statistical Traffic Anomaly | Anomaly | MEDIUM/HIGH |

---

## Detailed Rule Documentation

### RULE-001: TCP SYN Port Scan

**MITRE ATT&CK:** T1046 — Network Service Discovery

**Description:**  
Detects when a single source IP probes multiple destination ports within a
short timeframe. This is a classic reconnaissance technique used by attackers
to map available services on a target before exploitation.

**Algorithm:**
```
FOR each unique source_ip:
    Sort events by timestamp
    Apply sliding window (default: 60 seconds)
    Count unique destination ports in window
    IF unique_ports >= threshold (default: 15):
        GENERATE ALERT
        Classify as "horizontal" if multiple targets, else "vertical"
```

**Configuration:**
```yaml
detection.thresholds.port_scan:
  unique_ports: 15              # Reduce to 10 for stricter detection
  time_window_seconds: 60       # Increase to 120 for slower scans
```

**Tuning Tips:**
- Reduce `unique_ports` to catch stealth scans (may increase false positives)
- Increase `time_window_seconds` to catch slow scans
- Known vulnerability scanners (Nessus, Qualys) may trigger this — whitelist their IPs

---

### RULE-003: SSH Brute Force

**MITRE ATT&CK:** T1110 — Brute Force

**Description:**  
Detects repeated failed SSH authentication attempts from a single source.
Attackers commonly use automated tools to try username/password combinations.

**Algorithm:**
```
Filter events where:
    dst_port = 22 AND action = "failed"
Group by (src_ip, dst_ip, dst_port)
FOR each group:
    Apply sliding window (default: 300 seconds)
    IF failed_count >= threshold (default: 5):
        GENERATE ALERT
```

**Configuration:**
```yaml
detection.thresholds.brute_force:
  failed_attempts: 5            # Increase to 10 for less sensitive detection
  time_window_seconds: 300      # 5 minutes
```

**Similar Rules:**
- **RULE-004**: Same algorithm for RDP (port 3389)
- **RULE-005**: Same algorithm for HTTP (ports 80, 443, 8080, 8443) with 401/403 status codes

---

### RULE-006: Volumetric DDoS

**MITRE ATT&CK:** T1498 — Network Denial of Service

**Description:**  
Detects when a destination IP receives an extremely high volume of requests
from many different source IPs, indicating a Distributed Denial of Service attack.

**Algorithm:**
```
Group events by destination_ip
FOR each destination:
    Apply sliding window (default: 10 seconds)
    Calculate requests_per_second
    Count unique source IPs
    IF RPS >= 1000 AND unique_sources >= 50:
        GENERATE CRITICAL ALERT
```

**Configuration:**
```yaml
detection.thresholds.ddos:
  requests_per_second: 1000     # Adjust based on normal server load
  unique_sources: 50            # Min distinct IPs
  time_window_seconds: 10       # Short window for burst detection
```

---

### RULE-008: Known Malicious IP Contact

**MITRE ATT&CK:** T1071 — Application Layer Protocol

**Description:**  
Checks every source and destination IP against threat intelligence feeds of
known malicious IPs. Any communication with a listed IP generates a CRITICAL alert.

**How it works:**
- Loads IPs from `config/threat_feeds/malicious_ips.txt` at startup
- Performs O(1) set lookup for each unique IP in the event stream
- Generates one alert per malicious IP (deduplication prevents flooding)

**Adding IPs to the feed:**
```
# config/threat_feeds/malicious_ips.txt
198.51.100.23
203.0.113.45
# Add your own entries:
192.0.2.100
```

---

### RULE-011: C2 Beaconing Pattern

**MITRE ATT&CK:** T1071 — Application Layer Protocol

**Description:**  
Detects Command & Control (C2) beaconing by identifying connections from a
source to a destination that occur at regular intervals. Malware often "phones
home" to C2 servers on a fixed schedule.

**Algorithm:**
```
Group connections by (src_ip, dst_ip) pair
FOR each pair with >= min_connections (default: 10):
    Calculate time intervals between consecutive connections
    Compute mean_interval and std_deviation
    Calculate coefficient_of_variation = (std / mean) * 100
    IF CV <= tolerance (default: 15%) AND mean_interval > 1s:
        GENERATE CRITICAL ALERT (beaconing detected)
        Report regularity as (100 - CV)%
```

**Configuration:**
```yaml
detection.thresholds.beaconing:
  min_connections: 10           # Minimum periodic connections needed
  interval_tolerance_percent: 15 # Max allowed jitter (lower = stricter)
  time_window_seconds: 3600    # Analysis window
```

**Understanding the Output:**
- **Regularity 95%+**: Very likely beaconing (automated malware)
- **Regularity 85-95%**: Probable beaconing, investigate
- **Regularity <85%**: Less likely, could be cron jobs or polling agents

---

### RULE-010: Large Data Transfer (Exfiltration)

**MITRE ATT&CK:** T1048 — Exfiltration Over Alternative Protocol

**Description:**  
Detects when a single internal host transfers an unusually large amount of
outbound data, which may indicate data exfiltration.

**Algorithm:**
```
Filter events where direction = "outbound" AND bytes_sent > 0
Group by source_ip
FOR each source:
    Apply sliding window (default: 3600 seconds)
    Sum bytes_sent in window
    IF total_bytes >= threshold (default: 100 MB):
        GENERATE ALERT
```

**Configuration:**
```yaml
detection.thresholds.data_exfiltration:
  outbound_bytes_threshold: 104857600  # 100 MB (adjust for your environment)
  time_window_seconds: 3600            # 1 hour window
```

---

### ANOMALY-001: Statistical Traffic Anomaly

**Description:**  
Uses z-score analysis to identify source IPs generating significantly more
traffic than the average. No predefined signatures — purely statistical.

**Algorithm:**
```
Count events per source_ip → counts[]
Calculate mean = average(counts)
Calculate std = standard_deviation(counts)

FOR each source_ip:
    z_score = (count - mean) / std
    IF z_score > threshold (default: 3.0):
        IF z_score >= 4.0: severity = HIGH
        ELSE: severity = MEDIUM
        GENERATE ALERT
```

**Sensitivity Settings:**
| Setting | Z-Score Threshold | Detection Rate | False Positive Rate |
|---------|------------------|----------------|-------------------- |
| `low` | 3.5 | Lower | Lower |
| `medium` | 3.0 | Balanced | Balanced |
| `high` | 2.0 | Higher | Higher |

---

## MITRE ATT&CK Mapping

```
                    MITRE ATT&CK Framework Coverage
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  Reconnaissance          Credential Access               │
│  ├── T1046 Port Scan     ├── T1110 Brute Force          │
│                                                          │
│  Impact                  Command & Control               │
│  ├── T1498 DDoS          ├── T1071 C2 / Malicious IP    │
│  ├── T1498 SYN Flood     ├── T1090.003 TOR Proxy        │
│                                                          │
│  Exfiltration            Defense Evasion                 │
│  ├── T1048 Large Xfer    ├── T1571 Non-Standard Port    │
│  ├── T1071.004 DNS Tun                                   │
│                                                          │
│  Initial Access                                          │
│  ├── T1078 Valid Accounts (after-hours)                  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Adding Custom Rules

### Step 1: Define the rule in `config/detection_rules.yaml`

```yaml
- id: "RULE-CUSTOM-001"
  name: "Suspicious FTP Upload"
  description: "Detects large file uploads over FTP"
  category: "exfiltration"
  severity: "HIGH"
  enabled: true
  conditions:
    protocol: "TCP"
    dst_port: 21
    bytes_sent_min: 52428800  # 50 MB
  action: "alert"
```

### Step 2: Implement detection logic in `src/detection_engine.py`

```python
def _detect_ftp_exfil(self, events: List[NetworkEvent]):
    ftp_events = [e for e in events if e.dst_port == 21 and e.bytes_sent > 52428800]
    for event in ftp_events:
        self._create_alert(
            rule_id="RULE-CUSTOM-001",
            rule_name="Suspicious FTP Upload",
            category="exfiltration",
            severity=Severity.HIGH,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            description=f"Large FTP upload: {event.bytes_sent / (1024*1024):.0f} MB",
            evidence={"bytes_uploaded": event.bytes_sent},
            recommendation="Investigate the file uploaded via FTP.",
            mitre_id="T1048.003",
            timestamp=event.timestamp,
        )
```

### Step 3: Register in the `analyze()` method

```python
def analyze(self, events):
    # ... existing detections ...
    self._detect_ftp_exfil(events)  # Add this line
```
