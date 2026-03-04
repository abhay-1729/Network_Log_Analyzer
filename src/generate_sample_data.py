"""
NetSentinel - Sample Log Data Generator
Generates realistic network traffic log data with embedded attack patterns
for testing and demonstrating the NIDS capabilities.

Embedded Attack Scenarios:
    1. Port Scan from external IP
    2. SSH Brute Force attack
    3. Communication with malicious IP
    4. C2 Beaconing pattern
    5. Large data exfiltration
    6. After-hours suspicious activity
    7. DDoS simulation (scaled down)
    8. Normal traffic baseline
"""

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple


def generate_sample_logs(output_dir: str, num_normal_events: int = 5000) -> dict:
    """
    Generate sample network log files with realistic traffic and attack patterns.

    Args:
        output_dir: Directory to write log files.
        num_normal_events: Number of normal baseline traffic events to generate.

    Returns:
        Dict with generation statistics.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Time range: last 24 hours
    end_time = datetime(2026, 2, 24, 18, 0, 0)
    start_time = end_time - timedelta(hours=24)

    # Internal network hosts
    internal_ips = [
        "192.168.1.10", "192.168.1.20", "192.168.1.30",
        "192.168.1.50", "192.168.1.100", "192.168.1.101",
        "192.168.1.150", "192.168.1.200", "10.0.0.5",
        "10.0.0.10", "10.0.0.15", "10.0.0.20",
    ]

    # External IPs (legitimate)
    external_ips = [
        "8.8.8.8", "1.1.1.1", "142.250.80.46", "151.101.1.140",
        "104.16.132.229", "52.85.132.50", "13.107.42.14",
        "20.190.159.2", "40.126.32.134", "52.109.8.20",
        "34.215.110.130", "54.239.28.85", "99.86.38.100",
    ]

    # Malicious IPs (from our threat feed)
    malicious_ips = ["198.51.100.23", "203.0.113.45", "192.0.2.100"]

    # Common services
    services = [
        (80, "TCP", "HTTP"), (443, "TCP", "HTTPS"),
        (53, "UDP", "DNS"), (22, "TCP", "SSH"),
        (25, "TCP", "SMTP"), (110, "TCP", "POP3"),
        (3389, "TCP", "RDP"), (8080, "TCP", "HTTP-Proxy"),
    ]

    all_events = []

    # ── 1. Normal Baseline Traffic ──────────────────────────

    for _ in range(num_normal_events):
        ts = _random_timestamp(start_time, end_time, business_hours_bias=True)
        src = random.choice(internal_ips)
        dst = random.choice(external_ips + internal_ips)
        port, proto, svc = random.choice(services)

        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "protocol": proto,
            "bytes_sent": random.randint(100, 50000),
            "bytes_received": random.randint(200, 100000),
            "packets": random.randint(1, 50),
            "duration": round(random.uniform(0.01, 30.0), 3),
            "flags": random.choice(["SYN,ACK", "ACK", "PSH,ACK", "FIN,ACK", ""]),
            "action": random.choice(["allow", "allow", "allow", "allow", "allow"]),
            "direction": "outbound" if dst not in internal_ips else "internal",
        })

    # ── 2. Port Scan Attack ─────────────────────────────────

    scanner_ip = "45.33.49.197"
    scan_start = start_time + timedelta(hours=6, minutes=23)
    target_ip = "192.168.1.10"
    scanned_ports = random.sample(range(1, 1024), 50)

    for i, port in enumerate(scanned_ports):
        ts = scan_start + timedelta(seconds=random.uniform(0, 45))
        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(40000, 65535),
            "dst_port": port,
            "protocol": "TCP",
            "bytes_sent": random.randint(40, 80),
            "bytes_received": random.randint(0, 60),
            "packets": 1,
            "duration": round(random.uniform(0.001, 0.1), 3),
            "flags": "SYN",
            "action": random.choice(["deny", "deny", "allow"]),
            "direction": "inbound",
        })

    # ── 3. SSH Brute Force ──────────────────────────────────

    brute_ip = "185.143.223.47"
    brute_start = start_time + timedelta(hours=10, minutes=15)
    brute_target = "192.168.1.20"

    for i in range(25):
        ts = brute_start + timedelta(seconds=i * random.uniform(3, 12))
        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": brute_ip,
            "dst_ip": brute_target,
            "src_port": random.randint(40000, 65535),
            "dst_port": 22,
            "protocol": "TCP",
            "bytes_sent": random.randint(200, 500),
            "bytes_received": random.randint(100, 300),
            "packets": random.randint(5, 15),
            "duration": round(random.uniform(0.5, 3.0), 3),
            "flags": "SYN,ACK",
            "action": "failed",
            "direction": "inbound",
        })

    # After 25 failures, one success  
    ts = brute_start + timedelta(seconds=25 * 10)
    all_events.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": brute_ip,
        "dst_ip": brute_target,
        "src_port": random.randint(40000, 65535),
        "dst_port": 22,
        "protocol": "TCP",
        "bytes_sent": 1500,
        "bytes_received": 2000,
        "packets": 30,
        "duration": 120.0,
        "flags": "SYN,ACK",
        "action": "allow",
        "direction": "inbound",
    })

    # ── 4. Malicious IP Communication ───────────────────────

    compromised_host = "192.168.1.100"
    mal_start = start_time + timedelta(hours=14, minutes=30)

    for i in range(8):
        ts = mal_start + timedelta(minutes=i * random.randint(5, 20))
        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": compromised_host,
            "dst_ip": random.choice(malicious_ips),
            "src_port": random.randint(40000, 65535),
            "dst_port": random.choice([443, 8443, 4444, 8080]),
            "protocol": "TCP",
            "bytes_sent": random.randint(500, 5000),
            "bytes_received": random.randint(1000, 50000),
            "packets": random.randint(10, 100),
            "duration": round(random.uniform(1.0, 60.0), 3),
            "flags": "PSH,ACK",
            "action": "allow",
            "direction": "outbound",
        })

    # ── 5. C2 Beaconing Pattern ─────────────────────────────

    beacon_host = "192.168.1.50"
    c2_server = "203.0.113.201"
    beacon_start = start_time + timedelta(hours=8)
    beacon_interval = 300  # 5 minutes

    for i in range(30):
        # Add slight jitter for realism (but still detectable)
        jitter = random.uniform(-10, 10)
        ts = beacon_start + timedelta(seconds=i * beacon_interval + jitter)
        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": beacon_host,
            "dst_ip": c2_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": random.randint(100, 300),
            "bytes_received": random.randint(50, 200),
            "packets": random.randint(3, 8),
            "duration": round(random.uniform(0.1, 2.0), 3),
            "flags": "PSH,ACK",
            "action": "allow",
            "direction": "outbound",
        })

    # ── 6. Data Exfiltration ────────────────────────────────

    exfil_host = "192.168.1.101"
    exfil_dst = "104.248.50.87"
    exfil_start = start_time + timedelta(hours=16)

    for i in range(20):
        ts = exfil_start + timedelta(minutes=i * 3)
        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": exfil_host,
            "dst_ip": exfil_dst,
            "src_port": random.randint(40000, 65535),
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": random.randint(5000000, 10000000),  # 5-10 MB per transfer
            "bytes_received": random.randint(100, 1000),
            "packets": random.randint(3000, 7000),
            "duration": round(random.uniform(10.0, 60.0), 3),
            "flags": "PSH,ACK",
            "action": "allow",
            "direction": "outbound",
        })

    # ── 7. After-Hours Activity ─────────────────────────────

    night_host = "192.168.1.150"
    night_start = start_time + timedelta(hours=2)

    for i in range(40):
        ts = night_start + timedelta(minutes=random.randint(0, 120))
        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": night_host,
            "dst_ip": random.choice(external_ips + malicious_ips[:1]),
            "src_port": random.randint(40000, 65535),
            "dst_port": random.choice([80, 443, 22, 3389, 8080]),
            "protocol": "TCP",
            "bytes_sent": random.randint(500, 50000),
            "bytes_received": random.randint(500, 100000),
            "packets": random.randint(5, 100),
            "duration": round(random.uniform(0.5, 30.0), 3),
            "flags": "PSH,ACK",
            "action": "allow",
            "direction": "outbound",
        })

    # ── 8. Mini DDoS (scaled for sample) ────────────────────

    ddos_target = "192.168.1.10"
    ddos_start = start_time + timedelta(hours=12, minutes=45)
    ddos_sources = [f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                    for _ in range(60)]

    for i in range(1200):
        ts = ddos_start + timedelta(seconds=random.uniform(0, 8))
        all_events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": random.choice(ddos_sources),
            "dst_ip": ddos_target,
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": "TCP",
            "bytes_sent": random.randint(40, 120),
            "bytes_received": 0,
            "packets": 1,
            "duration": 0.0,
            "flags": "SYN",
            "action": "allow",
            "direction": "inbound",
        })

    # ── Sort by timestamp and write files ───────────────────

    all_events.sort(key=lambda e: e["timestamp"])

    # Write CSV file
    csv_path = output_path / "network_traffic.csv"
    fieldnames = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "bytes_sent", "bytes_received", "packets",
        "duration", "flags", "action", "direction"
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_events)

    # Write JSON file (subset for format variety)
    json_path = output_path / "firewall_events.json"
    json_events = all_events[::3]  # Every 3rd event
    with open(json_path, "w") as f:
        json.dump(json_events, f, indent=2)

    stats = {
        "total_events": len(all_events),
        "csv_file": str(csv_path),
        "json_file": str(json_path),
        "attack_scenarios": [
            "Port Scan (50 ports from 45.33.49.197)",
            "SSH Brute Force (25 attempts from 185.143.223.47)",
            "Malicious IP Communication (8 connections to threat-listed IPs)",
            "C2 Beaconing (30 periodic connections at 5min intervals)",
            "Data Exfiltration (20 large transfers, ~100-200MB total)",
            "After-Hours Activity (40 events between 2-4 AM)",
            "DDoS Simulation (1200 SYN floods from 60 sources)",
        ],
        "normal_events": num_normal_events,
    }

    print(f"\n  ✅ Sample data generated:")
    print(f"     📁 CSV:  {csv_path}")
    print(f"     📁 JSON: {json_path}")
    print(f"     📊 Total events: {len(all_events):,}")
    print(f"     🎯 Attack scenarios: {len(stats['attack_scenarios'])}")

    return stats


def _random_timestamp(
    start: datetime, end: datetime, business_hours_bias: bool = True
) -> datetime:
    """Generate a random timestamp, optionally biased toward business hours."""
    delta = (end - start).total_seconds()
    random_seconds = random.uniform(0, delta)
    ts = start + timedelta(seconds=random_seconds)

    if business_hours_bias and random.random() < 0.7:
        # Bias toward 8 AM - 6 PM
        ts = ts.replace(hour=random.randint(8, 17))

    return ts


if __name__ == "__main__":
    generate_sample_logs("data/logs")