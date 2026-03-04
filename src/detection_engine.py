"""
NetSentinel - Detection Engine
Core intrusion detection module implementing both rule-based and
statistical anomaly detection for network traffic analysis.

Detection Methods:
    1. Signature/Rule-Based  - Matches traffic patterns against predefined rules
    2. Threshold-Based       - Flags when metrics exceed configured thresholds
    3. Statistical Anomaly   - Uses z-score analysis to find deviations from baseline
    4. Threat Intelligence   - Checks against known malicious IPs/domains
    5. Behavioral Analysis   - Detects beaconing, after-hours activity, etc.
"""

import logging
import uuid
import yaml
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from .models import Alert, NetworkEvent, Severity, AttackCategory

logger = logging.getLogger("NetSentinel.DetectionEngine")


class ThreatIntelligence:
    """Manages threat intelligence feeds (malicious IPs, domains, TOR nodes)."""

    def __init__(self, config: dict, project_root: Path):
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.tor_exit_nodes: Set[str] = set()
        self._load_feeds(config, project_root)

    def _load_feeds(self, config: dict, project_root: Path):
        """Load threat intelligence feeds from files."""
        feeds = {
            "malicious_ips": config.get("malicious_ips_file", ""),
            "malicious_domains": config.get("malicious_domains_file", ""),
            "tor_exit_nodes": config.get("tor_exit_nodes_file", ""),
        }

        for feed_name, feed_path in feeds.items():
            if not feed_path:
                continue
            full_path = project_root / feed_path
            if full_path.exists():
                with open(full_path, "r") as f:
                    entries = {
                        line.strip().lower()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    }
                setattr(self, feed_name, entries)
                logger.info(f"Loaded {len(entries)} entries from {feed_name}")
            else:
                logger.warning(f"Threat feed not found: {full_path}")

    def is_malicious_ip(self, ip: str) -> bool:
        return ip.lower() in self.malicious_ips

    def is_malicious_domain(self, domain: str) -> bool:
        return domain.lower() in self.malicious_domains

    def is_tor_exit_node(self, ip: str) -> bool:
        return ip.lower() in self.tor_exit_nodes


class DetectionEngine:
    """
    Main detection engine that analyzes network events and generates alerts.

    Pipeline:
        Events  -->  Pre-Processing  -->  Rule Matching  -->  Threshold Checks
                                                |                    |
                                                v                    v
                                          Threat Intel Check    Anomaly Detection
                                                |                    |
                                                v                    v
                                           Alert Generation  <-------+
                                                |
                                                v
                                           Deduplication  -->  Final Alerts
    """

    def __init__(self, config: dict, project_root: Path):
        self.config = config
        self.project_root = project_root
        self.alerts: List[Alert] = []
        self._alert_cache: Dict[str, datetime] = {}  # For deduplication

        # Load detection rules
        self.rules = self._load_rules()

        # Load thresholds from config
        self.thresholds = config.get("detection", {}).get("thresholds", {})
        self.anomaly_config = config.get("detection", {}).get("anomaly", {})

        # Load threat intelligence
        threat_config = config.get("threat_intel", {})
        self.threat_intel = ThreatIntelligence(threat_config, project_root)

        # Alert dedup settings
        alert_config = config.get("alerts", {})
        self.dedup_window = timedelta(
            seconds=alert_config.get("dedup_window_seconds", 300)
        )

        logger.info(
            f"Detection engine initialized with {len(self.rules)} rules, "
            f"threat intel: {threat_config.get('enabled', False)}"
        )

    def _load_rules(self) -> List[dict]:
        """Load detection rules from YAML file."""
        rules_file = self.config.get("detection", {}).get(
            "rules_file", "config/detection_rules.yaml"
        )
        rules_path = self.project_root / rules_file
        if rules_path.exists():
            with open(rules_path, "r") as f:
                data = yaml.safe_load(f) or {}
            rules = data.get("rules", [])
            enabled_rules = [r for r in rules if r.get("enabled", True)]
            logger.info(f"Loaded {len(enabled_rules)}/{len(rules)} detection rules")
            return enabled_rules
        logger.warning(f"Rules file not found: {rules_path}")
        return []

    # ── Main Analysis Entry Point ──────────────────────────────

    def analyze(self, events: List[NetworkEvent]) -> List[Alert]:
        """
        Run all detection methods against the provided events.

        Args:
            events: List of parsed network events, sorted by timestamp.

        Returns:
            List of generated alerts after deduplication.
        """
        if not events:
            logger.warning("No events provided for analysis.")
            return []

        logger.info(f"Starting analysis of {len(events)} events...")
        self.alerts = []

        # 1. Threat intelligence checks
        self._check_threat_intel(events)

        # 2. Port scanning detection
        self._detect_port_scans(events)

        # 3. Brute force detection
        self._detect_brute_force(events)

        # 4. DDoS detection
        self._detect_ddos(events)

        # 5. Data exfiltration detection
        self._detect_data_exfiltration(events)

        # 6. Beaconing detection
        self._detect_beaconing(events)

        # 7. After-hours activity detection
        self._detect_unusual_hours(events)

        # 8. Statistical anomaly detection
        if self.anomaly_config.get("enabled", True):
            self._detect_anomalies(events)

        # Deduplicate alerts
        final_alerts = self._deduplicate_alerts(self.alerts)

        logger.info(
            f"Analysis complete: {len(final_alerts)} alerts generated "
            f"(before dedup: {len(self.alerts)})"
        )
        return final_alerts

    # ── Detection Method 1: Threat Intelligence ────────────────

    def _check_threat_intel(self, events: List[NetworkEvent]):
        """Check events against threat intelligence feeds."""
        if not self.config.get("threat_intel", {}).get("enabled", True):
            return

        checked_ips: Set[str] = set()

        for event in events:
            for ip, direction in [(event.src_ip, "source"), (event.dst_ip, "destination")]:
                if ip in checked_ips:
                    continue
                checked_ips.add(ip)

                # Check malicious IPs
                if self.threat_intel.is_malicious_ip(ip):
                    self._create_alert(
                        rule_id="RULE-008",
                        rule_name="Known Malicious IP Contact",
                        category=AttackCategory.THREAT_INTEL.value,
                        severity=Severity.CRITICAL,
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        dst_port=event.dst_port,
                        description=(
                            f"Communication detected with known malicious IP {ip} "
                            f"as {direction}. This IP is listed in threat intelligence feeds."
                        ),
                        evidence={
                            "malicious_ip": ip,
                            "direction": direction,
                            "event_time": event.timestamp.isoformat(),
                        },
                        recommendation=(
                            "Immediately investigate the host communicating with this IP. "
                            "Block the IP at the firewall and check for compromise indicators."
                        ),
                        mitre_id="T1071",
                        timestamp=event.timestamp,
                    )

                # Check TOR exit nodes
                if self.threat_intel.is_tor_exit_node(ip):
                    self._create_alert(
                        rule_id="RULE-014",
                        rule_name="TOR Exit Node Communication",
                        category=AttackCategory.ANONYMIZATION.value,
                        severity=Severity.HIGH,
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        dst_port=event.dst_port,
                        description=(
                            f"Traffic detected to/from known TOR exit node: {ip}. "
                            f"This may indicate anonymized communication."
                        ),
                        evidence={
                            "tor_node_ip": ip,
                            "direction": direction,
                        },
                        recommendation=(
                            "Investigate why TOR is being used. May indicate data exfiltration "
                            "or access to dark web services."
                        ),
                        mitre_id="T1090.003",
                        timestamp=event.timestamp,
                    )

            # Check malicious domains
            if event.domain and self.threat_intel.is_malicious_domain(event.domain):
                self._create_alert(
                    rule_id="RULE-008",
                    rule_name="Known Malicious Domain Contact",
                    category=AttackCategory.THREAT_INTEL.value,
                    severity=Severity.CRITICAL,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    description=(
                        f"DNS query or connection to known malicious domain: {event.domain}"
                    ),
                    evidence={
                        "malicious_domain": event.domain,
                        "src_ip": event.src_ip,
                    },
                    recommendation=(
                        "Block the domain immediately. Investigate the source host for malware."
                    ),
                    mitre_id="T1071.001",
                    timestamp=event.timestamp,
                )

    # ── Detection Method 2: Port Scanning ──────────────────────

    def _detect_port_scans(self, events: List[NetworkEvent]):
        """Detect port scanning activity based on unique destination ports per source IP."""
        config = self.thresholds.get("port_scan", {})
        unique_port_threshold = config.get("unique_ports", 15)
        time_window = timedelta(seconds=config.get("time_window_seconds", 60))

        # Group events by source IP
        src_ip_events: Dict[str, List[NetworkEvent]] = defaultdict(list)
        for event in events:
            src_ip_events[event.src_ip].append(event)

        for src_ip, ip_events in src_ip_events.items():
            ip_events.sort(key=lambda e: e.timestamp)

            # Sliding window analysis
            window_start = 0
            for window_end in range(len(ip_events)):
                # Move window start forward
                while (
                    window_start < window_end
                    and ip_events[window_end].timestamp - ip_events[window_start].timestamp
                    > time_window
                ):
                    window_start += 1

                window_events = ip_events[window_start : window_end + 1]
                unique_ports = {e.dst_port for e in window_events}

                if len(unique_ports) >= unique_port_threshold:
                    # Determine scan type
                    dst_ips = {e.dst_ip for e in window_events}
                    scan_type = "horizontal" if len(dst_ips) > 3 else "vertical"

                    self._create_alert(
                        rule_id="RULE-001",
                        rule_name=f"Port Scan Detected ({scan_type})",
                        category=AttackCategory.RECONNAISSANCE.value,
                        severity=Severity.HIGH,
                        src_ip=src_ip,
                        dst_ip=list(dst_ips)[0] if len(dst_ips) == 1 else f"{len(dst_ips)} targets",
                        description=(
                            f"Port scan detected from {src_ip}: {len(unique_ports)} unique ports "
                            f"probed across {len(dst_ips)} destination(s) "
                            f"within {time_window.seconds}s window."
                        ),
                        evidence={
                            "unique_ports": len(unique_ports),
                            "sample_ports": sorted(unique_ports)[:20],
                            "target_count": len(dst_ips),
                            "scan_type": scan_type,
                            "event_count": len(window_events),
                        },
                        recommendation=(
                            "Block the scanning IP at the firewall. Review if any scanned "
                            "ports have known vulnerabilities. Monitor for follow-up exploitation."
                        ),
                        mitre_id="T1046",
                        timestamp=window_events[0].timestamp,
                    )
                    break  # One alert per source IP

    # ── Detection Method 3: Brute Force ────────────────────────

    def _detect_brute_force(self, events: List[NetworkEvent]):
        """Detect brute force login attempts."""
        config = self.thresholds.get("brute_force", {})
        fail_threshold = config.get("failed_attempts", 5)
        time_window = timedelta(seconds=config.get("time_window_seconds", 300))

        # Focus on authentication-related ports
        auth_ports = {22, 23, 3389, 21, 80, 443, 8080, 8443, 25, 110, 143}

        # Group failed events by (src_ip, dst_ip, dst_port)
        failed_attempts: Dict[Tuple[str, str, int], List[NetworkEvent]] = defaultdict(list)

        for event in events:
            if event.action in ("failed", "denied", "reject", "drop"):
                if event.dst_port in auth_ports or event.action == "failed":
                    key = (event.src_ip, event.dst_ip, event.dst_port)
                    failed_attempts[key].append(event)

        for (src_ip, dst_ip, dst_port), attempts in failed_attempts.items():
            attempts.sort(key=lambda e: e.timestamp)

            # Sliding window check
            window_start = 0
            for window_end in range(len(attempts)):
                while (
                    window_start < window_end
                    and attempts[window_end].timestamp - attempts[window_start].timestamp
                    > time_window
                ):
                    window_start += 1

                window_count = window_end - window_start + 1
                if window_count >= fail_threshold:
                    service_map = {
                        22: "SSH",
                        23: "Telnet",
                        3389: "RDP",
                        21: "FTP",
                        80: "HTTP",
                        443: "HTTPS",
                        25: "SMTP",
                    }
                    service = service_map.get(dst_port, f"Port {dst_port}")

                    self._create_alert(
                        rule_id="RULE-003",
                        rule_name=f"{service} Brute Force Attack",
                        category=AttackCategory.BRUTE_FORCE.value,
                        severity=Severity.HIGH,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        description=(
                            f"Brute force attack detected: {window_count} failed "
                            f"{service} login attempts from {src_ip} to {dst_ip}:{dst_port} "
                            f"within {time_window.seconds // 60} minutes."
                        ),
                        evidence={
                            "failed_attempts": window_count,
                            "service": service,
                            "time_span_seconds": (
                                attempts[window_end].timestamp
                                - attempts[window_start].timestamp
                            ).total_seconds(),
                            "first_attempt": attempts[window_start].timestamp.isoformat(),
                            "last_attempt": attempts[window_end].timestamp.isoformat(),
                        },
                        recommendation=(
                            f"Block {src_ip} immediately. Enable account lockout policies. "
                            f"Consider implementing MFA for {service} access. "
                            f"Check if any credentials were compromised."
                        ),
                        mitre_id="T1110",
                        timestamp=attempts[window_start].timestamp,
                    )
                    break

    # ── Detection Method 4: DDoS ───────────────────────────────

    def _detect_ddos(self, events: List[NetworkEvent]):
        """Detect Distributed Denial of Service attacks."""
        config = self.thresholds.get("ddos", {})
        rps_threshold = config.get("requests_per_second", 1000)
        src_threshold = config.get("unique_sources", 50)
        time_window = timedelta(seconds=config.get("time_window_seconds", 10))

        if not events:
            return

        # Group events by destination IP
        dst_ip_events: Dict[str, List[NetworkEvent]] = defaultdict(list)
        for event in events:
            dst_ip_events[event.dst_ip].append(event)

        for dst_ip, ip_events in dst_ip_events.items():
            ip_events.sort(key=lambda e: e.timestamp)

            # Sliding window analysis
            window_start = 0
            for window_end in range(len(ip_events)):
                while (
                    window_start < window_end
                    and ip_events[window_end].timestamp - ip_events[window_start].timestamp
                    > time_window
                ):
                    window_start += 1

                window_events = ip_events[window_start : window_end + 1]
                window_duration = max(
                    (window_events[-1].timestamp - window_events[0].timestamp).total_seconds(),
                    1,
                )
                rps = len(window_events) / window_duration
                unique_sources = {e.src_ip for e in window_events}

                if rps >= rps_threshold and len(unique_sources) >= src_threshold:
                    total_bytes = sum(e.total_bytes for e in window_events)
                    self._create_alert(
                        rule_id="RULE-006",
                        rule_name="DDoS Attack Detected",
                        category=AttackCategory.DDOS.value,
                        severity=Severity.CRITICAL,
                        src_ip=f"{len(unique_sources)} sources",
                        dst_ip=dst_ip,
                        description=(
                            f"Potential DDoS attack against {dst_ip}: "
                            f"{rps:.0f} requests/sec from {len(unique_sources)} unique sources. "
                            f"Total volume: {total_bytes / (1024*1024):.1f} MB."
                        ),
                        evidence={
                            "requests_per_second": round(rps, 1),
                            "unique_sources": len(unique_sources),
                            "total_events": len(window_events),
                            "total_bytes_mb": round(total_bytes / (1024 * 1024), 2),
                            "duration_seconds": window_duration,
                            "top_sources": sorted(
                                [(ip, sum(1 for e in window_events if e.src_ip == ip))
                                 for ip in list(unique_sources)[:10]],
                                key=lambda x: x[1],
                                reverse=True,
                            ),
                        },
                        recommendation=(
                            "Activate DDoS mitigation. Enable rate limiting and geo-blocking. "
                            "Contact upstream ISP for traffic scrubbing if needed. "
                            "Consider CDN/WAF deployment."
                        ),
                        mitre_id="T1498",
                        timestamp=window_events[0].timestamp,
                    )
                    break

    # ── Detection Method 5: Data Exfiltration ──────────────────

    def _detect_data_exfiltration(self, events: List[NetworkEvent]):
        """Detect unusually large outbound data transfers."""
        config = self.thresholds.get("data_exfiltration", {})
        bytes_threshold = config.get("outbound_bytes_threshold", 104857600)  # 100 MB
        time_window = timedelta(seconds=config.get("time_window_seconds", 3600))

        # Aggregate outbound bytes per source IP per hour
        outbound_data: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)

        for event in events:
            if event.direction in ("outbound", "unknown") and event.bytes_sent > 0:
                outbound_data[event.src_ip].append((event.timestamp, event.bytes_sent))

        for src_ip, transfers in outbound_data.items():
            transfers.sort(key=lambda x: x[0])

            # Sliding window
            window_start = 0
            for window_end in range(len(transfers)):
                while (
                    window_start < window_end
                    and transfers[window_end][0] - transfers[window_start][0] > time_window
                ):
                    window_start += 1

                total_bytes = sum(t[1] for t in transfers[window_start : window_end + 1])

                if total_bytes >= bytes_threshold:
                    self._create_alert(
                        rule_id="RULE-010",
                        rule_name="Potential Data Exfiltration",
                        category=AttackCategory.EXFILTRATION.value,
                        severity=Severity.HIGH,
                        src_ip=src_ip,
                        description=(
                            f"Large outbound data transfer detected from {src_ip}: "
                            f"{total_bytes / (1024*1024):.1f} MB transferred within "
                            f"{time_window.seconds // 3600} hour(s)."
                        ),
                        evidence={
                            "total_bytes": total_bytes,
                            "total_mb": round(total_bytes / (1024 * 1024), 2),
                            "transfer_count": window_end - window_start + 1,
                            "time_window_hours": time_window.seconds / 3600,
                        },
                        recommendation=(
                            "Investigate the source host for malware. Check what data was "
                            "transferred and to which destinations. Review DLP policies."
                        ),
                        mitre_id="T1048",
                        timestamp=transfers[window_start][0],
                    )
                    break

    # ── Detection Method 6: C2 Beaconing ──────────────────────

    def _detect_beaconing(self, events: List[NetworkEvent]):
        """Detect Command & Control beaconing patterns (regular periodic connections)."""
        config = self.thresholds.get("beaconing", {})
        min_connections = config.get("min_connections", 10)
        tolerance_pct = config.get("interval_tolerance_percent", 15)
        time_window = timedelta(seconds=config.get("time_window_seconds", 3600))

        # Group connections by (src_ip, dst_ip) pairs
        connection_pairs: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)

        for event in events:
            connection_pairs[(event.src_ip, event.dst_ip)].append(event.timestamp)

        for (src_ip, dst_ip), timestamps in connection_pairs.items():
            timestamps.sort()

            if len(timestamps) < min_connections:
                continue

            # Calculate intervals between consecutive connections
            intervals = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                continue

            # Check for regularity using coefficient of variation
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)

            if mean_interval <= 0:
                continue

            cv = (std_interval / mean_interval) * 100  # Coefficient of variation as %

            if cv <= tolerance_pct and mean_interval > 1:
                # Regular pattern detected
                self._create_alert(
                    rule_id="RULE-011",
                    rule_name="C2 Beaconing Pattern Detected",
                    category=AttackCategory.C2.value,
                    severity=Severity.CRITICAL,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    description=(
                        f"Regular beaconing pattern detected: {src_ip} -> {dst_ip}. "
                        f"{len(timestamps)} connections at ~{mean_interval:.1f}s intervals "
                        f"(regularity: {100 - cv:.1f}%)."
                    ),
                    evidence={
                        "connection_count": len(timestamps),
                        "mean_interval_seconds": round(mean_interval, 2),
                        "std_deviation": round(std_interval, 2),
                        "regularity_percent": round(100 - cv, 1),
                        "first_seen": timestamps[0].isoformat(),
                        "last_seen": timestamps[-1].isoformat(),
                    },
                    recommendation=(
                        "PRIORITY: Investigate the destination IP immediately for C2 infrastructure. "
                        "Isolate the source host. Capture network traffic for forensic analysis. "
                        "Check for malware on the infected host."
                    ),
                    mitre_id="T1071",
                    timestamp=timestamps[0],
                )

    # ── Detection Method 7: Unusual Hours ──────────────────────

    def _detect_unusual_hours(self, events: List[NetworkEvent]):
        """Detect significant network activity during unusual hours."""
        config = self.thresholds.get("unusual_hours", {})
        start_hour = config.get("start_hour", 0)
        end_hour = config.get("end_hour", 5)
        min_events = config.get("min_events", 20)

        # Group by source IP and check for events in unusual hours
        unusual_activity: Dict[str, List[NetworkEvent]] = defaultdict(list)

        for event in events:
            hour = event.timestamp.hour
            if start_hour <= hour < end_hour:
                unusual_activity[event.src_ip].append(event)

        for src_ip, ip_events in unusual_activity.items():
            if len(ip_events) >= min_events:
                unique_dsts = {e.dst_ip for e in ip_events}
                total_bytes = sum(e.total_bytes for e in ip_events)

                self._create_alert(
                    rule_id="RULE-013",
                    rule_name="After-Hours Network Activity",
                    category=AttackCategory.INSIDER_THREAT.value,
                    severity=Severity.MEDIUM,
                    src_ip=src_ip,
                    description=(
                        f"Unusual after-hours activity from {src_ip}: "
                        f"{len(ip_events)} events between {start_hour:02d}:00-{end_hour:02d}:00, "
                        f"contacting {len(unique_dsts)} unique destinations."
                    ),
                    evidence={
                        "event_count": len(ip_events),
                        "unique_destinations": len(unique_dsts),
                        "total_bytes": total_bytes,
                        "time_range": f"{start_hour:02d}:00 - {end_hour:02d}:00",
                    },
                    recommendation=(
                        "Verify if this activity is expected (e.g., scheduled jobs, maintenance). "
                        "If not, investigate for potential insider threat or compromised account."
                    ),
                    mitre_id="T1078",
                    timestamp=ip_events[0].timestamp,
                )

    # ── Detection Method 8: Statistical Anomaly ────────────────

    def _detect_anomalies(self, events: List[NetworkEvent]):
        """Detect statistical anomalies in traffic patterns."""
        z_threshold = self.anomaly_config.get("z_score_threshold", 3.0)
        sensitivity = self.anomaly_config.get("sensitivity", "medium")

        # Adjust threshold based on sensitivity
        sensitivity_map = {"low": 3.5, "medium": 3.0, "high": 2.0}
        z_threshold = sensitivity_map.get(sensitivity, z_threshold)

        if len(events) < 10:
            return

        # Analyze traffic volume per source IP
        ip_event_counts: Dict[str, int] = defaultdict(int)
        ip_bytes: Dict[str, int] = defaultdict(int)

        for event in events:
            ip_event_counts[event.src_ip] += 1
            ip_bytes[event.src_ip] += event.total_bytes

        # Calculate z-scores for event counts
        counts = list(ip_event_counts.values())
        if len(counts) < 3:
            return

        mean_count = np.mean(counts)
        std_count = np.std(counts)

        if std_count == 0:
            return

        for ip, count in ip_event_counts.items():
            z_score = (count - mean_count) / std_count

            if z_score > z_threshold:
                self._create_alert(
                    rule_id="ANOMALY-001",
                    rule_name="Statistical Traffic Anomaly",
                    category=AttackCategory.ANOMALY.value,
                    severity=Severity.MEDIUM if z_score < 4 else Severity.HIGH,
                    src_ip=ip,
                    description=(
                        f"Anomalous traffic volume from {ip}: {count} events "
                        f"(z-score: {z_score:.2f}, mean: {mean_count:.0f}). "
                        f"This is {z_score:.1f} standard deviations above normal."
                    ),
                    evidence={
                        "event_count": count,
                        "z_score": round(z_score, 2),
                        "mean_events": round(mean_count, 1),
                        "std_deviation": round(std_count, 1),
                        "total_bytes": ip_bytes.get(ip, 0),
                    },
                    recommendation=(
                        "Investigate the source for automated scanning, malware activity, "
                        "or misconfigured applications generating excessive traffic."
                    ),
                    mitre_id="",
                    timestamp=events[0].timestamp,
                )

    # ── Alert Creation & Deduplication ─────────────────────────

    def _create_alert(
        self,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: Severity,
        src_ip: str,
        description: str,
        evidence: dict,
        recommendation: str,
        mitre_id: str = "",
        dst_ip: str = "",
        dst_port: int = 0,
        timestamp: Optional[datetime] = None,
    ):
        """Create and store a new alert."""
        alert = Alert(
            alert_id=f"ALERT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=timestamp or datetime.now(),
            rule_id=rule_id,
            rule_name=rule_name,
            category=category,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            mitre_attack_id=mitre_id,
        )
        self.alerts.append(alert)

    def _deduplicate_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """Remove duplicate alerts within the deduplication window."""
        seen: Dict[str, datetime] = {}
        unique_alerts = []

        for alert in sorted(alerts, key=lambda a: a.timestamp):
            # Create dedup key from rule + source
            dedup_key = f"{alert.rule_id}:{alert.src_ip}:{alert.dst_ip}"

            last_seen = seen.get(dedup_key)
            if last_seen is None or (alert.timestamp - last_seen) > self.dedup_window:
                seen[dedup_key] = alert.timestamp
                unique_alerts.append(alert)

        return unique_alerts