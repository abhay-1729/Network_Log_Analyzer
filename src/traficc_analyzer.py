"""
NetSentinel - Traffic Analyzer
Provides statistical analysis and aggregation of network traffic data.
Computes traffic baselines, protocol distributions, top talkers, and flow analysis.
"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Tuple

from .models import NetworkEvent, TrafficStats

logger = logging.getLogger("NetSentinel.TrafficAnalyzer")


class TrafficAnalyzer:
    """
    Analyzes parsed network events to produce traffic statistics
    and behavioral baselines used by the detection engine and reports.

    Flow:
        List[NetworkEvent]
              |
              v
        ┌─────────────────────────┐
        │   Compute Statistics    │
        │  ─ Protocol Distribution│
        │  ─ Top Talkers         │
        │  ─ Port Analysis       │
        │  ─ Traffic Volume      │
        │  ─ Flow Metrics        │
        └────────────┬────────────┘
                     v
              TrafficStats
    """

    def __init__(self, config: dict):
        self.config = config
        self.top_n = config.get("reporting", {}).get("top_n_entries", 20)

    def analyze(self, events: List[NetworkEvent]) -> TrafficStats:
        """
        Perform comprehensive traffic analysis on a list of events.

        Args:
            events: Sorted list of NetworkEvent objects.

        Returns:
            TrafficStats with aggregated metrics.
        """
        if not events:
            now = datetime.now()
            return TrafficStats(time_window_start=now, time_window_end=now)

        logger.info(f"Analyzing traffic statistics for {len(events)} events...")

        stats = TrafficStats(
            time_window_start=events[0].timestamp,
            time_window_end=events[-1].timestamp,
            total_events=len(events),
        )

        # Compute all metrics
        stats.total_bytes = sum(e.total_bytes for e in events)
        stats.unique_src_ips = len({e.src_ip for e in events})
        stats.unique_dst_ips = len({e.dst_ip for e in events})
        stats.unique_dst_ports = len({e.dst_port for e in events if e.dst_port > 0})

        # Time-based metrics
        duration = max(
            (stats.time_window_end - stats.time_window_start).total_seconds(), 1
        )
        stats.events_per_second = stats.total_events / duration
        stats.bytes_per_second = stats.total_bytes / duration

        # Direction-based bytes
        stats.inbound_bytes = sum(
            e.bytes_received for e in events if e.direction == "inbound"
        )
        stats.outbound_bytes = sum(
            e.bytes_sent for e in events if e.direction == "outbound"
        )

        # Action counts
        stats.denied_connections = sum(
            1 for e in events if e.action in ("deny", "drop", "blocked", "reject")
        )
        stats.failed_actions = sum(
            1 for e in events if e.action in ("failed", "error")
        )

        # Distributions and rankings
        stats.protocol_distribution = self._protocol_distribution(events)
        stats.top_talkers = self._top_talkers(events)
        stats.top_destinations = self._top_destinations(events)
        stats.top_ports = self._top_ports(events)

        logger.info(
            f"Traffic stats: {stats.total_events} events, "
            f"{stats.unique_src_ips} sources, "
            f"{stats.unique_dst_ips} destinations, "
            f"{stats.total_bytes / (1024*1024):.1f} MB total"
        )

        return stats

    def _protocol_distribution(self, events: List[NetworkEvent]) -> Dict[str, int]:
        """Count events per protocol."""
        dist: Dict[str, int] = defaultdict(int)
        for event in events:
            proto = event.protocol if event.protocol else "UNKNOWN"
            dist[proto] += 1
        return dict(sorted(dist.items(), key=lambda x: x[1], reverse=True))

    def _top_talkers(self, events: List[NetworkEvent]) -> List[Dict[str, Any]]:
        """Find IPs generating the most traffic (by event count and bytes)."""
        ip_data: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"events": 0, "bytes": 0, "connections": 0}
        )

        for event in events:
            ip_data[event.src_ip]["events"] += 1
            ip_data[event.src_ip]["bytes"] += event.total_bytes
            ip_data[event.src_ip]["connections"] += 1

        sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]["events"], reverse=True)
        return [
            {
                "ip": ip,
                "events": data["events"],
                "bytes": data["bytes"],
                "bytes_human": self._human_bytes(data["bytes"]),
            }
            for ip, data in sorted_ips[: self.top_n]
        ]

    def _top_destinations(self, events: List[NetworkEvent]) -> List[Dict[str, Any]]:
        """Find most accessed destination IPs."""
        dst_data: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"events": 0, "bytes": 0, "unique_sources": set()}
        )

        for event in events:
            dst_data[event.dst_ip]["events"] += 1
            dst_data[event.dst_ip]["bytes"] += event.total_bytes
            dst_data[event.dst_ip]["unique_sources"].add(event.src_ip)

        sorted_dsts = sorted(
            dst_data.items(), key=lambda x: x[1]["events"], reverse=True
        )
        return [
            {
                "ip": ip,
                "events": data["events"],
                "bytes_human": self._human_bytes(data["bytes"]),
                "unique_sources": len(data["unique_sources"]),
            }
            for ip, data in sorted_dsts[: self.top_n]
        ]

    def _top_ports(self, events: List[NetworkEvent]) -> List[Dict[str, Any]]:
        """Find most accessed destination ports."""
        port_well_known = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            27017: "MongoDB", 6379: "Redis",
        }

        port_data: Dict[int, int] = defaultdict(int)
        for event in events:
            if event.dst_port > 0:
                port_data[event.dst_port] += 1

        sorted_ports = sorted(port_data.items(), key=lambda x: x[1], reverse=True)
        return [
            {
                "port": port,
                "service": port_well_known.get(port, "Unknown"),
                "events": count,
            }
            for port, count in sorted_ports[: self.top_n]
        ]

    def get_hourly_distribution(
        self, events: List[NetworkEvent]
    ) -> Dict[str, int]:
        """Get event distribution by hour of day."""
        hourly: Dict[str, int] = defaultdict(int)
        for event in events:
            hour_key = event.timestamp.strftime("%H:00")
            hourly[hour_key] += 1
        return dict(sorted(hourly.items()))

    def get_protocol_bytes(
        self, events: List[NetworkEvent]
    ) -> Dict[str, int]:
        """Get total bytes transferred per protocol."""
        proto_bytes: Dict[str, int] = defaultdict(int)
        for event in events:
            proto_bytes[event.protocol] += event.total_bytes
        return dict(sorted(proto_bytes.items(), key=lambda x: x[1], reverse=True))

    def get_connection_pairs(
        self, events: List[NetworkEvent], top_n: int = 10
    ) -> List[Dict]:
        """Get top source-destination IP pairs by connection count."""
        pairs: Dict[Tuple[str, str], int] = defaultdict(int)
        for event in events:
            pairs[(event.src_ip, event.dst_ip)] += 1

        sorted_pairs = sorted(pairs.items(), key=lambda x: x[1], reverse=True)
        return [
            {"src_ip": src, "dst_ip": dst, "connections": count}
            for (src, dst), count in sorted_pairs[:top_n]
        ]

    def get_geo_summary(self, events: List[NetworkEvent]) -> Dict[str, Any]:
        """
        Provide a summary of internal vs external IPs.
        (Simplified - actual implementation would use GeoIP database)
        """
        internal_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                             "172.20.", "172.21.", "172.22.", "172.23.",
                             "172.24.", "172.25.", "172.26.", "172.27.",
                             "172.28.", "172.29.", "172.30.", "172.31.",
                             "192.168.", "127.")
        internal_ips = set()
        external_ips = set()

        for event in events:
            for ip in (event.src_ip, event.dst_ip):
                if ip.startswith(internal_prefixes):
                    internal_ips.add(ip)
                else:
                    external_ips.add(ip)

        return {
            "internal_ips": len(internal_ips),
            "external_ips": len(external_ips),
            "internal_to_external_ratio": (
                f"{len(internal_ips)}:{len(external_ips)}"
                if external_ips else "All internal"
            ),
        }

    @staticmethod
    def _human_bytes(num_bytes: int) -> str:
        """Convert bytes to human-readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PB"
