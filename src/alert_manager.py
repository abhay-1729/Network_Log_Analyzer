"""
NetSentinel - Alert Manager
Handles alert storage, formatting, console output, and file persistence.
Provides alert aggregation, filtering, and severity-based prioritization.
"""

import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .models import Alert, Severity

logger = logging.getLogger("NetSentinel.AlertManager")


# ── Console Colors (ANSI) ─────────────────────────────────────

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN = "\033[42m"
    DIM = "\033[2m"

    SEVERITY_COLORS = {
        "CRITICAL": "\033[41m\033[97m",   # White on Red
        "HIGH": "\033[91m",               # Red
        "MEDIUM": "\033[93m",             # Yellow
        "LOW": "\033[92m",                # Green
    }


class AlertManager:
    """
    Manages security alerts: storage, filtering, console display, and file output.

    Flow:
        Detection Engine  -->  AlertManager.process_alerts()
                                    |
                          +---------+---------+
                          |         |         |
                          v         v         v
                      Console   JSON File  Aggregation
                      Output    Storage    & Stats
    """

    def __init__(self, config: dict, project_root: Path):
        self.config = config.get("alerts", {})
        self.project_root = project_root
        self.alerts: List[Alert] = []

        # Configuration
        self.min_severity = Severity[self.config.get("min_severity", "LOW")]
        self.console_output = self.config.get("console_output", True)
        self.file_output = self.config.get("file_output", True)
        self.alert_log_file = project_root / self.config.get(
            "alert_log_file", "output/alerts/alerts.json"
        )

        # Ensure alert directory exists
        self.alert_log_file.parent.mkdir(parents=True, exist_ok=True)

    def process_alerts(self, alerts: List[Alert]):
        """
        Process a batch of alerts: filter, display, and store.

        Args:
            alerts: List of Alert objects from the detection engine.
        """
        # Filter by minimum severity
        filtered = [a for a in alerts if a.severity >= self.min_severity]
        filtered.sort(key=lambda a: a.severity, reverse=True)

        self.alerts = filtered

        logger.info(f"Processing {len(filtered)} alerts (filtered from {len(alerts)})")

        if self.console_output:
            self._display_console(filtered)

        if self.file_output:
            self._save_to_file(filtered)

    def _display_console(self, alerts: List[Alert]):
        """Display alerts in a formatted console output."""
        if not alerts:
            print(f"\n{Colors.GREEN}{Colors.BOLD}  ✅ No security alerts detected.{Colors.RESET}\n")
            return

        # Header
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD}{Colors.RED}  🚨 SECURITY ALERTS - NetSentinel NIDS{Colors.RESET}")
        print(f"{'='*80}")
        print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Total Alerts: {len(alerts)}")

        # Severity summary bar
        severity_counts = self._count_by_severity(alerts)
        print(f"\n  Severity Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = Colors.SEVERITY_COLORS.get(sev, "")
                bar = "█" * min(count, 30)
                print(f"    {color}{sev:10s}{Colors.RESET} │ {bar} ({count})")

        print(f"\n{'─'*80}")

        # Individual alerts
        for i, alert in enumerate(alerts, 1):
            self._print_alert(i, alert)

        print(f"{'='*80}\n")

    def _print_alert(self, index: int, alert: Alert):
        """Print a single formatted alert."""
        sev_color = Colors.SEVERITY_COLORS.get(alert.severity.value, "")

        print(f"\n  {Colors.BOLD}Alert #{index}{Colors.RESET}")
        print(f"  ┌─────────────────────────────────────────────────────────────────")
        print(f"  │ {Colors.BOLD}ID:{Colors.RESET}        {alert.alert_id}")
        print(f"  │ {Colors.BOLD}Rule:{Colors.RESET}      [{alert.rule_id}] {alert.rule_name}")
        print(f"  │ {Colors.BOLD}Severity:{Colors.RESET}  {sev_color}{alert.severity.value}{Colors.RESET}")
        print(f"  │ {Colors.BOLD}Category:{Colors.RESET}  {alert.category}")
        print(f"  │ {Colors.BOLD}Time:{Colors.RESET}      {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  │ {Colors.BOLD}Source:{Colors.RESET}    {alert.src_ip}")

        if alert.dst_ip:
            print(f"  │ {Colors.BOLD}Target:{Colors.RESET}    {alert.dst_ip}"
                  + (f":{alert.dst_port}" if alert.dst_port else ""))

        print(f"  │")
        print(f"  │ {Colors.BOLD}Description:{Colors.RESET}")

        # Word wrap description
        desc_lines = self._wrap_text(alert.description, 60)
        for line in desc_lines:
            print(f"  │   {line}")

        if alert.evidence:
            print(f"  │")
            print(f"  │ {Colors.BOLD}Evidence:{Colors.RESET}")
            for key, value in alert.evidence.items():
                if isinstance(value, list) and len(str(value)) > 60:
                    print(f"  │   {key}: [{len(value)} items]")
                else:
                    print(f"  │   {key}: {value}")

        if alert.recommendation:
            print(f"  │")
            print(f"  │ {Colors.CYAN}{Colors.BOLD}💡 Recommendation:{Colors.RESET}")
            rec_lines = self._wrap_text(alert.recommendation, 58)
            for line in rec_lines:
                print(f"  │   {Colors.CYAN}{line}{Colors.RESET}")

        if alert.mitre_attack_id:
            print(f"  │")
            print(f"  │ {Colors.DIM}MITRE ATT&CK: {alert.mitre_attack_id}{Colors.RESET}")

        print(f"  └─────────────────────────────────────────────────────────────────")

    def _save_to_file(self, alerts: List[Alert]):
        """Save alerts to JSON file."""
        alert_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_alerts": len(alerts),
                "severity_summary": self._count_by_severity(alerts),
                "generator": "NetSentinel NIDS v1.0.0",
            },
            "alerts": [a.to_dict() for a in alerts],
        }

        try:
            with open(self.alert_log_file, "w") as f:
                json.dump(alert_data, f, indent=2, default=str)
            logger.info(f"Alerts saved to {self.alert_log_file}")
        except Exception as e:
            logger.error(f"Failed to save alerts: {e}")

    # ── Aggregation & Statistics ───────────────────────────────

    def get_summary(self) -> Dict:
        """Get a summary of all processed alerts."""
        if not self.alerts:
            return {"total": 0, "message": "No alerts"}

        summary = {
            "total_alerts": len(self.alerts),
            "severity_breakdown": self._count_by_severity(self.alerts),
            "category_breakdown": self._count_by_category(self.alerts),
            "top_source_ips": self._top_source_ips(self.alerts, 10),
            "timeline": self._alert_timeline(self.alerts),
        }
        return summary

    @staticmethod
    def _count_by_severity(alerts: List[Alert]) -> Dict[str, int]:
        counts = defaultdict(int)
        for alert in alerts:
            counts[alert.severity.value] += 1
        return dict(counts)

    @staticmethod
    def _count_by_category(alerts: List[Alert]) -> Dict[str, int]:
        counts = defaultdict(int)
        for alert in alerts:
            counts[alert.category] += 1
        return dict(counts)

    @staticmethod
    def _top_source_ips(alerts: List[Alert], top_n: int) -> List[Dict]:
        ip_counts = defaultdict(int)
        for alert in alerts:
            ip_counts[alert.src_ip] += 1
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "alert_count": count} for ip, count in sorted_ips[:top_n]]

    @staticmethod
    def _alert_timeline(alerts: List[Alert]) -> List[Dict]:
        hourly = defaultdict(int)
        for alert in alerts:
            hour_key = alert.timestamp.strftime("%Y-%m-%d %H:00")
            hourly[hour_key] += 1
        return [{"hour": h, "count": c} for h, c in sorted(hourly.items())]

    @staticmethod
    def _wrap_text(text: str, width: int) -> List[str]:
        """Simple word-wrapping."""
        words = text.split()
        lines = []
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 > width:
                lines.append(current_line)
                current_line = word
            else:
                current_line = f"{current_line} {word}".strip()
        if current_line:
            lines.append(current_line)
        return lines
