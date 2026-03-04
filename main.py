"""
NetSentinel - Main Entry Point
Orchestrates the complete NIDS analysis pipeline:
    1. Configuration loading
    2. Log parsing
    3. Traffic analysis
    4. Intrusion detection
    5. Alert management
    6. Report generation

Usage:
    python main.py                          # Analyze logs in default directory
    python main.py --log-dir data/logs      # Specify log directory
    python main.py --generate-sample        # Generate sample data first
    python main.py --help                   # Show help
"""

import argparse
import logging
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config_manager import ConfigManager
from src.log_parser import LogParser
from src.traffic_analyzer import TrafficAnalyzer
from src.detection_engine import DetectionEngine
from src.alert_manager import AlertManager
from src.report_generator import ReportGenerator
from src.dashboard import Dashboard
from src.models import AnalysisResult
from src.generate_sample_data import generate_sample_logs

logger = logging.getLogger("NetSentinel.Main")


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="NetSentinel - Network Log Analyzer & Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                            Analyze logs in default directory
  python main.py --log-dir /path/to/logs    Analyze specific log directory
  python main.py --generate-sample          Generate sample data and analyze
  python main.py --generate-sample --only   Only generate sample data, don't analyze
  python main.py --config custom.yaml       Use custom configuration file
        """,
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default=None,
        help="Directory containing network log files to analyze",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to custom configuration YAML file",
    )
    parser.add_argument(
        "--generate-sample",
        action="store_true",
        help="Generate sample log data for testing",
    )
    parser.add_argument(
        "--only",
        action="store_true",
        help="Only generate sample data without running analysis",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip report generation",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output (alerts still logged)",
    )
    return parser.parse_args()


def calculate_risk_score(alerts: list) -> float:
    """Calculate overall risk score (0-100) based on alert severity and count."""
    if not alerts:
        return 0.0

    severity_weights = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
    }

    total_weight = sum(
        severity_weights.get(a.severity.value, 1) for a in alerts
    )

    # Normalize to 0-100 scale (cap at 100)
    score = min(total_weight, 100)
    return float(score)


def generate_recommendations(alerts: list, traffic_stats) -> list:
    """Generate actionable recommendations based on detected alerts."""
    recommendations = []
    categories_seen = {a.category for a in alerts}

    if "threat_intel" in categories_seen:
        recommendations.append(
            "CRITICAL: Block all communication with known malicious IPs immediately. "
            "Isolate affected hosts and conduct forensic investigation."
        )

    if "c2" in categories_seen:
        recommendations.append(
            "CRITICAL: C2 beaconing detected - isolate the affected host from the network. "
            "Run full malware scan and check for lateral movement."
        )

    if "brute_force" in categories_seen:
        recommendations.append(
            "HIGH: Implement account lockout policies and multi-factor authentication. "
            "Block attacking IPs at the perimeter firewall."
        )

    if "reconnaissance" in categories_seen:
        recommendations.append(
            "HIGH: Port scanning detected - review firewall rules and minimize exposed services. "
            "Ensure all exposed services are patched and hardened."
        )

    if "ddos" in categories_seen:
        recommendations.append(
            "HIGH: Deploy DDoS mitigation (rate limiting, traffic scrubbing). "
            "Consider CDN/WAF services for critical applications."
        )

    if "exfiltration" in categories_seen:
        recommendations.append(
            "HIGH: Investigate large outbound data transfers. Implement Data Loss Prevention "
            "(DLP) policies and monitor for unauthorized data movement."
        )

    if "insider_threat" in categories_seen:
        recommendations.append(
            "MEDIUM: Review after-hours network activity. Verify if scheduled tasks or "
            "legitimate maintenance was occurring. Enhance monitoring."
        )

    if "anomaly" in categories_seen:
        recommendations.append(
            "MEDIUM: Investigate traffic anomalies. Establish network baselines and "
            "tune detection thresholds to reduce false positives."
        )

    if not recommendations:
        recommendations.append(
            "No significant threats detected. Continue regular monitoring and keep "
            "detection signatures updated."
        )

    return recommendations


def generate_summary(result: AnalysisResult) -> str:
    """Generate an executive summary string."""
    counts = result.alert_count_by_severity
    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)

    if critical > 0:
        urgency = (
            f"URGENT ACTION REQUIRED: {critical} critical security alert(s) detected. "
            f"Evidence of active threats including "
        )
        categories = list({a.category for a in result.alerts if a.severity.value == "CRITICAL"})
        urgency += ", ".join(categories) + ". "
    elif high > 0:
        urgency = (
            f"Elevated threat level: {high} high-severity alert(s) require investigation. "
        )
    else:
        urgency = "Network security posture appears stable. "

    summary = (
        f"{urgency}"
        f"Analysis processed {result.total_events_processed:,} network events "
        f"from {result.total_files_processed} log file(s) over a period of "
        f"{(result.end_time - result.start_time).total_seconds() / 3600:.1f} hours. "
        f"Total of {len(result.alerts)} security alerts generated across "
        f"{len({a.category for a in result.alerts})} attack categories. "
        f"Overall risk score: {result.risk_score:.0f}/100 ({result.risk_level})."
    )
    return summary


def main():
    """Main execution pipeline."""
    args = parse_arguments()
    dashboard = Dashboard()

    # ── Phase 0: Banner ─────────────────────────────────────
    if not args.quiet:
        dashboard.show_banner()

    dashboard.start_timer()

    # ── Phase 1: Configuration ──────────────────────────────
    dashboard.show_phase("PHASE 1: Configuration", "Loading settings and detection rules")

    config_path = args.config or str(PROJECT_ROOT / "config" / "settings.yaml")
    config = ConfigManager(config_path)

    dashboard.show_progress("Configuration loaded", "done")
    dashboard.show_progress(f"Project root: {config.project_root}", "info")

    # ── Phase 2: Sample Data Generation (optional) ──────────
    if args.generate_sample:
        dashboard.show_phase("PHASE 2: Sample Data Generation", "Creating realistic network traffic logs")
        log_dir = str(config.resolve_path("data/logs"))
        generate_sample_logs(log_dir)
        dashboard.show_progress("Sample data generated", "done")

        if args.only:
            dashboard.show_completion(dashboard.get_elapsed())
            return

    # ── Phase 3: Log Parsing ────────────────────────────────
    dashboard.show_phase("PHASE 3: Log Parsing", "Reading and normalizing network log files")

    log_dir = args.log_dir or str(config.resolve_path(config.get("input.log_directory", "data/logs")))
    dashboard.show_progress(f"Scanning directory: {log_dir}", "info")

    parser = LogParser()
    events = parser.parse_directory(log_dir)

    if not events:
        dashboard.show_progress(
            "No events found! Use --generate-sample to create test data.", "error"
        )
        return

    dashboard.show_progress(f"Parsed {len(events):,} network events", "done")
    dashboard.show_stats_box("Parser Statistics", parser.stats)

    # ── Phase 4: Traffic Analysis ───────────────────────────
    dashboard.show_phase("PHASE 4: Traffic Analysis", "Computing traffic statistics and baselines")

    traffic_analyzer = TrafficAnalyzer(config._config)
    traffic_stats = traffic_analyzer.analyze(events)

    dashboard.show_progress(
        f"Unique sources: {traffic_stats.unique_src_ips}, "
        f"Unique destinations: {traffic_stats.unique_dst_ips}",
        "done",
    )
    dashboard.show_stats_box("Traffic Overview", {
        "Total Events": f"{traffic_stats.total_events:,}",
        "Total Data": f"{traffic_stats.total_bytes / (1024*1024):.1f} MB",
        "Events/sec": f"{traffic_stats.events_per_second:.1f}",
        "Unique Ports": str(traffic_stats.unique_dst_ports),
        "Denied Connections": str(traffic_stats.denied_connections),
    })

    # ── Phase 5: Intrusion Detection ────────────────────────
    dashboard.show_phase(
        "PHASE 5: Intrusion Detection",
        "Running rule-based and anomaly detection engines",
    )

    detection_engine = DetectionEngine(config._config, config.project_root)
    alerts = detection_engine.analyze(events)

    dashboard.show_progress(f"Detection complete: {len(alerts)} alerts generated", "done")

    # ── Phase 6: Alert Management ───────────────────────────
    dashboard.show_phase("PHASE 6: Alert Management", "Processing and formatting security alerts")

    alert_manager = AlertManager(config._config, config.project_root)
    alert_manager.process_alerts(alerts)

    dashboard.show_progress(f"Alerts processed and saved", "done")

    # ── Phase 7: Build Analysis Result ──────────────────────
    processing_time = dashboard.get_elapsed()

    result = AnalysisResult(
        analysis_id=f"ANALYSIS-{uuid.uuid4().hex[:8].upper()}",
        start_time=events[0].timestamp,
        end_time=events[-1].timestamp,
        total_events_processed=len(events),
        total_files_processed=len(list(Path(log_dir).iterdir())),
        alerts=alerts,
        traffic_stats=traffic_stats,
        processing_time_seconds=processing_time,
    )

    result.risk_score = calculate_risk_score(alerts)
    result.recommendations = generate_recommendations(alerts, traffic_stats)
    result.summary = generate_summary(result)

    # ── Phase 8: Report Generation ──────────────────────────
    if not args.no_report:
        dashboard.show_phase("PHASE 7: Report Generation", "Creating HTML and JSON reports")

        report_gen = ReportGenerator(config._config, config.project_root)
        report_paths = report_gen.generate(result, traffic_stats)

        dashboard.show_progress("Reports generated", "done")
        dashboard.show_report_paths(report_paths)

    # ── Final Summary ───────────────────────────────────────
    dashboard.show_result_summary(result)
    dashboard.show_completion(dashboard.get_elapsed())


if __name__ == "__main__":
    main()
