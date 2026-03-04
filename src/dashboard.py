"""
NetSentinel - CLI Dashboard
Interactive command-line interface for running the NIDS analyzer
with real-time status display and formatted output.
"""

import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import AnalysisResult

logger = logging.getLogger("NetSentinel.Dashboard")


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_BLUE = "\033[44m"
    BG_RED = "\033[41m"


class Dashboard:
    """
    Command-line dashboard for NetSentinel.
    Displays analysis progress, results summary, and navigation.
    """

    BANNER = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     ███╗   ██╗███████╗████████╗                              ║
    ║     ████╗  ██║██╔════╝╚══██╔══╝                              ║
    ║     ██╔██╗ ██║█████╗     ██║                                 ║
    ║     ██║╚██╗██║██╔══╝     ██║                                 ║
    ║     ██║ ╚████║███████╗   ██║                                 ║
    ║     ╚═╝  ╚═══╝╚══════╝   ╚═╝                                ║
    ║                                                              ║
    ║     ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗         ║
    ║     ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║         ║
    ║     ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║         ║
    ║     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║         ║
    ║     ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║         ║
    ║     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝      ║
    ║                                                              ║
    ║     Network Intrusion Detection System  v1.0.0               ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """

    def __init__(self):
        self._start_time = None

    def show_banner(self):
        """Display the application banner."""
        print(f"{Colors.CYAN}{self.BANNER}{Colors.RESET}")
        print(f"    {Colors.DIM}Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print()

    def show_phase(self, phase: str, description: str = ""):
        """Display a phase header."""
        print(f"\n  {Colors.BLUE}{Colors.BOLD}▶ {phase}{Colors.RESET}")
        if description:
            print(f"    {Colors.DIM}{description}{Colors.RESET}")

    def show_progress(self, message: str, status: str = "working"):
        """Display a progress message."""
        icons = {
            "working": f"{Colors.YELLOW}⟳{Colors.RESET}",
            "done": f"{Colors.GREEN}✓{Colors.RESET}",
            "error": f"{Colors.RED}✗{Colors.RESET}",
            "info": f"{Colors.CYAN}ℹ{Colors.RESET}",
            "warning": f"{Colors.YELLOW}⚠{Colors.RESET}",
        }
        icon = icons.get(status, icons["info"])
        print(f"    {icon} {message}")

    def show_stats_box(self, title: str, stats: dict):
        """Display a statistics box."""
        print(f"\n    {Colors.BOLD}┌─ {title} {'─' * (50 - len(title))}┐{Colors.RESET}")
        for key, value in stats.items():
            key_display = key.replace("_", " ").title()
            print(f"    │  {key_display:<30s} {str(value):>18s} │")
        print(f"    {Colors.BOLD}└{'─' * 52}┘{Colors.RESET}")

    def show_result_summary(self, result: AnalysisResult):
        """Display the final analysis result summary."""
        print(f"\n  {'═' * 62}")
        print(f"  {Colors.BOLD} ANALYSIS RESULTS{Colors.RESET}")
        print(f"  {'═' * 62}")

        # Risk Score
        risk_color = Colors.GREEN
        if result.risk_score >= 80:
            risk_color = Colors.RED
        elif result.risk_score >= 60:
            risk_color = Colors.YELLOW
        elif result.risk_score >= 40:
            risk_color = Colors.YELLOW

        risk_bar_len = int(result.risk_score / 2)
        risk_bar = "█" * risk_bar_len + "░" * (50 - risk_bar_len)

        print(f"\n    {Colors.BOLD}Risk Score:{Colors.RESET}")
        print(f"    {risk_color}{risk_bar} {result.risk_score:.0f}/100 ({result.risk_level}){Colors.RESET}")

        # Alert Summary
        counts = result.alert_count_by_severity
        print(f"\n    {Colors.BOLD}Alerts:{Colors.RESET}")

        severity_bars = [
            (f"{Colors.RED}CRITICAL{Colors.RESET}", counts.get("CRITICAL", 0)),
            (f"{Colors.YELLOW}HIGH{Colors.RESET}    ", counts.get("HIGH", 0)),
            (f"{Colors.YELLOW}MEDIUM{Colors.RESET}  ", counts.get("MEDIUM", 0)),
            (f"{Colors.GREEN}LOW{Colors.RESET}     ", counts.get("LOW", 0)),
        ]
        for label, count in severity_bars:
            bar = "■" * min(count, 40)
            print(f"      {label} │ {bar} ({count})")

        # Processing Stats
        self.show_stats_box("Processing Statistics", {
            "Events Processed": f"{result.total_events_processed:,}",
            "Files Analyzed": str(result.total_files_processed),
            "Total Alerts": str(len(result.alerts)),
            "Processing Time": f"{result.processing_time_seconds:.2f}s",
        })

        # Top Recommendations
        if result.recommendations:
            print(f"\n    {Colors.BOLD}{Colors.CYAN}Top Recommendations:{Colors.RESET}")
            for i, rec in enumerate(result.recommendations[:5], 1):
                print(f"      {Colors.CYAN}{i}. {rec}{Colors.RESET}")

        print(f"\n  {'═' * 62}\n")

    def show_report_paths(self, report_paths: dict):
        """Display generated report file paths."""
        print(f"    {Colors.BOLD}Generated Reports:{Colors.RESET}")
        for fmt, path in report_paths.items():
            print(f"      📄 {fmt.upper()}: {Colors.BLUE}{path}{Colors.RESET}")

    def show_completion(self, elapsed: float):
        """Show completion message."""
        print(f"\n  {Colors.GREEN}{Colors.BOLD}✅ Analysis complete!{Colors.RESET}")
        print(f"     Total time: {elapsed:.2f} seconds")
        print(f"     {Colors.DIM}Thank you for using NetSentinel.{Colors.RESET}\n")

    def start_timer(self):
        """Start the elapsed time timer."""
        self._start_time = time.time()

    def get_elapsed(self) -> float:
        """Get elapsed time since timer started."""
        if self._start_time:
            return time.time() - self._start_time
        return 0.0
