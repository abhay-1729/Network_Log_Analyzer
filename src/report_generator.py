"""
NetSentinel - Report Generator
Creates comprehensive HTML and JSON security analysis reports
with embedded visualizations and executive summaries.
"""

import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Alert, AnalysisResult, TrafficStats

logger = logging.getLogger("NetSentinel.ReportGenerator")


class ReportGenerator:
    """
    Generates formatted analysis reports in HTML and JSON formats.

    Flow:
        AnalysisResult + TrafficStats + Alerts
                    |
                    v
            ┌──────────────────┐
            │ Report Generator │
            ├──────────────────┤
            │  ─ Executive     │
            │    Summary       │
            │  ─ Alert Details │
            │  ─ Traffic Stats │
            │  ─ Charts (HTML) │
            │  ─ Recommend.    │
            └────────┬─────────┘
                     v
            HTML / JSON Reports
    """

    def __init__(self, config: dict, project_root: Path):
        self.config = config.get("reporting", {})
        self.project_root = project_root
        self.output_dir = project_root / self.config.get(
            "output_directory", "output/reports"
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.top_n = self.config.get("top_n_entries", 20)

    def generate(
        self,
        result: AnalysisResult,
        traffic_stats: Optional[TrafficStats] = None,
    ) -> Dict[str, str]:
        """
        Generate reports in all configured formats.

        Returns:
            Dict mapping format name to output file path.
        """
        output_files = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        formats = self.config.get("formats", ["html", "json"])

        if "json" in formats:
            json_path = self.output_dir / f"report_{timestamp}.json"
            self._generate_json(result, traffic_stats, json_path)
            output_files["json"] = str(json_path)

        if "html" in formats:
            html_path = self.output_dir / f"report_{timestamp}.html"
            self._generate_html(result, traffic_stats, html_path)
            output_files["html"] = str(html_path)

        logger.info(f"Reports generated: {list(output_files.keys())}")
        return output_files

    # ── JSON Report ────────────────────────────────────────────

    def _generate_json(
        self,
        result: AnalysisResult,
        traffic_stats: Optional[TrafficStats],
        output_path: Path,
    ):
        """Generate a JSON format report."""
        report = {
            "report_metadata": {
                "title": "NetSentinel Security Analysis Report",
                "generated_at": datetime.now().isoformat(),
                "analysis_id": result.analysis_id,
                "version": "1.0.0",
            },
            "executive_summary": {
                "risk_score": result.risk_score,
                "risk_level": result.risk_level,
                "total_events_processed": result.total_events_processed,
                "total_alerts": len(result.alerts),
                "alert_severity_breakdown": result.alert_count_by_severity,
                "processing_time_seconds": result.processing_time_seconds,
                "analysis_period": {
                    "start": result.start_time.isoformat(),
                    "end": result.end_time.isoformat(),
                },
                "summary": result.summary,
            },
            "alerts": [a.to_dict() for a in result.alerts],
            "recommendations": result.recommendations,
        }

        if traffic_stats:
            report["traffic_statistics"] = {
                "total_events": traffic_stats.total_events,
                "total_bytes": traffic_stats.total_bytes,
                "unique_source_ips": traffic_stats.unique_src_ips,
                "unique_destination_ips": traffic_stats.unique_dst_ips,
                "events_per_second": round(traffic_stats.events_per_second, 2),
                "protocol_distribution": traffic_stats.protocol_distribution,
                "top_talkers": traffic_stats.top_talkers,
                "top_destinations": traffic_stats.top_destinations,
                "top_ports": traffic_stats.top_ports,
            }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"JSON report saved: {output_path}")

    # ── HTML Report ────────────────────────────────────────────

    def _generate_html(
        self,
        result: AnalysisResult,
        traffic_stats: Optional[TrafficStats],
        output_path: Path,
    ):
        """Generate a comprehensive HTML report with embedded styling and charts."""

        severity_counts = result.alert_count_by_severity
        category_counts = defaultdict(int)
        for alert in result.alerts:
            category_counts[alert.category] += 1

        # Build chart data
        severity_chart_data = json.dumps(severity_counts)
        category_chart_data = json.dumps(dict(category_counts))
        protocol_chart_data = json.dumps(
            traffic_stats.protocol_distribution if traffic_stats else {}
        )

        # Top talkers table rows
        top_talkers_rows = ""
        if traffic_stats and traffic_stats.top_talkers:
            for t in traffic_stats.top_talkers[:10]:
                top_talkers_rows += f"""
                <tr>
                    <td>{t['ip']}</td>
                    <td>{t['events']:,}</td>
                    <td>{t['bytes_human']}</td>
                </tr>"""

        # Top ports table
        top_ports_rows = ""
        if traffic_stats and traffic_stats.top_ports:
            for p in traffic_stats.top_ports[:10]:
                top_ports_rows += f"""
                <tr>
                    <td>{p['port']}</td>
                    <td>{p['service']}</td>
                    <td>{p['events']:,}</td>
                </tr>"""

        # Alerts table
        alerts_rows = ""
        severity_badge_class = {
            "CRITICAL": "badge-critical",
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low",
        }
        for alert in result.alerts:
            badge = severity_badge_class.get(alert.severity.value, "badge-low")
            alerts_rows += f"""
            <tr>
                <td><span class="{badge}">{alert.severity.value}</span></td>
                <td>{alert.rule_name}</td>
                <td>{alert.category}</td>
                <td>{alert.src_ip}</td>
                <td>{alert.dst_ip or 'N/A'}</td>
                <td class="description-cell">{alert.description[:120]}{'...' if len(alert.description) > 120 else ''}</td>
                <td>{alert.timestamp.strftime('%H:%M:%S')}</td>
            </tr>"""

        # Recommendations list
        recommendations_html = ""
        for i, rec in enumerate(result.recommendations, 1):
            recommendations_html += f'<li><strong>#{i}:</strong> {rec}</li>\n'

        # Risk gauge color
        risk_color = "#22c55e"  # green
        if result.risk_score >= 80:
            risk_color = "#ef4444"
        elif result.risk_score >= 60:
            risk_color = "#f97316"
        elif result.risk_score >= 40:
            risk_color = "#eab308"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel - Security Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --border: #334155;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size: 28px; color: var(--accent); }}
        .header .subtitle {{ color: var(--text-secondary); font-size: 14px; }}
        .header .timestamp {{ color: var(--text-secondary); text-align: right; font-size: 13px; }}

        /* Cards Grid */
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 36px;
            font-weight: 700;
            color: var(--accent);
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }}

        /* Risk Score */
        .risk-card .value {{ color: {risk_color}; }}

        /* Section */
        .section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 20px;
        }}
        .section h2 {{
            font-size: 20px;
            margin-bottom: 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
        }}
        .section h2 .icon {{ margin-right: 8px; }}

        /* Charts Grid */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .chart-container {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }}
        .chart-container h3 {{
            margin-bottom: 12px;
            color: var(--text-secondary);
            font-size: 14px;
            text-transform: uppercase;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th {{
            background: var(--bg-primary);
            color: var(--text-secondary);
            padding: 10px 12px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            color: var(--text-primary);
        }}
        tr:hover {{ background: rgba(59, 130, 246, 0.05); }}
        .description-cell {{ max-width: 300px; font-size: 12px; color: var(--text-secondary); }}

        /* Badges */
        .badge-critical {{
            background: var(--critical); color: white;
            padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;
        }}
        .badge-high {{
            background: var(--high); color: white;
            padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;
        }}
        .badge-medium {{
            background: var(--medium); color: #1e293b;
            padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;
        }}
        .badge-low {{
            background: var(--low); color: #1e293b;
            padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;
        }}

        /* Recommendations */
        .recommendations ul {{
            list-style: none; padding: 0;
        }}
        .recommendations li {{
            padding: 12px 16px;
            margin-bottom: 8px;
            background: var(--bg-primary);
            border-radius: 8px;
            border-left: 3px solid var(--accent);
            font-size: 14px;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div>
                <h1>🛡️ NetSentinel</h1>
                <div class="subtitle">Network Intrusion Detection System - Security Analysis Report</div>
            </div>
            <div class="timestamp">
                <div><strong>Report ID:</strong> {result.analysis_id}</div>
                <div><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                <div><strong>Analysis Period:</strong> {result.start_time.strftime('%Y-%m-%d %H:%M')} to {result.end_time.strftime('%Y-%m-%d %H:%M')}</div>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="cards-grid">
            <div class="stat-card risk-card">
                <div class="value">{result.risk_score:.0f}</div>
                <div class="label">Risk Score ({result.risk_level})</div>
            </div>
            <div class="stat-card">
                <div class="value">{result.total_events_processed:,}</div>
                <div class="label">Events Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(result.alerts)}</div>
                <div class="label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: var(--critical)">{severity_counts.get('CRITICAL', 0)}</div>
                <div class="label">Critical Alerts</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: var(--high)">{severity_counts.get('HIGH', 0)}</div>
                <div class="label">High Alerts</div>
            </div>
            <div class="stat-card">
                <div class="value">{result.processing_time_seconds:.1f}s</div>
                <div class="label">Processing Time</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2><span class="icon">📋</span>Executive Summary</h2>
            <p style="color: var(--text-secondary); line-height: 1.8;">{result.summary}</p>
        </div>

        <!-- Charts -->
        <div class="charts-grid">
            <div class="chart-container">
                <h3>Alert Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Alert Categories</h3>
                <canvas id="categoryChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Protocol Distribution</h3>
                <canvas id="protocolChart"></canvas>
            </div>
        </div>

        <!-- Alerts Table -->
        <div class="section">
            <h2><span class="icon">🚨</span>Security Alerts ({len(result.alerts)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>Category</th>
                        <th>Source IP</th>
                        <th>Target</th>
                        <th>Description</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {alerts_rows if alerts_rows else '<tr><td colspan="7" style="text-align:center; color: var(--low);">No alerts detected ✅</td></tr>'}
                </tbody>
            </table>
        </div>

        <!-- Traffic Stats -->
        {'<div class="charts-grid">' if traffic_stats else ''}
        {'<div class="section"><h2><span class="icon">📊</span>Top Talkers (Source IPs)</h2><table><thead><tr><th>IP Address</th><th>Events</th><th>Data Volume</th></tr></thead><tbody>' + top_talkers_rows + '</tbody></table></div>' if top_talkers_rows else ''}
        {'<div class="section"><h2><span class="icon">🔌</span>Top Destination Ports</h2><table><thead><tr><th>Port</th><th>Service</th><th>Events</th></tr></thead><tbody>' + top_ports_rows + '</tbody></table></div>' if top_ports_rows else ''}
        {'</div>' if traffic_stats else ''}

        <!-- Recommendations -->
        <div class="section recommendations">
            <h2><span class="icon">💡</span>Recommendations</h2>
            <ul>
                {recommendations_html if recommendations_html else '<li>No specific recommendations at this time. Continue monitoring.</li>'}
            </ul>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Generated by NetSentinel NIDS v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>This report is confidential and intended for authorized security personnel only.</p>
        </div>
    </div>

    <!-- Charts Script -->
    <script>
        const chartColors = {{
            critical: '#ef4444',
            high: '#f97316',
            medium: '#eab308',
            low: '#22c55e',
            protocols: ['#3b82f6', '#8b5cf6', '#ec4899', '#06b6d4', '#10b981', '#f59e0b', '#6366f1']
        }};

        // Severity Chart
        const sevData = {severity_chart_data};
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(sevData),
                datasets: [{{
                    data: Object.values(sevData),
                    backgroundColor: [chartColors.critical, chartColors.high, chartColors.medium, chartColors.low],
                    borderWidth: 0,
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#94a3b8' }} }}
                }}
            }}
        }});

        // Category Chart
        const catData = {category_chart_data};
        new Chart(document.getElementById('categoryChart'), {{
            type: 'bar',
            data: {{
                labels: Object.keys(catData),
                datasets: [{{
                    label: 'Alerts',
                    data: Object.values(catData),
                    backgroundColor: chartColors.protocols,
                    borderRadius: 4,
                }}]
            }},
            options: {{
                responsive: true,
                indexAxis: 'y',
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#334155' }} }},
                    y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }}
                }}
            }}
        }});

        // Protocol Chart
        const protoData = {protocol_chart_data};
        new Chart(document.getElementById('protocolChart'), {{
            type: 'pie',
            data: {{
                labels: Object.keys(protoData),
                datasets: [{{
                    data: Object.values(protoData),
                    backgroundColor: chartColors.protocols,
                    borderWidth: 0,
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#94a3b8' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML report saved: {output_path}")
