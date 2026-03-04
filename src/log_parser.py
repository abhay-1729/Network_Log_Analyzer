"""
NetSentinel - Log Parser Module
Parses network traffic logs from multiple formats (CSV, JSON, Syslog)
into normalized NetworkEvent objects for analysis.
"""

import csv
import json
import re
import logging
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional

from .models import NetworkEvent

logger = logging.getLogger("NetSentinel.LogParser")


class LogParser:
    """
    Multi-format network log parser.
    Supports CSV, JSON, and Syslog formats. Normalizes all entries
    into NetworkEvent objects for uniform downstream processing.

    Flow:
        Raw Log File  -->  Format Detection  -->  Format-Specific Parser
                                                        |
                                                        v
                                              List[NetworkEvent]
    """

    # Common timestamp formats encountered in logs
    TIMESTAMP_FORMATS = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]

    # Syslog regex pattern
    SYSLOG_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)"
    )

    # Firewall / network device syslog pattern
    NETWORK_SYSLOG_PATTERN = re.compile(
        r"src=(?P<src_ip>[\d.]+)(?::(?P<src_port>\d+))?\s+"
        r"dst=(?P<dst_ip>[\d.]+)(?::(?P<dst_port>\d+))?\s+"
        r"proto=(?P<protocol>\w+)\s*"
        r"(?:action=(?P<action>\w+))?\s*"
        r"(?:bytes=(?P<bytes>\d+))?\s*"
        r"(?:packets=(?P<packets>\d+))?",
        re.IGNORECASE,
    )

    def __init__(self):
        self._parse_errors = 0
        self._total_parsed = 0

    def parse_file(self, file_path: str) -> List[NetworkEvent]:
        """
        Parse a single log file. Auto-detects format based on extension.

        Args:
            file_path: Path to the log file.

        Returns:
            List of parsed NetworkEvent objects.
        """
        path = Path(file_path)
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        ext = path.suffix.lower()
        logger.info(f"Parsing file: {path.name} (format: {ext})")

        events = []
        try:
            if ext == ".csv":
                events = list(self._parse_csv(path))
            elif ext == ".json":
                events = list(self._parse_json(path))
            elif ext in (".log", ".syslog", ".txt"):
                events = list(self._parse_syslog(path))
            else:
                # Try auto-detection
                events = list(self._auto_detect_and_parse(path))

            self._total_parsed += len(events)
            logger.info(f"Successfully parsed {len(events)} events from {path.name}")

        except Exception as e:
            logger.error(f"Failed to parse {path.name}: {e}")

        return events

    def parse_directory(self, directory: str) -> List[NetworkEvent]:
        """
        Parse all log files in a directory.

        Args:
            directory: Path to directory containing log files.

        Returns:
            Combined list of all parsed NetworkEvent objects, sorted by timestamp.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.error(f"Directory not found: {directory}")
            return []

        all_events = []
        supported_exts = {".csv", ".json", ".log", ".syslog", ".txt"}
        files = [f for f in dir_path.iterdir() if f.is_file() and f.suffix.lower() in supported_exts]

        logger.info(f"Found {len(files)} log files in {directory}")

        for file_path in sorted(files):
            events = self.parse_file(str(file_path))
            all_events.extend(events)

        # Sort all events by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        logger.info(
            f"Total: {len(all_events)} events parsed from {len(files)} files "
            f"({self._parse_errors} parse errors)"
        )
        return all_events

    # ── CSV Parser ─────────────────────────────────────────────

    def _parse_csv(self, path: Path) -> Generator[NetworkEvent, None, None]:
        """Parse CSV format network logs."""
        with open(path, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            # Normalize header names to lowercase
            if reader.fieldnames:
                reader.fieldnames = [fn.strip().lower() for fn in reader.fieldnames]

            for row_num, row in enumerate(reader, start=2):
                try:
                    event = self._csv_row_to_event(row)
                    if event:
                        yield event
                except Exception as e:
                    self._parse_errors += 1
                    if self._parse_errors <= 10:
                        logger.debug(f"CSV parse error at row {row_num}: {e}")

    def _csv_row_to_event(self, row: dict) -> Optional[NetworkEvent]:
        """Convert a CSV row dict to a NetworkEvent."""
        # Flexible field mapping (handles various CSV column naming conventions)
        field_map = {
            "timestamp": ["timestamp", "time", "date", "datetime", "event_time", "log_time"],
            "src_ip": ["src_ip", "source_ip", "src", "source", "srcip", "src_addr"],
            "dst_ip": ["dst_ip", "dest_ip", "dst", "destination", "dstip", "dst_addr", "dest"],
            "src_port": ["src_port", "source_port", "sport", "srcport"],
            "dst_port": ["dst_port", "dest_port", "dport", "dstport", "destination_port"],
            "protocol": ["protocol", "proto", "ip_protocol"],
            "bytes_sent": ["bytes_sent", "sent_bytes", "upload_bytes", "out_bytes", "bytes_out"],
            "bytes_received": ["bytes_received", "recv_bytes", "download_bytes", "in_bytes", "bytes_in"],
            "packets": ["packets", "packet_count", "num_packets", "pkt_count"],
            "duration": ["duration", "session_duration", "flow_duration", "conn_duration"],
            "flags": ["flags", "tcp_flags", "flag"],
            "action": ["action", "event_action", "disposition", "result", "status"],
            "direction": ["direction", "flow_direction", "dir"],
            "domain": ["domain", "hostname", "host", "dns_query", "url"],
        }

        def get_field(field_name: str) -> Optional[str]:
            for alias in field_map.get(field_name, [field_name]):
                val = row.get(alias, "").strip()
                if val:
                    return val
            return None

        # Parse timestamp (required)
        ts_str = get_field("timestamp")
        if not ts_str:
            return None
        timestamp = self._parse_timestamp(ts_str)
        if not timestamp:
            return None

        # Parse required fields
        src_ip = get_field("src_ip") or "0.0.0.0"
        dst_ip = get_field("dst_ip") or "0.0.0.0"

        return NetworkEvent(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(get_field("src_port") or 0),
            dst_port=int(get_field("dst_port") or 0),
            protocol=(get_field("protocol") or "UNKNOWN").upper(),
            bytes_sent=int(get_field("bytes_sent") or 0),
            bytes_received=int(get_field("bytes_received") or 0),
            packets=int(get_field("packets") or 1),
            duration=float(get_field("duration") or 0.0),
            flags=get_field("flags") or "",
            action=(get_field("action") or "").lower(),
            direction=(get_field("direction") or "unknown").lower(),
            domain=get_field("domain") or "",
            raw_log=str(row),
        )

    # ── JSON Parser ────────────────────────────────────────────

    def _parse_json(self, path: Path) -> Generator[NetworkEvent, None, None]:
        """Parse JSON format network logs (array of objects or newline-delimited)."""
        content = path.read_text(encoding="utf-8-sig").strip()

        if content.startswith("["):
            # JSON array
            try:
                records = json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"JSON parse error in {path.name}: {e}")
                return
        else:
            # Newline-delimited JSON (NDJSON)
            records = []
            for line_num, line in enumerate(content.split("\n"), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    self._parse_errors += 1

        for record in records:
            try:
                # Normalize keys to lowercase
                normalized = {k.lower(): v for k, v in record.items()}
                event = self._json_record_to_event(normalized)
                if event:
                    yield event
            except Exception as e:
                self._parse_errors += 1

    def _json_record_to_event(self, record: dict) -> Optional[NetworkEvent]:
        """Convert a JSON record to a NetworkEvent."""
        # Find timestamp
        ts_val = (
            record.get("timestamp")
            or record.get("time")
            or record.get("datetime")
            or record.get("event_time")
        )
        if not ts_val:
            return None

        timestamp = self._parse_timestamp(str(ts_val))
        if not timestamp:
            return None

        src_ip = str(record.get("src_ip", record.get("source_ip", record.get("src", "0.0.0.0"))))
        dst_ip = str(record.get("dst_ip", record.get("dest_ip", record.get("dst", "0.0.0.0"))))

        return NetworkEvent(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(record.get("src_port", record.get("source_port", 0))),
            dst_port=int(record.get("dst_port", record.get("dest_port", 0))),
            protocol=str(record.get("protocol", record.get("proto", "UNKNOWN"))).upper(),
            bytes_sent=int(record.get("bytes_sent", record.get("out_bytes", 0))),
            bytes_received=int(record.get("bytes_received", record.get("in_bytes", 0))),
            packets=int(record.get("packets", record.get("packet_count", 1))),
            duration=float(record.get("duration", record.get("flow_duration", 0.0))),
            flags=str(record.get("flags", record.get("tcp_flags", ""))),
            action=str(record.get("action", record.get("disposition", ""))).lower(),
            status_code=record.get("status_code") or record.get("http_status"),
            direction=str(record.get("direction", "unknown")).lower(),
            domain=str(record.get("domain", record.get("hostname", ""))),
            raw_log=json.dumps(record),
        )

    # ── Syslog Parser ──────────────────────────────────────────

    def _parse_syslog(self, path: Path) -> Generator[NetworkEvent, None, None]:
        """Parse syslog format network logs."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    event = self._syslog_line_to_event(line)
                    if event:
                        yield event
                except Exception as e:
                    self._parse_errors += 1

    def _syslog_line_to_event(self, line: str) -> Optional[NetworkEvent]:
        """Convert a syslog line to a NetworkEvent."""
        # Try structured network syslog first
        net_match = self.NETWORK_SYSLOG_PATTERN.search(line)
        if net_match:
            # Try to extract timestamp from the beginning
            syslog_match = self.SYSLOG_PATTERN.match(line)
            ts_str = syslog_match.group("timestamp") if syslog_match else None
            timestamp = self._parse_timestamp(ts_str) if ts_str else datetime.now()

            return NetworkEvent(
                timestamp=timestamp,
                src_ip=net_match.group("src_ip"),
                dst_ip=net_match.group("dst_ip"),
                src_port=int(net_match.group("src_port") or 0),
                dst_port=int(net_match.group("dst_port") or 0),
                protocol=(net_match.group("protocol") or "UNKNOWN").upper(),
                bytes_sent=int(net_match.group("bytes") or 0),
                packets=int(net_match.group("packets") or 1),
                action=(net_match.group("action") or "").lower(),
                raw_log=line,
            )

        # Fallback: try to extract any IP addresses from the line
        syslog_match = self.SYSLOG_PATTERN.match(line)
        if syslog_match:
            ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
            ips = ip_pattern.findall(line)
            if len(ips) >= 2:
                timestamp = self._parse_timestamp(syslog_match.group("timestamp"))
                return NetworkEvent(
                    timestamp=timestamp or datetime.now(),
                    src_ip=ips[0],
                    dst_ip=ips[1],
                    src_port=0,
                    dst_port=0,
                    protocol="UNKNOWN",
                    raw_log=line,
                    metadata={"program": syslog_match.group("program")},
                )

        return None

    # ── Auto Detection ─────────────────────────────────────────

    def _auto_detect_and_parse(self, path: Path) -> Generator[NetworkEvent, None, None]:
        """Try to auto-detect file format and parse accordingly."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()

        if first_line.startswith("{") or first_line.startswith("["):
            yield from self._parse_json(path)
        elif "," in first_line and not first_line.startswith("<"):
            yield from self._parse_csv(path)
        else:
            yield from self._parse_syslog(path)

    # ── Utility ────────────────────────────────────────────────

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Try multiple timestamp formats to parse a timestamp string."""
        if not ts_str:
            return None

        ts_str = ts_str.strip()

        # Try each known format
        for fmt in self.TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(ts_str, fmt)
                # If year is 1900 (format without year), use current year
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue

        # Try ISO format as fallback
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00").replace("+00:00", ""))
        except (ValueError, AttributeError):
            pass

        return None

    @property
    def stats(self) -> dict:
        """Return parsing statistics."""
        return {
            "total_parsed": self._total_parsed,
            "parse_errors": self._parse_errors,
            "success_rate": (
                f"{(self._total_parsed / (self._total_parsed + self._parse_errors) * 100):.1f}%"
                if (self._total_parsed + self._parse_errors) > 0
                else "N/A"
            ),
        }
