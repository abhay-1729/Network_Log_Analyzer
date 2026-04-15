"""
NetSentinel - Configuration Manager
Loads and validates YAML-based configuration for the entire application.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, Optional


class ConfigManager:
    """
    Centralized configuration manager.
    Loads settings from YAML file and provides typed access to all config values.
    """

    _instance: Optional["ConfigManager"] = None
    _config: Dict[str, Any] = {}

    def __new__(cls, config_path: Optional[str] = None):
        """Singleton pattern to ensure single config instance across the app."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path: Optional[str] = None):
        if self._initialized:
            return
        self._initialized = True

        if config_path is None:
            # Default config path relative to project root
            project_root = Path(__file__).parent.parent
            config_path = str(project_root / "config" / "settings.yaml")

        self._config_path = config_path
        self._project_root = Path(config_path).parent.parent
        self._load_config()
        self._setup_logging()
        self._ensure_directories()

    def _load_config(self):
        """Load configuration from YAML file."""
        try:
            with open(self._config_path, "r") as f:
                self._config = yaml.safe_load(f) or {}
            logging.info(f"Configuration loaded from {self._config_path}")
        except FileNotFoundError:
            logging.warning(f"Config file not found: {self._config_path}. Using defaults.")
            self._config = self._default_config()
        except yaml.YAMLError as e:
            logging.error(f"Error parsing config file: {e}")
            self._config = self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration if file not found."""
        return {
            "general": {
                "app_name": "NetSentinel",
                "version": "1.0.0",
                "log_level": "INFO",
                "timezone": "UTC",
                "max_workers": 4,
            },
            "input": {
                "log_directory": "data/logs",
                "supported_formats": ["csv", "json", "syslog"],
            },
            "detection": {
                "thresholds": {
                    "port_scan": {"unique_ports": 15, "time_window_seconds": 60},
                    "brute_force": {"failed_attempts": 5, "time_window_seconds": 300},
                    "ddos": {
                        "requests_per_second": 1000,
                        "unique_sources": 50,
                        "time_window_seconds": 10,
                    },
                },
                "anomaly": {
                    "enabled": True,
                    "sensitivity": "medium",
                    "z_score_threshold": 3.0,
                },
            },
            "alerts": {
                "min_severity": "LOW",
                "console_output": True,
                "file_output": True,
                "alert_log_file": "output/alerts/alerts.json",
            },
            "reporting": {
                "output_directory": "output/reports",
                "formats": ["html", "json"],
                "include_visualizations": True,
                "top_n_entries": 20,
            },
        }

    def _setup_logging(self):
        """Configure application-wide logging."""
        log_level = self.get("general.log_level", "INFO")
        log_dir = self._project_root / self.get("logging.directory", "output/app_logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        log_format = self.get(
            "logging.format",
            "%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
        )

        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format=log_format,
            handlers=[
                logging.FileHandler(log_dir / "netsentinel.log"),
                logging.StreamHandler(),
            ],
        )

    def _ensure_directories(self):
        """Create required output directories."""
        dirs_to_create = [
            self.get("input.log_directory", "data/logs"),
            self.get("reporting.output_directory", "output/reports"),
            "output/alerts",
            "output/app_logs",
            "output/visualizations",
        ]
        for d in dirs_to_create:
            full_path = self._project_root / d
            full_path.mkdir(parents=True, exist_ok=True)

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a config value using dot notation.
        Example: config.get("detection.thresholds.port_scan.unique_ports")
        """
        keys = key_path.split(".")
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value

    @property
    def project_root(self) -> Path:
        return self._project_root

    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a path relative to the project root."""
        return self._project_root / relative_path

    def __repr__(self):
        return f"ConfigManager(config_path='{self._config_path}')"
