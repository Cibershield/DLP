#!/usr/bin/env python3
"""
Configuration Loader
Cibershield R.L. 2025

Loads and manages YAML configuration for the Windows DLP Agent.
"""

import os
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger("ConfigLoader")


class ConfigLoader:
    """
    Loads and provides access to YAML configuration.
    Supports environment variable expansion.
    """

    # Default configuration values
    DEFAULTS = {
        'agent': {
            'name': 'DLP-WIN',
            'version': '1.0.0',
            'log_level': 'INFO'
        },
        'console': {
            'host': '127.0.0.1',
            'port': 5000,
            'use_ssl': False,
            'timeout': 10,
            'retry_attempts': 3
        },
        'monitoring': {
            'paths': ['%USERPROFILE%'],
            'patterns': ['*.git', '.git*'],
            'exclude': ['node_modules', '.venv'],
            'processes': ['git.exe', 'gh.exe'],
            'github': {
                'domains': ['github.com', 'api.github.com'],
                'ip_ranges': ['140.82.112.0/20', '192.30.252.0/22']
            }
        },
        'security': {
            'self_protection': False,
            'watchdog_enabled': True
        },
        'network': {
            'enabled': True,
            'log_dns': False,
            'block_unauthorized': False
        },
        'reporting': {
            'enabled': True,
            'batch_size': 10,
            'batch_timeout': 5,
            'local_log': '%PROGRAMDATA%\\DLP-Agent\\events.log'
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration loader.

        Args:
            config_path: Path to config.yaml (optional)
        """
        self.config_path = config_path
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _find_config_file(self) -> Optional[str]:
        """
        Find the configuration file in standard locations.

        Returns:
            Path to config file or None
        """
        search_paths = [
            # Same directory as script
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.yaml'),
            # Current working directory
            os.path.join(os.getcwd(), 'config.yaml'),
            # ProgramData
            os.path.join(os.getenv('PROGRAMDATA', 'C:\\ProgramData'),
                        'DLP-Agent', 'config.yaml'),
            # User AppData
            os.path.join(os.getenv('APPDATA', ''), 'DLP-Agent', 'config.yaml'),
        ]

        for path in search_paths:
            expanded = os.path.expandvars(path)
            normalized = os.path.normpath(expanded)
            if os.path.exists(normalized):
                logger.info(f"Found config at: {normalized}")
                return normalized

        return None

    def _load_config(self):
        """Load configuration from YAML file."""
        # Start with defaults
        self._config = self._deep_copy(self.DEFAULTS)

        # Find config file
        config_file = self.config_path or self._find_config_file()

        if not config_file:
            logger.warning("No config file found, using defaults")
            return

        try:
            import yaml
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f) or {}

            # Merge with defaults
            self._merge_config(self._config, file_config)
            logger.info(f"Configuration loaded from: {config_file}")

        except ImportError:
            logger.error("PyYAML not installed. Using defaults.")
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_file}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")

    def _deep_copy(self, obj: Any) -> Any:
        """Create a deep copy of nested dicts/lists."""
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy(item) for item in obj]
        else:
            return obj

    def _merge_config(self, base: Dict, override: Dict):
        """
        Recursively merge override into base config.

        Args:
            base: Base configuration dict (modified in place)
            override: Override values
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by dot-notation key.

        Args:
            key: Key like 'console.host' or 'monitoring.paths'
            default: Default value if key not found

        Returns:
            Configuration value
        """
        parts = key.split('.')
        value = self._config

        try:
            for part in parts:
                value = value[part]
            return value
        except (KeyError, TypeError):
            return default

    def get_expanded(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value with environment variables expanded.

        Args:
            key: Configuration key
            default: Default value

        Returns:
            Expanded configuration value
        """
        value = self.get(key, default)

        if isinstance(value, str):
            return os.path.expandvars(value)
        elif isinstance(value, list):
            return [os.path.expandvars(v) if isinstance(v, str) else v for v in value]
        else:
            return value

    def get_paths(self) -> List[str]:
        """Get monitored paths with environment variables expanded."""
        paths = self.get('monitoring.paths', [])
        expanded = []
        for path in paths:
            exp = os.path.expandvars(path)
            if os.path.exists(exp):
                expanded.append(exp)
            else:
                logger.debug(f"Path does not exist: {exp}")
        return expanded

    def get_console_url(self) -> str:
        """Get the console API URL."""
        host = self.get('console.host', '127.0.0.1')
        port = self.get('console.port', 5000)
        protocol = 'https' if self.get('console.use_ssl', False) else 'http'
        return f"{protocol}://{host}:{port}"

    def get_log_level(self) -> int:
        """Get the logging level as a constant."""
        level_str = self.get('agent.log_level', 'INFO').upper()
        levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return levels.get(level_str, logging.INFO)

    @property
    def config(self) -> Dict[str, Any]:
        """Get the full configuration dict."""
        return self._config


# Global config instance
_config: Optional[ConfigLoader] = None


def get_config(config_path: Optional[str] = None) -> ConfigLoader:
    """Get or create the global config instance."""
    global _config
    if _config is None:
        _config = ConfigLoader(config_path)
    return _config


if __name__ == "__main__":
    # Test
    import json
    config = ConfigLoader()
    print("Console URL:", config.get_console_url())
    print("Paths:", config.get_paths())
    print("Full config:", json.dumps(config.config, indent=2))
