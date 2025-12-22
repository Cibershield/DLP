#!/usr/bin/env python3
"""
Windows DLP Agent - Main Orchestrator
Cibershield R.L. 2025

Data Loss Prevention Agent for Windows (ARM64 & x86-64)
Monitors git operations, network connections, and file system changes.
Reports events to the central DLP console.
"""

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime
from typing import Dict, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.system_info import SystemInfo, get_system_info
from utils.config_loader import ConfigLoader, get_config
from utils.event_reporter import EventReporter, init_reporter, get_reporter
from monitors.process_monitor import ProcessMonitor
from monitors.file_monitor import FileMonitor, GitRepoDetector
from monitors.network_monitor import NetworkMonitor
from monitors.git_detector import GitDetector, get_git_detector

# Version
__version__ = "1.0.0"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("DLPAgent")


class WindowsDLPAgent:
    """
    Main DLP Agent class that orchestrates all monitors.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the DLP Agent.

        Args:
            config_path: Path to config.yaml (optional)
        """
        self.config = get_config(config_path)
        self.system_info = get_system_info()
        self.git_detector = get_git_detector()

        # Agent identification
        self.agent_name = self._generate_agent_name()

        # Monitors
        self.process_monitor: Optional[ProcessMonitor] = None
        self.file_monitor: Optional[FileMonitor] = None
        self.network_monitor: Optional[NetworkMonitor] = None
        self.repo_detector: Optional[GitRepoDetector] = None

        # Reporter
        self.reporter: Optional[EventReporter] = None

        # State
        self._running = False
        self._start_time: Optional[datetime] = None

        logger.info(f"DLP Agent initialized: {self.agent_name}")
        logger.info(f"Architecture: {self.system_info.get_architecture()}")
        logger.info(f"Windows: {self.system_info.get_windows_version()}")

    def _generate_agent_name(self) -> str:
        """Generate a unique agent name."""
        base_name = self.config.get('agent.name', 'DLP-WIN')
        hostname = self.system_info.get_hostname()
        arch = self.system_info.get_architecture()
        return f"{base_name}-{hostname}-{arch}"

    def _on_process_event(self, info: Dict):
        """Handle process creation events."""
        try:
            # Analyze with git detector
            analysis = self.git_detector.analyze_process(
                process_name=info.get('name', ''),
                cmdline=info.get('command_line', ''),
                pid=info.get('pid'),
                parent_name=None
            )

            if analysis and analysis.get('is_network_operation'):
                # Report git event
                if self.reporter:
                    self.reporter.report_git_event(
                        operation=analysis.get('operation', 'unknown'),
                        repo_url=analysis.get('repo_url', 'unknown'),
                        username=info.get('user', 'unknown'),
                        details={
                            'organization': analysis.get('organization'),
                            'repo_name': analysis.get('repo_name'),
                            'branch': analysis.get('branch'),
                            'command_line': info.get('command_line', '')[:200],
                            'pid': info.get('pid')
                        }
                    )

                logger.info(
                    f"Git operation detected: {analysis.get('operation')} - "
                    f"{analysis.get('organization', 'unknown')}/{analysis.get('repo_name', 'unknown')}"
                )

        except Exception as e:
            logger.error(f"Error processing process event: {e}")

    def _on_file_event(self, info: Dict):
        """Handle file system events."""
        try:
            if self.reporter:
                self.reporter.report_file_event(
                    path=info.get('path', ''),
                    action=info.get('event_type', 'unknown'),
                    process_name=info.get('process', 'unknown')
                )

        except Exception as e:
            logger.error(f"Error processing file event: {e}")

    def _on_network_event(self, info: Dict):
        """Handle network connection events."""
        try:
            if self.reporter:
                self.reporter.report_network_event(
                    remote_ip=info.get('remote_ip', ''),
                    remote_port=info.get('remote_port', 0),
                    process_name=info.get('process_name', 'unknown'),
                    direction='outbound'
                )

        except Exception as e:
            logger.error(f"Error processing network event: {e}")

    def _on_repo_detected(self, info: Dict):
        """Handle new git repository detection."""
        try:
            logger.warning(f"New git repository: {info.get('repo_path')}")

            if self.reporter:
                self.reporter.report_event(
                    event_type='new_repository',
                    data=info,
                    severity='warning'
                )

        except Exception as e:
            logger.error(f"Error processing repo detection: {e}")

    def start(self):
        """Start the DLP Agent and all monitors."""
        if self._running:
            logger.warning("Agent already running")
            return

        logger.info("=" * 60)
        logger.info(f"Starting Windows DLP Agent v{__version__}")
        logger.info("=" * 60)

        self._running = True
        self._start_time = datetime.now()

        # Initialize event reporter
        console_url = self.config.get_console_url()
        self.reporter = init_reporter(
            console_url=console_url,
            agent_name=self.agent_name,
            batch_size=self.config.get('reporting.batch_size', 10),
            batch_timeout=self.config.get('reporting.batch_timeout', 5)
        )

        # Report agent start
        self.reporter.report_event(
            event_type='agent_start',
            data={
                'agent_name': self.agent_name,
                'version': __version__,
                'system': self.system_info.get_system_summary()
            },
            severity='info'
        )

        # Start process monitor
        watched_processes = self.config.get('monitoring.processes', [])
        self.process_monitor = ProcessMonitor(
            watched_processes=watched_processes,
            callback=self._on_process_event
        )
        self.process_monitor.start()

        # Start file monitor
        paths = self.config.get_paths()
        if paths:
            self.file_monitor = FileMonitor(
                paths=paths,
                patterns=self.config.get('monitoring.patterns', []),
                exclude_patterns=self.config.get('monitoring.exclude', []),
                callback=self._on_file_event
            )
            self.file_monitor.start()

            # Also start repo detector
            self.repo_detector = GitRepoDetector(
                paths=paths,
                callback=self._on_repo_detected
            )
            self.repo_detector.start()

        # Start network monitor
        if self.config.get('network.enabled', True):
            self.network_monitor = NetworkMonitor(
                callback=self._on_network_event
            )
            self.network_monitor.start()

        logger.info("All monitors started successfully")
        logger.info(f"Reporting to: {console_url}")

    def stop(self):
        """Stop the DLP Agent and all monitors."""
        if not self._running:
            return

        logger.info("Stopping DLP Agent...")
        self._running = False

        # Report agent stop
        if self.reporter:
            self.reporter.report_event(
                event_type='agent_stop',
                data={
                    'agent_name': self.agent_name,
                    'uptime_seconds': (datetime.now() - self._start_time).total_seconds()
                    if self._start_time else 0
                },
                severity='info'
            )

        # Stop monitors
        if self.process_monitor:
            self.process_monitor.stop()

        if self.file_monitor:
            self.file_monitor.stop()

        if self.repo_detector:
            self.repo_detector.stop()

        if self.network_monitor:
            self.network_monitor.stop()

        # Stop reporter (will flush remaining events)
        if self.reporter:
            self.reporter.stop()

        logger.info("DLP Agent stopped")

    def run(self):
        """Run the agent in foreground mode."""
        self.start()

        # Setup signal handlers
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        logger.info("Agent running. Press Ctrl+C to stop.")

        # Main loop
        while self._running:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                break

        self.stop()

    def get_status(self) -> Dict:
        """Get agent status information."""
        uptime = 0
        if self._start_time:
            uptime = (datetime.now() - self._start_time).total_seconds()

        return {
            'agent_name': self.agent_name,
            'version': __version__,
            'running': self._running,
            'uptime_seconds': uptime,
            'system': self.system_info.get_system_summary(),
            'monitors': {
                'process': self.process_monitor is not None,
                'file': self.file_monitor is not None,
                'network': self.network_monitor is not None
            },
            'reporter_stats': self.reporter.get_stats() if self.reporter else None
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Windows DLP Agent - Data Loss Prevention Monitoring'
    )
    parser.add_argument(
        '-c', '--config',
        help='Path to config.yaml',
        default=None
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'DLP Agent {__version__}'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show system status and exit'
    )

    args = parser.parse_args()

    # Set log level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Status mode
    if args.status:
        info = SystemInfo()
        print("\n=== System Information ===")
        print(f"Hostname: {info.get_hostname()}")
        print(f"Username: {info.get_username()}")
        print(f"Domain: {info.get_domain() or 'N/A'}")
        print(f"Architecture: {info.get_architecture()}")
        print(f"Windows: {info.get_windows_version()}")
        print(f"Admin: {'Yes' if info.is_admin() else 'No'}")
        return 0

    # Create and run agent
    agent = WindowsDLPAgent(config_path=args.config)
    agent.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())
