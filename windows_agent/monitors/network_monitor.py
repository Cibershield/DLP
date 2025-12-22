#!/usr/bin/env python3
"""
Network Monitor for Windows
Cibershield R.L. 2025

Monitors network connections to detect GitHub access.
Uses psutil for connection monitoring.
Optionally uses ETW (Event Tracing for Windows) for advanced monitoring.
"""

import logging
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("NetworkMonitor")


class NetworkMonitor:
    """
    Monitors network connections to detect access to GitHub servers.

    Primary method: psutil connection enumeration
    Advanced method: ETW network events (requires admin)
    """

    # GitHub IP ranges (from api.github.com/meta)
    GITHUB_IP_RANGES = [
        ('140.82.112.0', '140.82.127.255'),      # 140.82.112.0/20
        ('192.30.252.0', '192.30.255.255'),      # 192.30.252.0/22
        ('185.199.108.0', '185.199.111.255'),    # 185.199.108.0/22
        ('143.55.64.0', '143.55.79.255'),        # 143.55.64.0/20
        ('20.201.28.0', '20.201.28.255'),        # Azure
        ('20.205.243.0', '20.205.243.255'),      # Azure
        ('20.233.83.0', '20.233.83.255'),        # Azure
        ('20.248.137.0', '20.248.137.255'),      # Azure
        ('20.27.177.0', '20.27.177.255'),        # Azure
        ('4.208.26.0', '4.208.26.255'),          # Azure
    ]

    # GitHub domains to resolve
    GITHUB_DOMAINS = [
        'github.com',
        'api.github.com',
        'raw.githubusercontent.com',
        'gist.github.com',
        'codeload.github.com',
        'github.githubassets.com'
    ]

    def __init__(
        self,
        callback: Callable[[Dict], None] = None,
        check_interval: float = 1.0
    ):
        """
        Initialize the network monitor.

        Args:
            callback: Function to call when GitHub connection detected
            check_interval: Seconds between connection checks
        """
        self.callback = callback
        self.check_interval = check_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._seen_connections: Set[Tuple] = set()
        self._github_ips: Set[str] = set()
        self._resolve_github_ips()

    def _resolve_github_ips(self):
        """Resolve GitHub domains to IP addresses."""
        for domain in self.GITHUB_DOMAINS:
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    self._github_ips.add(ip)
            except socket.gaierror:
                pass

        logger.debug(f"Resolved {len(self._github_ips)} GitHub IPs")

    def _ip_to_int(self, ip: str) -> int:
        """Convert IP address to integer."""
        parts = [int(p) for p in ip.split('.')]
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

    def is_github_ip(self, ip: str) -> bool:
        """
        Check if an IP address belongs to GitHub.

        Args:
            ip: IP address to check

        Returns:
            True if it's a GitHub IP
        """
        # Check resolved IPs first
        if ip in self._github_ips:
            return True

        # Check IP ranges
        try:
            ip_int = self._ip_to_int(ip)
            for start, end in self.GITHUB_IP_RANGES:
                if self._ip_to_int(start) <= ip_int <= self._ip_to_int(end):
                    return True
        except (ValueError, IndexError):
            pass

        return False

    def start(self):
        """Start monitoring network connections."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("NetworkMonitor started")

    def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("NetworkMonitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop using psutil."""
        try:
            import psutil

            while self._running:
                try:
                    self._check_connections()
                    time.sleep(self.check_interval)
                except Exception as e:
                    logger.error(f"Connection check error: {e}")
                    time.sleep(2)

        except ImportError:
            logger.error("psutil not available - network monitoring disabled")

    def _check_connections(self):
        """Check current network connections for GitHub access."""
        import psutil

        for conn in psutil.net_connections(kind='inet'):
            try:
                # Only interested in established connections
                if conn.status != 'ESTABLISHED':
                    continue

                # Need remote address
                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

                # Create connection key
                conn_key = (conn.pid, remote_ip, remote_port)

                # Skip already seen connections
                if conn_key in self._seen_connections:
                    continue

                self._seen_connections.add(conn_key)

                # Check if GitHub connection
                if not self.is_github_ip(remote_ip):
                    continue

                # Get process info
                process_name = "unknown"
                cmdline = ""
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                    cmdline = ' '.join(proc.cmdline())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # Build event info
                info = {
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'local_port': conn.laddr.port if conn.laddr else None,
                    'pid': conn.pid,
                    'process_name': process_name,
                    'command_line': cmdline,
                    'is_github': True,
                    'connection_type': 'https' if remote_port == 443 else 'ssh' if remote_port == 22 else 'other',
                    'severity': 'info'
                }

                logger.info(f"GitHub connection: {process_name} -> {remote_ip}:{remote_port}")

                if self.callback:
                    self.callback(info)

            except Exception as e:
                logger.debug(f"Error processing connection: {e}")

        # Clean up old connections periodically
        if len(self._seen_connections) > 10000:
            self._seen_connections.clear()

    def get_active_github_connections(self) -> List[Dict]:
        """
        Get all currently active GitHub connections.

        Returns:
            List of connection info dicts
        """
        connections = []

        try:
            import psutil

            for conn in psutil.net_connections(kind='inet'):
                if conn.status != 'ESTABLISHED' or not conn.raddr:
                    continue

                if not self.is_github_ip(conn.raddr.ip):
                    continue

                process_name = "unknown"
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                connections.append({
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'pid': conn.pid,
                    'process_name': process_name
                })

        except ImportError:
            logger.error("psutil not available")

        return connections


class DNSMonitor:
    """
    Optional DNS query monitor using ETW.
    Requires administrator privileges.
    """

    GITHUB_DOMAINS = {
        'github.com', 'api.github.com', 'raw.githubusercontent.com',
        'gist.github.com', 'codeload.github.com', 'github.githubassets.com',
        'avatars.githubusercontent.com', 'objects.githubusercontent.com'
    }

    def __init__(self, callback: Callable[[Dict], None] = None):
        self.callback = callback
        self._running = False
        self._etw_available = False

    def start(self):
        """Start DNS monitoring (requires admin)."""
        # ETW DNS monitoring would go here
        # For now, this is a placeholder
        logger.info("DNS monitoring not yet implemented (requires ETW)")
        pass

    def stop(self):
        """Stop DNS monitoring."""
        self._running = False


if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.DEBUG)

    def on_connection(info):
        print(f"GitHub connection: {info['process_name']} -> {info['remote_ip']}:{info['remote_port']}")

    monitor = NetworkMonitor(callback=on_connection)

    print("Starting network monitor (Ctrl+C to stop)...")
    print("Try: git clone https://github.com/any/repo.git")
    monitor.start()

    try:
        while True:
            # Periodically show active GitHub connections
            conns = monitor.get_active_github_connections()
            if conns:
                print(f"Active GitHub connections: {len(conns)}")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()
