#!/usr/bin/env python3
"""
Process Monitor for Windows
Cibershield R.L. 2025

Monitors process creation using WMI (Windows Management Instrumentation).
Detects git commands and suspicious processes.
"""

import logging
import threading
import time
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger("ProcessMonitor")


class ProcessMonitor:
    """
    Monitors Windows process creation using WMI.

    Uses Win32_ProcessStartTrace for real-time process monitoring.
    Falls back to polling with psutil if WMI events are not available.
    """

    def __init__(
        self,
        watched_processes: List[str] = None,
        callback: Callable[[Dict], None] = None
    ):
        """
        Initialize the process monitor.

        Args:
            watched_processes: List of process names to watch (e.g., ['git.exe', 'gh.exe'])
            callback: Function to call when a watched process is detected
        """
        self.watched_processes: Set[str] = set(
            p.lower() for p in (watched_processes or [])
        )
        self.callback = callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._wmi_available = False
        self._seen_pids: Set[int] = set()

    def start(self):
        """Start monitoring processes."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("ProcessMonitor started")

    def stop(self):
        """Stop monitoring processes."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("ProcessMonitor stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        # Try WMI first
        if self._try_wmi_monitoring():
            return

        # Fall back to polling
        logger.info("Using polling mode for process monitoring")
        self._polling_monitor()

    def _try_wmi_monitoring(self) -> bool:
        """
        Try to use WMI for real-time process monitoring.

        Returns:
            True if WMI monitoring started successfully
        """
        try:
            import wmi
            import pythoncom

            # Initialize COM for this thread
            pythoncom.CoInitialize()

            try:
                c = wmi.WMI()

                # Create process watcher
                process_watcher = c.Win32_Process.watch_for("creation")

                logger.info("WMI process monitoring active")
                self._wmi_available = True

                while self._running:
                    try:
                        # Wait for new process (with timeout)
                        new_process = process_watcher(timeout_ms=1000)

                        if new_process:
                            self._handle_wmi_process(new_process)

                    except wmi.x_wmi_timed_out:
                        continue
                    except Exception as e:
                        logger.debug(f"WMI watcher error: {e}")

                return True

            finally:
                pythoncom.CoUninitialize()

        except ImportError:
            logger.warning("WMI module not available")
            return False
        except Exception as e:
            logger.warning(f"WMI monitoring failed: {e}")
            return False

    def _handle_wmi_process(self, process):
        """
        Handle a WMI process creation event.

        Args:
            process: WMI Win32_Process object
        """
        try:
            name = process.Name
            if not name:
                return

            name_lower = name.lower()

            # Check if this is a watched process
            if name_lower not in self.watched_processes:
                # Also check if it starts with any watched prefix
                if not any(name_lower.startswith(wp.replace('.exe', ''))
                          for wp in self.watched_processes):
                    return

            # Get process details
            info = {
                'name': name,
                'pid': process.ProcessId,
                'parent_pid': process.ParentProcessId,
                'command_line': process.CommandLine or '',
                'executable': process.ExecutablePath or '',
                'creation_time': str(process.CreationDate) if process.CreationDate else '',
                'user': self._get_process_user(process)
            }

            logger.debug(f"Detected process: {name} (PID: {info['pid']})")

            if self.callback:
                self.callback(info)

        except Exception as e:
            logger.error(f"Error handling WMI process: {e}")

    def _get_process_user(self, process) -> str:
        """Get the user running a process."""
        try:
            owner = process.GetOwner()
            if owner:
                domain, user = owner[0], owner[2]
                return f"{domain}\\{user}" if domain else user
        except Exception:
            pass
        return "unknown"

    def _polling_monitor(self):
        """
        Monitor processes using psutil polling.
        Fallback when WMI is not available.
        """
        try:
            import psutil

            while self._running:
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid', 'username']):
                        try:
                            pid = proc.info['pid']

                            # Skip already seen processes
                            if pid in self._seen_pids:
                                continue

                            name = proc.info['name'] or ''
                            name_lower = name.lower()

                            # Check if watched
                            if name_lower not in self.watched_processes:
                                if not any(name_lower.startswith(wp.replace('.exe', ''))
                                          for wp in self.watched_processes):
                                    self._seen_pids.add(pid)
                                    continue

                            # Get command line
                            cmdline = proc.info['cmdline']
                            cmdline_str = ' '.join(cmdline) if cmdline else ''

                            info = {
                                'name': name,
                                'pid': pid,
                                'parent_pid': proc.info['ppid'],
                                'command_line': cmdline_str,
                                'executable': proc.exe() if hasattr(proc, 'exe') else '',
                                'user': proc.info.get('username', 'unknown')
                            }

                            self._seen_pids.add(pid)

                            logger.debug(f"Detected process (poll): {name} (PID: {pid})")

                            if self.callback:
                                self.callback(info)

                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                    # Clean up seen PIDs for terminated processes
                    if len(self._seen_pids) > 10000:
                        current_pids = set(p.pid for p in psutil.process_iter())
                        self._seen_pids = self._seen_pids & current_pids

                    time.sleep(0.5)

                except Exception as e:
                    logger.error(f"Polling error: {e}")
                    time.sleep(1)

        except ImportError:
            logger.error("psutil not available - process monitoring disabled")

    def get_running_processes(self, filter_names: List[str] = None) -> List[Dict]:
        """
        Get a snapshot of currently running processes.

        Args:
            filter_names: Only return processes matching these names

        Returns:
            List of process info dicts
        """
        processes = []
        filter_set = set(n.lower() for n in (filter_names or []))

        try:
            import psutil

            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid', 'username']):
                try:
                    name = proc.info['name'] or ''
                    if filter_set and name.lower() not in filter_set:
                        continue

                    cmdline = proc.info['cmdline']
                    processes.append({
                        'name': name,
                        'pid': proc.info['pid'],
                        'parent_pid': proc.info['ppid'],
                        'command_line': ' '.join(cmdline) if cmdline else '',
                        'user': proc.info.get('username', 'unknown')
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except ImportError:
            logger.error("psutil not available")

        return processes


if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.DEBUG)

    def on_process(info):
        print(f"Process detected: {info['name']} - {info['command_line'][:80]}")

    monitor = ProcessMonitor(
        watched_processes=['git.exe', 'gh.exe', 'python.exe', 'cmd.exe'],
        callback=on_process
    )

    print("Starting process monitor (Ctrl+C to stop)...")
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()
