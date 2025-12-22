#!/usr/bin/env python3
"""
Event Reporter
Cibershield R.L. 2025

Reports DLP events to the central console via HTTP API.
Supports batching and retry logic.
"""

import json
import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger("EventReporter")


class EventReporter:
    """
    Reports security events to the DLP console.
    Features:
    - Event batching for efficiency
    - Automatic retry on failure
    - Local queue for offline operation
    - Thread-safe operation
    """

    def __init__(
        self,
        console_url: str,
        agent_name: str,
        batch_size: int = 10,
        batch_timeout: float = 5.0,
        retry_attempts: int = 3
    ):
        """
        Initialize the event reporter.

        Args:
            console_url: Base URL of the DLP console (e.g., http://192.168.1.100:5000)
            agent_name: Name of this agent for identification
            batch_size: Number of events to batch before sending
            batch_timeout: Max seconds to wait before sending a partial batch
            retry_attempts: Number of retry attempts on failure
        """
        self.console_url = console_url.rstrip('/')
        self.agent_name = agent_name
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.retry_attempts = retry_attempts

        # Event queue (thread-safe)
        self._queue: deque = deque(maxlen=10000)  # Max 10k events in queue
        self._lock = threading.Lock()

        # Batch timer
        self._last_send_time = time.time()

        # Background sender thread
        self._running = False
        self._sender_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            'events_queued': 0,
            'events_sent': 0,
            'events_failed': 0,
            'batches_sent': 0,
            'last_error': None
        }

    def start(self):
        """Start the background sender thread."""
        if self._running:
            return

        self._running = True
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()
        logger.info(f"EventReporter started - Console: {self.console_url}")

    def stop(self):
        """Stop the background sender and flush remaining events."""
        self._running = False
        if self._sender_thread:
            self._sender_thread.join(timeout=5)

        # Try to send remaining events
        self._flush_queue()
        logger.info("EventReporter stopped")

    def report_event(self, event_type: str, data: Dict[str, Any], severity: str = "info"):
        """
        Queue an event for reporting.

        Args:
            event_type: Type of event (git_clone, network_connection, file_access, etc.)
            data: Event data dictionary
            severity: Event severity (info, warning, alert, critical)
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'agent': self.agent_name,
            'type': event_type,
            'severity': severity,
            'data': data
        }

        with self._lock:
            self._queue.append(event)
            self.stats['events_queued'] += 1

        logger.debug(f"Event queued: {event_type} ({severity})")

    def report_git_event(
        self,
        operation: str,
        repo_url: str,
        username: str = None,
        details: Dict = None
    ):
        """
        Report a git-related event.

        Args:
            operation: Git operation (clone, push, pull, fetch)
            repo_url: Repository URL
            username: Git username (if known)
            details: Additional details
        """
        data = {
            'operation': operation,
            'repo_url': repo_url,
            'username': username or 'unknown',
            **(details or {})
        }
        self.report_event('git_operation', data, severity='warning')

    def report_network_event(
        self,
        remote_ip: str,
        remote_port: int,
        process_name: str,
        direction: str = 'outbound'
    ):
        """
        Report a network connection event.

        Args:
            remote_ip: Remote IP address
            remote_port: Remote port
            process_name: Process that initiated the connection
            direction: 'inbound' or 'outbound'
        """
        data = {
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'process': process_name,
            'direction': direction
        }
        self.report_event('network_connection', data, severity='info')

    def report_file_event(
        self,
        path: str,
        action: str,
        process_name: str = None
    ):
        """
        Report a file system event.

        Args:
            path: File path
            action: Action (created, modified, deleted)
            process_name: Process that triggered the action
        """
        data = {
            'path': path,
            'action': action,
            'process': process_name or 'unknown'
        }
        self.report_event('file_access', data, severity='info')

    def _sender_loop(self):
        """Background loop that sends batched events."""
        while self._running:
            try:
                # Check if we should send
                should_send = False
                with self._lock:
                    queue_size = len(self._queue)
                    time_since_last = time.time() - self._last_send_time

                    if queue_size >= self.batch_size:
                        should_send = True
                    elif queue_size > 0 and time_since_last >= self.batch_timeout:
                        should_send = True

                if should_send:
                    self._flush_queue()

                # Sleep briefly
                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Error in sender loop: {e}")
                time.sleep(1)

    def _flush_queue(self):
        """Send all queued events to the console."""
        events_to_send: List[Dict] = []

        with self._lock:
            while self._queue and len(events_to_send) < self.batch_size * 2:
                events_to_send.append(self._queue.popleft())
            self._last_send_time = time.time()

        if not events_to_send:
            return

        # Try to send
        success = self._send_batch(events_to_send)

        if success:
            with self._lock:
                self.stats['events_sent'] += len(events_to_send)
                self.stats['batches_sent'] += 1
        else:
            # Put events back in queue (at the front)
            with self._lock:
                for event in reversed(events_to_send):
                    self._queue.appendleft(event)
                self.stats['events_failed'] += len(events_to_send)

    def _send_batch(self, events: List[Dict]) -> bool:
        """
        Send a batch of events to the console.

        Args:
            events: List of event dictionaries

        Returns:
            True if successful, False otherwise
        """
        try:
            import requests

            url = f"{self.console_url}/api/events"
            payload = {
                'agent': self.agent_name,
                'events': events,
                'batch_time': datetime.now().isoformat()
            }

            for attempt in range(self.retry_attempts):
                try:
                    response = requests.post(
                        url,
                        json=payload,
                        timeout=10,
                        headers={'Content-Type': 'application/json'}
                    )

                    if response.status_code in (200, 201, 202):
                        logger.debug(f"Sent {len(events)} events successfully")
                        return True
                    else:
                        logger.warning(f"Console returned {response.status_code}: {response.text}")

                except requests.exceptions.Timeout:
                    logger.warning(f"Timeout sending events (attempt {attempt + 1})")
                except requests.exceptions.ConnectionError:
                    logger.warning(f"Connection error (attempt {attempt + 1})")

                if attempt < self.retry_attempts - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff

            self.stats['last_error'] = 'Failed after all retries'
            return False

        except ImportError:
            logger.error("requests library not installed")
            self.stats['last_error'] = 'requests not installed'
            return False
        except Exception as e:
            logger.error(f"Error sending events: {e}")
            self.stats['last_error'] = str(e)
            return False

    def get_stats(self) -> Dict:
        """Get reporter statistics."""
        with self._lock:
            return {
                **self.stats,
                'queue_size': len(self._queue)
            }


# Global reporter instance
_reporter: Optional[EventReporter] = None


def get_reporter() -> Optional[EventReporter]:
    """Get the global reporter instance."""
    return _reporter


def init_reporter(
    console_url: str,
    agent_name: str,
    **kwargs
) -> EventReporter:
    """
    Initialize and start the global reporter.

    Args:
        console_url: Console URL
        agent_name: Agent name
        **kwargs: Additional EventReporter arguments

    Returns:
        EventReporter instance
    """
    global _reporter
    _reporter = EventReporter(console_url, agent_name, **kwargs)
    _reporter.start()
    return _reporter


if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.DEBUG)

    reporter = EventReporter("http://localhost:5000", "TEST-AGENT")
    reporter.start()

    reporter.report_git_event("clone", "https://github.com/test/repo.git", "testuser")
    reporter.report_network_event("140.82.121.4", 443, "git.exe")
    reporter.report_file_event("C:\\Users\\test\\.git", "created")

    time.sleep(6)  # Wait for batch timeout
    print("Stats:", reporter.get_stats())
    reporter.stop()
