#!/usr/bin/env python3
"""
File System Monitor for Windows
Cibershield R.L. 2025

Monitors file system changes using watchdog library.
Detects creation of .git directories and sensitive files.
"""

import logging
import os
import fnmatch
import threading
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger("FileMonitor")


class FileMonitor:
    """
    Monitors file system changes using the watchdog library.

    Cross-platform compatible, uses ReadDirectoryChangesW on Windows.
    """

    def __init__(
        self,
        paths: List[str],
        patterns: List[str] = None,
        exclude_patterns: List[str] = None,
        callback: Callable[[Dict], None] = None
    ):
        """
        Initialize the file monitor.

        Args:
            paths: List of directories to monitor
            patterns: File patterns to watch (e.g., ['*.git', '.git*'])
            exclude_patterns: Patterns to exclude (e.g., ['node_modules'])
            callback: Function to call when a matching event occurs
        """
        self.paths = paths
        self.patterns = patterns or ['*.git', '.git*', '*.env', '*.pem', '*.key']
        self.exclude_patterns = exclude_patterns or ['node_modules', '.venv', '__pycache__']
        self.callback = callback
        self._observers: List = []
        self._running = False

    def start(self):
        """Start monitoring file system changes."""
        if self._running:
            return

        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler, FileSystemEvent

            # Create custom event handler
            monitor = self

            class DLPEventHandler(FileSystemEventHandler):
                def on_any_event(self, event: FileSystemEvent):
                    monitor._handle_event(event)

            handler = DLPEventHandler()

            for path in self.paths:
                expanded = os.path.expandvars(path)
                if not os.path.exists(expanded):
                    logger.warning(f"Path does not exist: {expanded}")
                    continue

                observer = Observer()
                observer.schedule(handler, expanded, recursive=True)
                observer.start()
                self._observers.append(observer)
                logger.info(f"Monitoring: {expanded}")

            self._running = True
            logger.info(f"FileMonitor started ({len(self._observers)} paths)")

        except ImportError:
            logger.error("watchdog library not installed")
            logger.info("Install with: pip install watchdog")

    def stop(self):
        """Stop monitoring."""
        self._running = False
        for observer in self._observers:
            observer.stop()
            observer.join(timeout=2)
        self._observers.clear()
        logger.info("FileMonitor stopped")

    def _handle_event(self, event):
        """
        Handle a file system event.

        Args:
            event: watchdog FileSystemEvent
        """
        try:
            path = event.src_path
            event_type = event.event_type
            is_directory = event.is_directory

            # Check exclusions first
            if self._should_exclude(path):
                return

            # Check if matches our patterns
            if not self._matches_pattern(path):
                return

            # Build event info
            info = {
                'path': path,
                'event_type': event_type,
                'is_directory': is_directory,
                'filename': os.path.basename(path),
                'directory': os.path.dirname(path)
            }

            # Determine severity
            if '.git' in path.lower():
                info['severity'] = 'warning'
                info['category'] = 'git_repository'
            elif any(s in path.lower() for s in ['.env', '.pem', '.key', 'credential']):
                info['severity'] = 'alert'
                info['category'] = 'sensitive_file'
            else:
                info['severity'] = 'info'
                info['category'] = 'file_access'

            logger.debug(f"File event: {event_type} - {path}")

            if self.callback:
                self.callback(info)

        except Exception as e:
            logger.error(f"Error handling file event: {e}")

    def _should_exclude(self, path: str) -> bool:
        """
        Check if a path should be excluded.

        Args:
            path: File path to check

        Returns:
            True if should be excluded
        """
        path_lower = path.lower()
        for pattern in self.exclude_patterns:
            if pattern.lower() in path_lower:
                return True
        return False

    def _matches_pattern(self, path: str) -> bool:
        """
        Check if a path matches any of our watch patterns.

        Args:
            path: File path to check

        Returns:
            True if matches a pattern
        """
        filename = os.path.basename(path).lower()
        path_lower = path.lower()

        for pattern in self.patterns:
            pattern_lower = pattern.lower()

            # Check filename match
            if fnmatch.fnmatch(filename, pattern_lower):
                return True

            # Check if pattern appears in path (for .git directories)
            if pattern_lower.replace('*', '') in path_lower:
                return True

        return False

    def add_path(self, path: str):
        """
        Add a new path to monitor.

        Args:
            path: Directory path to add
        """
        expanded = os.path.expandvars(path)
        if not os.path.exists(expanded):
            logger.warning(f"Path does not exist: {expanded}")
            return

        if not self._running:
            self.paths.append(path)
            return

        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            monitor = self

            class DLPEventHandler(FileSystemEventHandler):
                def on_any_event(self, event):
                    monitor._handle_event(event)

            observer = Observer()
            observer.schedule(DLPEventHandler(), expanded, recursive=True)
            observer.start()
            self._observers.append(observer)
            self.paths.append(path)
            logger.info(f"Added monitoring path: {expanded}")

        except Exception as e:
            logger.error(f"Error adding path: {e}")


class GitRepoDetector:
    """
    Specialized detector for git repository creation.
    Uses FileMonitor but with specific logic for detecting new repos.
    """

    def __init__(
        self,
        paths: List[str],
        callback: Callable[[Dict], None] = None
    ):
        """
        Initialize the git repo detector.

        Args:
            paths: Paths to monitor for new git repos
            callback: Callback when a new repo is detected
        """
        self.callback = callback
        self._known_repos: Set[str] = set()
        self._file_monitor = FileMonitor(
            paths=paths,
            patterns=['.git', '*.git'],
            callback=self._on_file_event
        )

    def start(self):
        """Start detection."""
        # Scan for existing repos first
        self._scan_existing_repos()
        # Start monitoring
        self._file_monitor.start()
        logger.info(f"GitRepoDetector started ({len(self._known_repos)} existing repos)")

    def stop(self):
        """Stop detection."""
        self._file_monitor.stop()

    def _scan_existing_repos(self):
        """Scan paths for existing git repositories."""
        for path in self._file_monitor.paths:
            expanded = os.path.expandvars(path)
            if not os.path.exists(expanded):
                continue

            for root, dirs, files in os.walk(expanded):
                if '.git' in dirs:
                    self._known_repos.add(root)
                    # Don't recurse into .git directories
                    dirs[:] = [d for d in dirs if d != '.git']

    def _on_file_event(self, info: Dict):
        """Handle file events and detect new repos."""
        path = info.get('path', '')

        # Look for .git directory creation
        if '.git' in path and info.get('event_type') == 'created':
            # Find the repo root
            if os.path.basename(path) == '.git':
                repo_root = os.path.dirname(path)
            else:
                # Find parent .git
                parts = path.split(os.sep)
                try:
                    git_idx = parts.index('.git')
                    repo_root = os.sep.join(parts[:git_idx])
                except ValueError:
                    return

            if repo_root and repo_root not in self._known_repos:
                self._known_repos.add(repo_root)

                repo_info = {
                    'repo_path': repo_root,
                    'repo_name': os.path.basename(repo_root),
                    'git_dir': os.path.join(repo_root, '.git'),
                    'event_type': 'new_repository',
                    'severity': 'warning'
                }

                logger.info(f"New git repository detected: {repo_root}")

                if self.callback:
                    self.callback(repo_info)


if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.DEBUG)
    import time

    def on_event(info):
        print(f"Event: {info['event_type']} - {info['path']}")

    monitor = FileMonitor(
        paths=[os.path.expandvars('%USERPROFILE%'), os.path.expandvars('%TEMP%')],
        callback=on_event
    )

    print("Starting file monitor (Ctrl+C to stop)...")
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()
