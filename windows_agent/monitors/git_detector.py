#!/usr/bin/env python3
"""
Git Command Detector
Cibershield R.L. 2025

Detects and analyzes git commands and operations.
Extracts repository URLs, usernames, and operation types.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("GitDetector")


class GitDetector:
    """
    Analyzes command lines and process information to detect git operations.
    Extracts repository URLs, organization, and operation details.
    """

    # Git executable names
    GIT_EXECUTABLES = {
        'git.exe', 'git', 'git-remote-https.exe', 'git-remote-https',
        'gh.exe', 'gh', 'git-lfs.exe', 'git-lfs'
    }

    # Git operations that involve network
    NETWORK_OPERATIONS = {
        'clone', 'push', 'pull', 'fetch', 'remote',
        'ls-remote', 'archive', 'submodule'
    }

    # GitHub domains
    GITHUB_DOMAINS = {
        'github.com', 'api.github.com', 'raw.githubusercontent.com',
        'gist.github.com', 'codeload.github.com'
    }

    # URL patterns for git repositories
    URL_PATTERNS = [
        # HTTPS: https://github.com/owner/repo.git
        r'https?://([^/]+)/([^/]+)/([^/\s]+?)(?:\.git)?(?:\s|$)',
        # SSH: git@github.com:owner/repo.git
        r'git@([^:]+):([^/]+)/([^/\s]+?)(?:\.git)?(?:\s|$)',
        # SSH with ssh://: ssh://git@github.com/owner/repo.git
        r'ssh://(?:[^@]+@)?([^/]+)/([^/]+)/([^/\s]+?)(?:\.git)?(?:\s|$)',
    ]

    def __init__(self):
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.URL_PATTERNS]

    def is_git_process(self, process_name: str) -> bool:
        """
        Check if a process name is a git-related executable.

        Args:
            process_name: Process executable name

        Returns:
            True if it's a git process
        """
        name_lower = process_name.lower()
        return name_lower in self.GIT_EXECUTABLES or name_lower.startswith('git')

    def parse_command_line(self, cmdline: str) -> Optional[Dict]:
        """
        Parse a git command line and extract operation details.

        Args:
            cmdline: Full command line string

        Returns:
            Dict with operation, repo_url, org, repo_name, or None
        """
        if not cmdline:
            return None

        # Split command line
        parts = cmdline.split()
        if not parts:
            return None

        result = {
            'raw_command': cmdline,
            'operation': None,
            'repo_url': None,
            'host': None,
            'organization': None,
            'repo_name': None,
            'branch': None,
            'is_network_operation': False
        }

        # Find the git operation
        for i, part in enumerate(parts):
            part_lower = part.lower()

            # Skip the executable name
            if self.is_git_process(part):
                continue

            # Skip flags
            if part.startswith('-'):
                continue

            # This should be the git command
            if part_lower in self.NETWORK_OPERATIONS:
                result['operation'] = part_lower
                result['is_network_operation'] = True
                break
            elif part_lower in ('add', 'commit', 'status', 'log', 'diff', 'branch', 'checkout', 'merge', 'rebase'):
                result['operation'] = part_lower
                break

        # Extract repository URL from command line
        url_info = self._extract_url(cmdline)
        if url_info:
            result.update(url_info)

        # Extract branch if present
        branch = self._extract_branch(cmdline)
        if branch:
            result['branch'] = branch

        return result if result['operation'] else None

    def _extract_url(self, text: str) -> Optional[Dict]:
        """
        Extract repository URL and parse org/repo from text.

        Args:
            text: Text containing a git URL

        Returns:
            Dict with url info or None
        """
        for pattern in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                host, org, repo = match.groups()
                # Clean up repo name (remove .git suffix if present)
                repo = repo.rstrip('.git') if repo.endswith('.git') else repo

                # Reconstruct full URL
                full_url = match.group(0).strip()

                return {
                    'repo_url': full_url,
                    'host': host,
                    'organization': org,
                    'repo_name': repo,
                    'is_github': host.lower() in self.GITHUB_DOMAINS
                }

        return None

    def _extract_branch(self, cmdline: str) -> Optional[str]:
        """
        Extract branch name from git command.

        Args:
            cmdline: Command line string

        Returns:
            Branch name or None
        """
        # Pattern for -b branch or --branch=branch
        branch_patterns = [
            r'-b\s+([^\s]+)',
            r'--branch[=\s]+([^\s]+)',
        ]

        for pattern in branch_patterns:
            match = re.search(pattern, cmdline)
            if match:
                return match.group(1)

        return None

    def analyze_process(
        self,
        process_name: str,
        cmdline: str,
        pid: int = None,
        parent_name: str = None
    ) -> Optional[Dict]:
        """
        Analyze a process to detect git operations.

        Args:
            process_name: Process executable name
            cmdline: Full command line
            pid: Process ID
            parent_name: Parent process name

        Returns:
            Dict with analysis results or None
        """
        if not self.is_git_process(process_name):
            return None

        result = self.parse_command_line(cmdline)
        if not result:
            return None

        result['process'] = {
            'name': process_name,
            'pid': pid,
            'parent': parent_name
        }

        # Determine severity based on operation
        if result.get('is_network_operation'):
            if result['operation'] in ('clone', 'push'):
                result['severity'] = 'warning'
            else:
                result['severity'] = 'info'
        else:
            result['severity'] = 'debug'

        return result

    def is_github_connection(self, remote_ip: str, remote_port: int = None) -> bool:
        """
        Check if an IP address belongs to GitHub.

        Args:
            remote_ip: IP address to check
            remote_port: Port (optional, typically 443 or 22)

        Returns:
            True if it's a GitHub IP
        """
        # GitHub IP ranges (as of 2024)
        # https://api.github.com/meta
        github_ranges = [
            ('140.82.112.0', '140.82.127.255'),
            ('192.30.252.0', '192.30.255.255'),
            ('185.199.108.0', '185.199.111.255'),
            ('143.55.64.0', '143.55.79.255'),
        ]

        try:
            ip_parts = [int(p) for p in remote_ip.split('.')]
            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]

            for start, end in github_ranges:
                start_parts = [int(p) for p in start.split('.')]
                end_parts = [int(p) for p in end.split('.')]
                start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
                end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]

                if start_int <= ip_int <= end_int:
                    return True

        except (ValueError, IndexError):
            pass

        return False


# Singleton instance
_detector: Optional[GitDetector] = None


def get_git_detector() -> GitDetector:
    """Get the singleton GitDetector instance."""
    global _detector
    if _detector is None:
        _detector = GitDetector()
    return _detector


if __name__ == "__main__":
    # Test
    detector = GitDetector()

    test_commands = [
        "git clone https://github.com/anthropics/claude-code.git",
        "git push origin main",
        "git pull",
        "git clone git@github.com:owner/private-repo.git",
        "git fetch --all",
        "gh repo clone owner/repo",
        "git clone -b develop https://github.com/org/repo.git",
    ]

    for cmd in test_commands:
        result = detector.parse_command_line(cmd)
        print(f"\nCommand: {cmd}")
        print(f"Result: {result}")

    # Test IP detection
    print("\n--- IP Detection ---")
    print(f"140.82.121.4 is GitHub: {detector.is_github_connection('140.82.121.4')}")
    print(f"8.8.8.8 is GitHub: {detector.is_github_connection('8.8.8.8')}")
