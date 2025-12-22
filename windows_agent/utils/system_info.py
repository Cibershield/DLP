#!/usr/bin/env python3
"""
System Information Utility
Cibershield R.L. 2025

Detects Windows architecture (ARM64/x64), system info, and environment.
"""

import os
import platform
import socket
import struct
import logging
from typing import Dict, Optional

logger = logging.getLogger("SystemInfo")


class SystemInfo:
    """
    Utility class to detect system information on Windows.
    Supports ARM64 and x86-64 architectures.
    """

    def __init__(self):
        self._cache: Dict[str, any] = {}

    @staticmethod
    def get_architecture() -> str:
        """
        Detect the CPU architecture.

        Returns:
            'ARM64' for ARM-based Windows (Snapdragon, Apple Silicon VM, etc.)
            'x64' for 64-bit Intel/AMD
            'x86' for 32-bit (legacy)
        """
        machine = platform.machine().lower()

        if machine in ('aarch64', 'arm64'):
            return 'ARM64'
        elif machine in ('amd64', 'x86_64'):
            return 'x64'
        elif machine in ('i386', 'i686', 'x86'):
            return 'x86'
        else:
            # Fallback: check pointer size
            return 'x64' if struct.calcsize('P') * 8 == 64 else 'x86'

    @staticmethod
    def get_windows_version() -> Dict[str, str]:
        """
        Get Windows version information.

        Returns:
            Dict with version, build, edition
        """
        version_info = {
            'version': platform.version(),
            'release': platform.release(),
            'build': '',
            'edition': ''
        }

        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                try:
                    version_info['build'] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                except FileNotFoundError:
                    pass
                try:
                    version_info['edition'] = winreg.QueryValueEx(key, "EditionID")[0]
                except FileNotFoundError:
                    pass
        except Exception as e:
            logger.debug(f"Could not read registry: {e}")

        return version_info

    @staticmethod
    def get_hostname() -> str:
        """Get the machine hostname."""
        return socket.gethostname()

    @staticmethod
    def get_username() -> str:
        """Get the current username."""
        return os.getenv('USERNAME', os.getenv('USER', 'unknown'))

    @staticmethod
    def get_domain() -> Optional[str]:
        """Get the Windows domain if joined."""
        return os.getenv('USERDOMAIN', None)

    @staticmethod
    def expand_path(path: str) -> str:
        """
        Expand environment variables in a path.

        Args:
            path: Path with %VAR% style variables

        Returns:
            Expanded path
        """
        return os.path.expandvars(path)

    @staticmethod
    def get_program_data() -> str:
        """Get ProgramData directory."""
        return os.getenv('PROGRAMDATA', 'C:\\ProgramData')

    @staticmethod
    def get_app_data() -> str:
        """Get AppData directory."""
        return os.getenv('APPDATA', os.path.join(os.getenv('USERPROFILE', ''), 'AppData', 'Roaming'))

    @staticmethod
    def is_admin() -> bool:
        """Check if running with administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def get_network_interfaces() -> Dict[str, Dict]:
        """
        Get network interface information.

        Returns:
            Dict of interface name -> {ip, mac, status}
        """
        interfaces = {}
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                interfaces[name] = {
                    'ipv4': None,
                    'ipv6': None,
                    'mac': None
                }
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces[name]['ipv4'] = addr.address
                    elif addr.family == socket.AF_INET6:
                        interfaces[name]['ipv6'] = addr.address
                    elif addr.family == psutil.AF_LINK:
                        interfaces[name]['mac'] = addr.address
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")

        return interfaces

    def get_system_summary(self) -> Dict:
        """
        Get a complete system summary.

        Returns:
            Dict with all system information
        """
        return {
            'hostname': self.get_hostname(),
            'username': self.get_username(),
            'domain': self.get_domain(),
            'architecture': self.get_architecture(),
            'windows': self.get_windows_version(),
            'is_admin': self.is_admin(),
            'platform': {
                'system': platform.system(),
                'node': platform.node(),
                'processor': platform.processor()
            }
        }


# Singleton instance
_system_info: Optional[SystemInfo] = None


def get_system_info() -> SystemInfo:
    """Get the singleton SystemInfo instance."""
    global _system_info
    if _system_info is None:
        _system_info = SystemInfo()
    return _system_info


if __name__ == "__main__":
    # Test
    import json
    info = SystemInfo()
    print(json.dumps(info.get_system_summary(), indent=2))
