# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for Windows DLP Agent (ARM64)
Cibershield R.L. 2025

Build with: pyinstaller dlp_agent_arm64.spec
Note: Must be built on Windows ARM64 device or cross-compiled

Requirements for ARM64 build:
- Python ARM64 version
- PyInstaller with ARM64 support
- All dependencies compiled for ARM64
"""

import sys
import os

# Get the base directory
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

block_cipher = None

a = Analysis(
    [os.path.join(base_dir, 'dlp_agent_windows.py')],
    pathex=[base_dir],
    binaries=[],
    datas=[
        (os.path.join(base_dir, 'config.yaml'), '.'),
    ],
    hiddenimports=[
        'psutil',
        'yaml',
        'requests',
        'wmi',
        'win32com',
        'win32api',
        'win32con',
        'win32security',
        'pythoncom',
        'pywintypes',
        'watchdog',
        'watchdog.observers',
        'watchdog.events',
        'monitors',
        'monitors.process_monitor',
        'monitors.file_monitor',
        'monitors.network_monitor',
        'monitors.git_detector',
        'utils',
        'utils.system_info',
        'utils.config_loader',
        'utils.event_reporter',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='DLPAgent_ARM64',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX may not support ARM64
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch='arm64',
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version=None,
)
