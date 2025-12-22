# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for Windows DLP Agent (x86-64)
Cibershield R.L. 2025

Build with: pyinstaller dlp_agent_x64.spec
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
    name='DLPAgent_x64',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch='x86_64',
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon path here if available
    version=None,  # Add version info file here if available
)

# Version info for Windows
# Create a version file if needed:
# version_info = '''
# VSVersionInfo(
#   ffi=FixedFileInfo(
#     filevers=(1, 0, 0, 0),
#     prodvers=(1, 0, 0, 0),
#     ...
#   ),
#   ...
# )
# '''
