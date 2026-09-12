# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec — one self-contained executable per platform.

Windows gets the .ico and a windowed (console-less) binary; on Linux the icon
option does not apply and is left out.
"""
import sys

is_windows = sys.platform == "win32"

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    # The icon travels inside the bundle: on Linux nothing else can supply one.
    datas=[('icon.ico', '.'), ('icon.png', '.')],
    hiddenimports=[
        # Imported inside functions, so keep them explicit for the analyzer.
        'vault_window',
        'settings',
        'cloud_sync',
        'gdrive',
        'sync',
        'build_config',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ZaPassKa',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'] if is_windows else None,
)
