# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['run_safir.py'],
    pathex=[],
    binaries=[],
    datas=[('safir_guard\\ui\\templates', 'safir_guard\\ui\\templates'), ('safir_guard\\ui\\static', 'safir_guard\\ui\\static'), ('safir_guard\\engine\\signature_db.json', 'safir_guard\\engine'), ('quarantine_vault', 'quarantine_vault')],
    hiddenimports=[],
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
    name='SafirGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
