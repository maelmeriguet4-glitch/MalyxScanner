# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('src/i18n', 'src/i18n'), ('rules', 'rules'), ('assets', 'assets')]
binaries = []
hiddenimports = [
    'gui',
    'gui.app',
    'gui.settings_dialog',
    'gui.result_view',
    'gui.theme_manager',
    'core',
    'core.analyzer',
    'core.ai_analyst',
    'core.hashes',
    'core.entropy',
    'core.filetype',
    'core.pe_analysis',
    'core.threat_classifier',
    'core.strings_extractor',
    'core.yara_scanner',
    'core.virustotal',
    'core.report',
    'core.risk_score',
    'i18n',
    'i18n.translator',
    'app_config',
]

for pkg in ('tkinterdnd2', 'puremagic', 'customtkinter', 'requests', 'truststore'):
    tmp_ret = collect_all(pkg)
    datas += tmp_ret[0]
    binaries += tmp_ret[1]
    hiddenimports += tmp_ret[2]


a = Analysis(
    ['src/main.py'],
    pathex=['src'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name='MalyxScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon='assets/icon.ico',
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='MalyxScanner',
)
