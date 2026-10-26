# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for RootreX. Build:  pyinstaller --noconfirm rootrex.spec
# Produces dist/RootreX/RootreX.exe (onedir). The installer packages that folder.

from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [("ui/dist", "ui/dist"), ("assets/rootrex.ico", "assets")]  # UI + icon
binaries = []
hiddenimports = collect_submodules("uvicorn") + ["engine.api"]

# scapy ships data files and many lazily-imported layers; mac_vendor_lookup ships
# its OUI database — pull them in fully so the frozen app works offline.
for pkg in ("scapy", "mac_vendor_lookup"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# system-tray backend + icon image are imported lazily
hiddenimports += collect_submodules("pystray") + ["PIL.Image"]

a = Analysis(
    ["run.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RootreX",
    debug=False,
    strip=False,
    upx=False,
    console=False,          # windowed app (opens the UI in the browser)
    icon="assets/rootrex.ico",
    # No admin manifest: Npcap grants packet access to the normal user, so the app
    # launches without UAC. If a user's Npcap is admin-only, they can right-click
    # → Run as administrator; the UI surfaces capture/permission errors either way.
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="RootreX",
)
