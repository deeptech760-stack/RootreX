"""preflight.py — external prerequisites that pip cannot install.

RootreX needs one thing beyond the Python packages in requirements.txt:

  * **Npcap** — the packet driver Scapy uses to capture/send (scanner, jammer,
    observer). Its free build blocks silent install, so we open its official GUI
    installer for the operator to click through.

This module detects it (and whether we're elevated), and on explicit request
from the loopback UI downloads the *official* installer (HTTPS, npcap.com only)
and launches it. It never runs anything automatically — the operator clicks
"Download & install".

(The Test-AP uses PowerShell WinRT, so there is no `winsdk` wheel to install.)
"""
from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("rootrex.preflight")

# Official download page (always valid) and the direct installer (best-effort).
NPCAP_PAGE = "https://npcap.com/#download"
NPCAP_INSTALLER = "https://npcap.com/dist/npcap-1.90.exe"          # pinned official build

# Only this host may be fetched by the downloader.
_ALLOWED_HOSTS = ("npcap.com",)

_IS_WIN = sys.platform == "win32"


@dataclass
class Prereq:
    key: str
    name: str
    ok: bool
    required: bool          # missing-required blocks the core features
    detail: str
    page: str               # human download page (always safe to open)
    installer: str | None   # direct installer URL for the one-click downloader
    silent: bool            # can it be installed without user clicks?


def _npcap_ok() -> bool:
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    sysdir = sysroot / "System32"
    if (sysdir / "Npcap" / "wpcap.dll").exists():   # Npcap's own dir
        return True
    if (sysdir / "wpcap.dll").exists():             # WinPcap-compat shim
        return True
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    if (pf / "Npcap").is_dir():
        return True
    try:
        import winreg
        winreg.CloseKey(winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\npcap"))
        return True
    except OSError:
        return False


def _admin_ok() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def check() -> list[Prereq]:
    npcap = _npcap_ok() if _IS_WIN else False
    admin = _admin_ok() if _IS_WIN else False
    return [
        Prereq(
            "npcap", "Npcap packet driver", npcap, True,
            "Installed." if npcap else
            "Required for capture/send (scanner, jammer, observer). "
            "Install with \"WinPcap API-compatible mode\" ticked.",
            NPCAP_PAGE, NPCAP_INSTALLER, False),
        Prereq(
            "admin", "Administrator", admin, False,
            "Elevated." if admin else
            "Running as a normal user. Fine with Npcap installed; if scanning "
            "fails, right-click RootreX → Run as administrator.",
            "", None, False),
    ]


def report() -> dict:
    items = [asdict(p) for p in check()]
    missing = [p["key"] for p in items if p["required"] and not p["ok"]]
    return {"items": items, "ok": not missing, "missing_required": missing}


def _official(url: str) -> bool:
    if not url.startswith("https://"):
        return False
    host = (urlparse(url).hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in _ALLOWED_HOSTS)


def install(key: str) -> dict:
    """Download the official installer for `key` to TEMP and launch it.

    Npcap (free) blocks silent install, so its GUI installer opens for the
    operator. WebView2's bootstrapper installs silently. Only official vendor
    HTTPS hosts are fetched; on any failure we fall back to the download page.
    """
    p = {x.key: x for x in check()}.get(key)
    if not p or not p.installer:
        return {"error": f"no downloader for {key!r}"}
    if not _official(p.installer):
        return {"error": f"refusing non-official URL: {p.installer}", "page": p.page}
    dest = Path(tempfile.gettempdir()) / f"rootrex-{key}-setup.exe"
    try:
        req = urllib.request.Request(p.installer, headers={"User-Agent": "RootreX"})
        with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
            f.write(r.read())
    except Exception as exc:  # noqa: BLE001
        log.warning("installer download failed for %s: %s", key, exc)
        return {"error": f"download failed: {exc}", "page": p.page}
    try:
        if p.silent and key == "webview2":
            subprocess.Popen([str(dest), "/silent", "/install"])
            mode = "silent"
        else:
            os.startfile(str(dest))  # noqa: S606 - GUI installer the operator completes
            mode = "gui"
        log.info("launched %s installer (%s): %s", key, mode, dest)
        return {"ok": True, "key": key, "mode": mode, "url": p.installer}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"launch failed: {exc}", "page": p.page}


def open_page(key: str) -> dict:
    """Open the official download page in the system browser (not the webview)."""
    p = {x.key: x for x in check()}.get(key)
    if not p or not p.page:
        return {"error": f"no page for {key!r}"}
    try:
        os.startfile(p.page)  # noqa: S606
        return {"ok": True, "page": p.page}
    except Exception:  # noqa: BLE001
        import webbrowser
        webbrowser.open(p.page)
        return {"ok": True, "page": p.page}
