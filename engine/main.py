"""main.py — elevate, serve the loopback API, open the UI in the browser.

Why the browser + tray, not an embedded window: RootreX must run elevated
(raw sockets / ARP), and the Edge WebView2 control does not render reliably
inside an elevated process. So we serve the loopback UI and open it in the
user's normal browser (which renders fine), and keep RootreX in the system tray
with a clean Quit that restores all ARP state. safety.py still restores on exit,
crash, and signal as a final guarantee.

Flow:
  1. Ensure Administrator (raw sockets / ARP); re-launch via UAC if not.
  2. Start uvicorn on 127.0.0.1:<free port> in a daemon thread.
  3. Open the default browser at that URL; sit in the tray until Quit.
"""
from __future__ import annotations

import ctypes
import logging
import os
import socket
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)
HOST = "127.0.0.1"
ROOT = Path(__file__).resolve().parent.parent
MB_ICONERROR = 0x10

# A windowed PyInstaller build has no console, so sys.stdout/stderr are None —
# which crashes anything that calls sys.stdout.isatty() (e.g. uvicorn's log
# formatter) before the server can even start. Give them a real sink.
for _name in ("stdout", "stderr"):
    if getattr(sys, _name, None) is None:
        try:
            setattr(sys, _name, open(os.devnull, "w", encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass


def _log_dir() -> Path:
    """First writable RootreX dir among LOCALAPPDATA / APPDATA / home / TEMP."""
    for base in (os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA"),
                 str(Path.home()), os.environ.get("TEMP")):
        if not base:
            continue
        d = Path(base) / "RootreX"
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".wtest"
            probe.write_text("x", encoding="utf-8")
            probe.unlink()
            return d
        except Exception:  # noqa: BLE001
            continue
    return Path(os.environ.get("TEMP", "."))


def _setup_logging() -> Path:
    d = _log_dir()
    handlers: list[logging.Handler] = []
    try:
        handlers.append(logging.FileHandler(d / "rootrex.log", encoding="utf-8"))
    except Exception:  # noqa: BLE001
        pass
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.INFO, handlers=handlers or None,
        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    return d


LOGDIR = _setup_logging()
log = logging.getLogger("rootrex.main")


def _msgbox(text: str, title: str = "RootreX") -> None:
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, MB_ICONERROR)
    except Exception:  # noqa: BLE001
        pass


def _excepthook(exc_type, exc, tb) -> None:
    log.critical("UNCAUGHT:\n%s", "".join(traceback.format_exception(exc_type, exc, tb)))
    _msgbox(f"RootreX hit an unexpected error:\n\n{exc_type.__name__}: {exc}\n\n"
            f"Details were written to:\n{LOGDIR / 'rootrex.log'}")


sys.excepthook = _excepthook


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _relaunch_as_admin() -> None:
    """Re-run elevated via UAC, then exit the unelevated process."""
    log.info("requesting elevation...")
    if FROZEN:
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:])
        workdir = str(Path(sys.executable).resolve().parent)
    else:
        exe = sys.executable
        params = f'"{ROOT / "run.py"}" ' + " ".join(f'"{a}"' for a in sys.argv[1:])
        workdir = str(ROOT)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
    if rc <= 32:
        _msgbox("RootreX needs Administrator for ARP / raw sockets, but elevation "
                "was declined. Right-click RootreX and choose \"Run as administrator\".")
    sys.exit(0)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_until_up(port: int, timeout: float = 45.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _serve(port: int) -> None:
    try:
        import uvicorn
        from engine.api import app
        uvicorn.Server(uvicorn.Config(
            app, host=HOST, port=port, log_level="warning",
            log_config=None)).run()   # skip uvicorn's own log setup (isatty on None stdout)
    except Exception:  # noqa: BLE001
        log.exception("uvicorn server crashed")


def _icon_path() -> Path | None:
    base = Path(getattr(sys, "_MEIPASS", ROOT))
    for p in (base / "assets" / "rootrex.ico", ROOT / "assets" / "rootrex.ico"):
        if p.exists():
            return p
    return None


def _tray_image():
    from PIL import Image
    p = _icon_path()
    if p:
        try:
            return Image.open(p)
        except Exception:  # noqa: BLE001
            pass
    img = Image.new("RGBA", (64, 64), (10, 5, 14, 255))
    return img


def _run_tray(url: str) -> None:
    """Hold the process in the system tray until Quit; restore ARP on the way out."""
    try:
        import pystray
        icon = pystray.Icon(
            "RootreX", _tray_image(), "RootreX — WiFi Visibility & Control",
            menu=pystray.Menu(
                pystray.MenuItem("Open RootreX", lambda i, it: webbrowser.open(url), default=True),
                pystray.MenuItem("Quit", lambda i, it: i.stop())))
        log.info("tray running; UI at %s", url)
        icon.run()  # blocks until Quit
    except Exception as exc:  # noqa: BLE001
        log.warning("system tray unavailable (%s); holding process open", exc)
        _msgbox(f"RootreX is running.\n\nOpen the UI at:\n{url}\n\n"
                "Close this dialog, then end RootreX from Task Manager when done.",
                "RootreX is running")
    finally:
        try:
            from engine.safety import safety
            safety.restore_all(reason="app.quit")
        except Exception:  # noqa: BLE001
            pass


def main() -> None:
    if sys.platform != "win32":
        print("RootreX targets Windows (Npcap + Mobile Hotspot).")
    # Do NOT force elevation. With Npcap installed, the engine works as the normal
    # user (exactly like the dev server). Forcing admin prompts UAC on every launch
    # and, on standard-user machines, elevates into a *different* admin profile
    # (wrong AppData, failed startup). If a capture later needs privileges, the UI
    # surfaces that — the user can then right-click → Run as administrator.
    if not _is_admin():
        log.info("running unprivileged — relying on Npcap access")

    try:
        from engine.net import prime_vendors
        prime_vendors()
    except Exception:  # noqa: BLE001
        pass

    port = _free_port()
    threading.Thread(target=_serve, args=(port,), daemon=True).start()
    if not _wait_until_up(port):
        log.error("API failed to start")
        _msgbox("RootreX's control service failed to start.\n\nMake sure Npcap "
                "≥ 1.3.0 is installed (the app offers a one-click download). If "
                "scanning fails, try right-click → Run as administrator.\n\n"
                f"See {LOGDIR / 'rootrex.log'}")
        sys.exit(1)

    url = f"http://{HOST}:{port}/"
    log.info("UI at %s", url)
    webbrowser.open(url)
    _run_tray(url)


if __name__ == "__main__":
    main()
