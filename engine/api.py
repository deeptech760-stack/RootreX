"""api.py — loopback-only control plane (FastAPI + WebSocket).

Binds 127.0.0.1 only (see main.py). The UI talks to this; every state-changing
route goes through the engine objects, which go through safety.py. Nothing here
bypasses the consent gate or the allowlist.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import net, preflight
from .ap import TestAP
from .jammer import Jammer
from .observer import Observer
from .safety import ConsentError, safety
from .scanner import Scanner

log = logging.getLogger("rootrex.api")


def _resource_base() -> Path:
    """Where bundled resources live — the PyInstaller unpack dir when frozen,
    the repo root otherwise."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent.parent


UI_DIST = _resource_base() / "ui" / "dist"


class AppState:
    """Holds the live engine. Built at startup; degrades gracefully on error."""

    def __init__(self) -> None:
        self.ctx: Optional[net.NetContext] = None
        self.scanner: Optional[Scanner] = None
        self.jammer: Optional[Jammer] = None
        self.observer: Optional[Observer] = None
        self.ap = TestAP()
        self.error: str = ""
        self.preflight: dict = preflight.report()
        self._scan_task: Optional[asyncio.Task] = None
        self.clients: set[WebSocket] = set()

    def init_engine(self) -> None:
        self.preflight = preflight.report()
        if not self.preflight["ok"]:
            log.warning("missing prerequisites: %s",
                        ", ".join(self.preflight["missing_required"]))
        try:
            self.ctx = net.discover()
            self.scanner = Scanner(self.ctx)
            self.jammer = Jammer(self.ctx, safety)
            self.observer = Observer(self.ctx)
            log.info("engine ready on %s", self.ctx.iface)
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
            log.exception("engine init failed (Npcap installed? elevated?)")

    async def refresh_network(self) -> None:
        """Detect a router change and re-home to it: stop jamming on the old net,
        clear its device list, switch to the new router's remembered devices."""
        if self.ctx is None or self.scanner is None:
            return
        try:
            new = net.discover()
        except Exception:  # noqa: BLE001
            return
        same = (
            new.gateway_ip == self.ctx.gateway_ip
            and new.cidr == self.ctx.cidr
            and (not self.ctx.gateway_mac or not new.gateway_mac
                 or new.gateway_mac == self.ctx.gateway_mac)
        )
        if same:
            if new.gateway_mac and self.ctx.gateway_mac != new.gateway_mac:
                self.ctx.gateway_mac = new.gateway_mac
                self.scanner.update_network_key()
            return
        log.info("network changed: %s -> %s",
                 net.network_id(self.ctx), net.network_id(new))
        if self.jammer:
            await self.jammer.stop_all()
        if self.observer:
            self.observer.stop()
            self.observer.clear()
        self.ctx = new
        self.scanner.reset(new)
        if self.jammer:
            self.jammer.ctx = new
        if self.observer:
            self.observer.ctx = new

    def snapshot(self) -> dict:
        active = self.jammer.active if self.jammer else {}
        if self.scanner:
            for dev in self.scanner.devices:
                dev.status = {"cut": "cut", "route": "routed"}.get(
                    active.get(dev.mac, ""), "live")
        return {
            "ok": self.ctx is not None,
            "error": self.error,
            "context": self.ctx.as_dict() if self.ctx else None,
            "consent": safety.has_consent,
            "allowlist": [t.__dict__ for t in safety.allowlist],
            "devices": [d.as_dict() for d in (self.scanner.devices if self.scanner else [])],
            "jamming": active,
            "observer": self.observer.snapshot() if self.observer else [],
            "ap": self.ap.status().as_dict(),
            "preflight": self.preflight,
            "log": safety.session_log[-50:],
        }


state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.init_engine()
    if state.scanner:
        state._scan_task = asyncio.create_task(_scan_loop())
    asyncio.create_task(_broadcast_loop())
    yield
    # Shutdown: restore everything, stop capture.
    try:
        if state.jammer:
            await state.jammer.stop_all()
        if state.observer:
            state.observer.stop()
    finally:
        safety.restore_all(reason="api.shutdown")


app = FastAPI(title="RootreX", lifespan=lifespan)


async def _scan_loop() -> None:
    assert state.scanner
    tick = 0
    while True:
        try:
            if tick % 3 == 0:                 # ~every 15s, check for a router change
                await state.refresh_network()
            if state.ap.status().state == "on" or tick % 6 == 0:
                await state.ap.refresh()      # client count while AP is on
            await state.scanner.sweep()
        except Exception:  # noqa: BLE001
            pass
        tick += 1
        await asyncio.sleep(5.0)


async def _broadcast_loop() -> None:
    while True:
        await asyncio.sleep(0.8)
        if not state.clients:
            continue
        snap = state.snapshot()
        dead = []
        for ws in list(state.clients):
            try:
                await ws.send_json(snap)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            state.clients.discard(ws)


# ------------------------------------------------------------------ models
class ConsentBody(BaseModel):
    note: str = ""


class PreflightBody(BaseModel):
    key: str


class Target(BaseModel):
    ip: str
    mac: str


class JamBody(BaseModel):
    ip: str
    mac: str
    mode: str  # "cut" | "route"


class APConfig(BaseModel):
    ssid: str
    passphrase: str


# ------------------------------------------------------------------ routes
@app.get("/api/state")
async def get_state() -> dict:
    return state.snapshot()


@app.get("/api/preflight")
async def preflight_check() -> dict:
    """Re-run the prerequisite checks (Npcap / admin)."""
    state.preflight = preflight.report()
    return state.preflight


@app.post("/api/preflight/install")
async def preflight_install(body: PreflightBody) -> dict:
    """Download the official installer for a missing prerequisite and launch it.
    HTTPS + official vendor hosts only; the operator completes the installer."""
    res = await asyncio.to_thread(preflight.install, body.key)
    state.preflight = preflight.report()
    return res


@app.post("/api/preflight/open")
async def preflight_open(body: PreflightBody) -> dict:
    """Open a prerequisite's official download page in the system browser."""
    return await asyncio.to_thread(preflight.open_page, body.key)


@app.post("/api/consent")
async def grant_consent(body: ConsentBody) -> dict:
    safety.grant_consent(body.note)
    return {"consent": True}


@app.post("/api/consent/revoke")
async def revoke_consent() -> dict:
    if state.jammer:
        await state.jammer.stop_all()
    if state.observer:
        state.observer.stop()
    safety.revoke_consent()
    return {"consent": False}


@app.post("/api/scan")
async def scan() -> dict:
    if not state.scanner:
        return {"error": state.error or "no engine"}
    try:
        await state.scanner.sweep()
    except Exception as exc:  # noqa: BLE001 - surface the real cause, don't 500
        return {"error": f"scan failed: {exc}"}
    return {"devices": [d.as_dict() for d in state.scanner.devices]}


@app.post("/api/identify")
async def identify_devices(seconds: int = 25) -> dict:
    """One-shot name discovery — SSDP/UPnP probe + passive DHCP listen. No MITM,
    no routing: nothing flows through this host. Merges names into the device
    table. Toggle a device's WiFi during the window to catch its DHCP hostname."""
    if not (state.ctx and state.scanner):
        return {"error": state.error or "no engine"}
    ctx = state.ctx
    window = max(5, min(60, seconds))

    def work():
        from engine import identify as idf
        ssdp = idf.ssdp_discover(ctx.local_ip, timeout=4.0)
        dhcp = idf.dhcp_passive(ctx.iface, duration=window)
        return ssdp, dhcp

    ssdp, dhcp = await asyncio.to_thread(work)
    devices = state.scanner.devices
    by_ip = {d.ip: d for d in devices}
    by_mac = {d.mac: d for d in devices}
    named = 0
    for ip, name in ssdp.items():
        dev = by_ip.get(ip)
        if dev and name and (not dev.name or dev.kind == "gateway"):
            dev.name = name
            state.scanner.remember(dev.mac, name)   # persist to device memory
            named += 1
    for mac, info in dhcp.items():
        dev = by_mac.get(mac.lower())
        nm = info.get("name") or info.get("vendor_class")
        if dev and nm and not dev.name:
            dev.name = nm
            state.scanner.remember(dev.mac, nm)
            named += 1
    return {"ok": True, "ssdp": len(ssdp), "dhcp": len(dhcp), "named": named}


@app.post("/api/allow")
async def allow(body: Target) -> dict:
    try:
        t = safety.allow(body.ip, body.mac)
    except ConsentError as exc:
        return {"error": str(exc)}
    return {"allowed": t.__dict__}


@app.delete("/api/allow/{mac}")
async def disallow(mac: str) -> dict:
    if state.jammer:
        await state.jammer.stop(mac)
    safety.disallow(mac)
    return {"removed": mac}


@app.post("/api/jam")
async def jam(body: JamBody) -> dict:
    if not (state.jammer and state.observer):
        return {"error": state.error or "no engine"}
    try:
        if body.mode == "cut":
            await state.jammer.cut(body.ip, body.mac)
            state.observer.remove_target(body.ip)
        elif body.mode == "route":
            await state.jammer.route(body.ip, body.mac)
            state.observer.set_observe_all(False)
            state.observer.add_target(body.ip, body.mac)
            state.observer.start()
        else:
            return {"error": f"unknown mode {body.mode!r}"}
    except (ConsentError, RuntimeError) as exc:
        return {"error": str(exc)}
    return {"ok": True, "mode": body.mode}


@app.post("/api/unjam")
async def unjam(body: Target) -> dict:
    if state.jammer:
        await state.jammer.stop(body.mac)
    if state.observer:
        state.observer.remove_target(body.ip)
    return {"ok": True}


@app.post("/api/stop_all")
async def stop_all() -> dict:
    """The big red STOP · RESTORE ALL."""
    if state.jammer:
        await state.jammer.stop_all()
    if state.observer:
        state.observer.stop()
        state.observer.clear()
    safety.restore_all(reason="ui.stop_all")
    return {"ok": True}


@app.post("/api/observer/clear")
async def observer_clear() -> dict:
    """Clear the captured destination log, leaving any active routing in place."""
    if state.observer:
        state.observer.clear()
    return {"ok": True}


@app.post("/api/ap/configure")
async def ap_configure(body: APConfig) -> dict:
    try:
        return (await state.ap.configure(body.ssid, body.passphrase)).as_dict()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


@app.post("/api/ap/start")
async def ap_start() -> dict:
    try:
        st = (await state.ap.start()).as_dict()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    # Observe the hotspot natively (no spoofing): we are the gateway. Capture on
    # the hotspot's virtual adapter and record every private client that joins.
    if state.observer and st.get("state") == "on":
        state.observer.stop()
        hs = state.ap.hotspot_iface()
        if hs:
            state.observer.set_iface(hs)
        state.observer.set_observe_all(True)
        state.observer.clear()
        state.observer.start()
    return st


@app.post("/api/ap/stop")
async def ap_stop() -> dict:
    try:
        st = (await state.ap.stop()).as_dict()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    if state.observer:
        state.observer.stop()
        state.observer.set_observe_all(False)
        state.observer.set_iface(None)   # back to the main interface
        state.observer.clear()
    return st


@app.websocket("/api/ws")
async def ws(websocket: WebSocket) -> None:
    await websocket.accept()
    state.clients.add(websocket)
    try:
        await websocket.send_json(state.snapshot())
        while True:
            await websocket.receive_text()  # keepalive; UI drives via REST
    except WebSocketDisconnect:
        pass
    finally:
        state.clients.discard(websocket)


# Serve the built UI last so it doesn't shadow /api/*.
if UI_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(UI_DIST), html=True), name="ui")
