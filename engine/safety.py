"""safety.py — the load-bearing safety core.

Every state-changing action in RootreX passes through here. It enforces the
invariants from AGENTS.md:

  * Nothing that alters another device is allowed before session consent.
  * A device can only be targeted if it is on the explicit allowlist.
  * Every ARP change is tracked and restored on exit / crash / signal / STOP.

This module never sends packets itself. The jammer registers a *restore
callback* (`set_restore_fn`) that knows how to put a correct ARP mapping back
on the wire; SafetyManager decides *when* that must happen and guarantees it
runs even on an unclean shutdown.
"""
from __future__ import annotations

import atexit
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

log = logging.getLogger("rootrex.safety")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Target:
    """A device the operator has explicitly authorized as a target."""
    ip: str
    mac: str
    added_at: str = field(default_factory=_now)


@dataclass
class PoisonRecord:
    """A live ARP manipulation that MUST be undone before we exit."""
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str
    mode: str  # "cut" | "route"
    started_at: str = field(default_factory=_now)


# A restore function takes a PoisonRecord and puts the correct ARP truth back
# (tell the target the real gateway MAC, tell the gateway the real target MAC).
RestoreFn = Callable[[PoisonRecord], None]


class ConsentError(RuntimeError):
    """Raised when a guarded action is attempted without consent/allowlisting."""


class SafetyManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._consent = False
        self._consent_note = ""
        self._consent_at: Optional[str] = None
        self._allow: dict[str, Target] = {}          # mac -> Target
        self._poisons: dict[str, PoisonRecord] = {}   # target_mac -> record
        self._restore_fn: Optional[RestoreFn] = None
        self._log: list[dict] = []
        self._hooks_installed = False
        # watchdog: if the engine stops heart-beating, assume a hang and restore.
        self._last_heartbeat = time.monotonic()
        self._watchdog_timeout = 15.0
        self._watchdog_stop = threading.Event()
        self._watchdog: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ log
    def _record(self, action: str, **detail) -> None:
        entry = {"ts": _now(), "action": action, **detail}
        self._log.append(entry)
        log.info("%s %s", action, detail)

    @property
    def session_log(self) -> list[dict]:
        with self._lock:
            return list(self._log)

    # --------------------------------------------------------------- consent
    def grant_consent(self, note: str = "") -> None:
        with self._lock:
            self._consent = True
            self._consent_note = note.strip()
            self._consent_at = _now()
            self._record("consent.granted", note=self._consent_note)
            self._install_hooks()

    def revoke_consent(self) -> None:
        """Revoking consent restores everything first, then locks the engine."""
        with self._lock:
            self.restore_all(reason="consent.revoked")
            self._consent = False
            self._record("consent.revoked")

    @property
    def has_consent(self) -> bool:
        with self._lock:
            return self._consent

    def require_consent(self) -> None:
        if not self.has_consent:
            raise ConsentError("Session consent has not been granted.")

    # -------------------------------------------------------------- allowlist
    def allow(self, ip: str, mac: str) -> Target:
        """Authorize a device as a target. Requires consent. No bulk/'all'."""
        self.require_consent()
        mac = mac.lower()
        with self._lock:
            t = Target(ip=ip, mac=mac)
            self._allow[mac] = t
            self._record("allowlist.add", ip=ip, mac=mac)
            return t

    def disallow(self, mac: str) -> None:
        """Remove a target. If it is currently poisoned, restore it first."""
        mac = mac.lower()
        with self._lock:
            if mac in self._poisons:
                self.clear_poison(mac, reason="allowlist.remove")
            self._allow.pop(mac, None)
            self._record("allowlist.remove", mac=mac)

    def is_allowed(self, mac: str) -> bool:
        with self._lock:
            return mac.lower() in self._allow

    def require_allowed(self, mac: str) -> None:
        if not self.is_allowed(mac):
            raise ConsentError(f"{mac} is not on the target allowlist.")

    @property
    def allowlist(self) -> list[Target]:
        with self._lock:
            return list(self._allow.values())

    # ------------------------------------------------------ restore callback
    def set_restore_fn(self, fn: RestoreFn) -> None:
        """The jammer registers how to undo one poison record."""
        with self._lock:
            self._restore_fn = fn

    # -------------------------------------------------------- poison tracking
    def register_poison(self, record: PoisonRecord) -> None:
        """Record a live ARP manipulation. Guarded by consent + allowlist."""
        self.require_consent()
        self.require_allowed(record.target_mac)
        with self._lock:
            if self._restore_fn is None:
                raise ConsentError("No restore function registered; refusing to poison.")
            self._poisons[record.target_mac.lower()] = record
            self._record("poison.start", target=record.target_ip,
                         mode=record.mode, gateway=record.gateway_ip)
            self._install_hooks()

    def clear_poison(self, target_mac: str, reason: str = "clear") -> None:
        """Restore a single target and stop tracking it."""
        target_mac = target_mac.lower()
        with self._lock:
            rec = self._poisons.pop(target_mac, None)
            if rec is None:
                return
            self._safe_restore(rec, reason)

    def restore_all(self, reason: str = "restore_all") -> None:
        """Undo every tracked poison. Safe to call repeatedly / on crash."""
        with self._lock:
            if not self._poisons:
                return
            self._record("restore.all", reason=reason, count=len(self._poisons))
            for rec in list(self._poisons.values()):
                self._safe_restore(rec, reason)
            self._poisons.clear()

    def _safe_restore(self, rec: PoisonRecord, reason: str) -> None:
        """Call the restore fn, swallowing errors so one failure can't block the rest.

        Restore packets are sent several times for reliability (ARP is lossy and
        unauthenticated — we want the correct mapping to win decisively)."""
        fn = self._restore_fn
        if fn is None:
            log.error("No restore fn; cannot restore %s", rec.target_ip)
            return
        for _ in range(5):
            try:
                fn(rec)
            except Exception:  # noqa: BLE001 - restore must never raise
                log.exception("restore attempt failed for %s", rec.target_ip)
        self._record("restore.done", target=rec.target_ip, reason=reason)

    @property
    def active_poisons(self) -> list[PoisonRecord]:
        with self._lock:
            return list(self._poisons.values())

    # --------------------------------------------------------------- watchdog
    def heartbeat(self) -> None:
        self._last_heartbeat = time.monotonic()

    def _watchdog_loop(self) -> None:
        while not self._watchdog_stop.wait(2.0):
            if not self._poisons:
                continue
            if time.monotonic() - self._last_heartbeat > self._watchdog_timeout:
                log.error("Engine heartbeat lost (%.0fs) — restoring all as a precaution.",
                          self._watchdog_timeout)
                try:
                    self.restore_all(reason="watchdog.heartbeat_lost")
                finally:
                    # reset so we don't spin; operator must re-arm.
                    self._last_heartbeat = time.monotonic()

    # ------------------------------------------------------------------ hooks
    def _install_hooks(self) -> None:
        """Make restore_all run on exit, Ctrl-C/term signals, and unhandled errors."""
        if self._hooks_installed:
            return
        self._hooks_installed = True

        atexit.register(lambda: self.restore_all(reason="atexit"))

        prev_excepthook = sys.excepthook

        def _hook(exc_type, exc, tb):
            try:
                self.restore_all(reason="excepthook")
            finally:
                prev_excepthook(exc_type, exc, tb)

        sys.excepthook = _hook

        # Signal handlers only install on the main thread.
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    prev = signal.getsignal(sig)

                    def _sig_handler(signum, frame, _prev=prev):
                        self.restore_all(reason=f"signal.{signum}")
                        if callable(_prev):
                            _prev(signum, frame)
                        else:
                            raise SystemExit(0)

                    signal.signal(sig, _sig_handler)
                except (ValueError, OSError):
                    pass  # e.g. not supported in this context

        if self._watchdog is None:
            self._watchdog = threading.Thread(
                target=self._watchdog_loop, name="rootrex-watchdog", daemon=True)
            self._watchdog.start()
        self._record("hooks.installed")


# A single process-wide instance the other modules share.
safety = SafetyManager()
