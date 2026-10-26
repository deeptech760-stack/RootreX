"""ap.py — Test-AP / Full-Observe controller (Windows Mobile Hotspot).

Stands up the operator's OWN access point with an operator-chosen SSID and
passphrase, via the Windows Mobile Hotspot WinRT API — driven through PowerShell
so it needs no Python winsdk wheel (which has no Python 3.13 build). Because the
laptop becomes the real gateway (clients land on 192.168.137.x), the Observer
sees all traffic on this AP **natively — no ARP spoofing at all**.

Scope (AGENTS.md): this configures *your own* AP that devices join deliberately.
It does not scan for or clone a network you do not own, and never injects frames.
Windows realities: needs upstream internet, caps at ~8 clients, needs a
hotspot-capable adapter.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("rootrex.ap")

# PowerShell that drives the WinRT tethering manager. Action + SSID + passphrase
# come in via environment variables so nothing needs escaping into the script.
_PS = r"""
$ErrorActionPreference = "Stop"
try { Add-Type -AssemblyName System.Runtime.WindowsRuntime } catch {}
$g  = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
$ga = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' })[0]
function Await($t,$rt){ $mm=$g.MakeGenericMethod($rt); $nt=$mm.Invoke($null,@($t)); $nt.Wait(-1)|Out-Null; $nt.Result }
function AwaitAction($a){ $nt=$ga.Invoke($null,@($a)); $nt.Wait(-1)|Out-Null }
try {
  $p = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
  if ($null -eq $p) { Write-Output "ERR=No upstream internet connection to share."; exit 0 }
  $m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($p)
  switch ($env:ROOTREX_AP_ACTION) {
    "configure" { $c=$m.GetCurrentAccessPointConfiguration(); $c.Ssid=$env:ROOTREX_AP_SSID; $c.Passphrase=$env:ROOTREX_AP_PASS; AwaitAction ($m.ConfigureAccessPointAsync($c)) }
    "start"     { if ("$($m.TetheringOperationalState)" -ne "On")  { Await ($m.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]) | Out-Null } }
    "stop"      { if ("$($m.TetheringOperationalState)" -ne "Off") { Await ($m.StopTetheringAsync())  ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]) | Out-Null } }
  }
  $c = $m.GetCurrentAccessPointConfiguration()
  Write-Output ("STATE="   + $m.TetheringOperationalState)
  Write-Output ("SSID="    + $c.Ssid)
  Write-Output ("CLIENTS=" + $m.ClientCount)
  Write-Output ("MAX="     + $m.MaxClientCount)
} catch { Write-Output ("ERR=" + $_.Exception.Message) }
"""


@dataclass
class APStatus:
    available: bool
    state: str              # "on" | "off" | "intransition" | "unavailable"
    ssid: str = ""
    client_count: int = 0
    max_clients: int = 0
    detail: str = ""

    def as_dict(self) -> dict:
        return self.__dict__


class TestAP:
    def __init__(self) -> None:
        self._cached = APStatus(available=True, state="off")

    # ----------------------------------------------------------------- powershell
    def _run(self, action: str, ssid: str = "", passphrase: str = "") -> dict:
        env = dict(os.environ, ROOTREX_AP_ACTION=action,
                   ROOTREX_AP_SSID=ssid, ROOTREX_AP_PASS=passphrase)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", _PS],
                capture_output=True, text=True, env=env, timeout=40,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
        except Exception as exc:  # noqa: BLE001
            return {"ERR": str(exc)}
        out: dict[str, str] = {}
        for line in (r.stdout or "").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
        return out

    def _status_from(self, d: dict) -> APStatus:
        if "ERR" in d or "STATE" not in d:
            return APStatus(available=False, state="unavailable",
                            detail=d.get("ERR", "Mobile Hotspot unavailable."))
        return APStatus(
            available=True,
            state=(d.get("STATE", "") or "unknown").lower(),
            ssid=d.get("SSID", ""),
            client_count=int(d.get("CLIENTS", "0") or 0),
            max_clients=int(d.get("MAX", "0") or 0),
        )

    # ----------------------------------------------------------------- actions
    async def configure(self, ssid: str, passphrase: str) -> APStatus:
        if not ssid or len(passphrase) < 8:
            raise ValueError("SSID required and passphrase must be >= 8 chars.")
        self._cached = self._status_from(
            await asyncio.to_thread(self._run, "configure", ssid, passphrase))
        return self._cached

    async def start(self) -> APStatus:
        self._cached = self._status_from(await asyncio.to_thread(self._run, "start"))
        return self._cached

    async def stop(self) -> APStatus:
        self._cached = self._status_from(await asyncio.to_thread(self._run, "stop"))
        return self._cached

    async def refresh(self) -> APStatus:
        self._cached = self._status_from(await asyncio.to_thread(self._run, "status"))
        return self._cached

    def status(self) -> APStatus:
        return self._cached   # cheap; refreshed by the background loop

    # --------------------------------------------------------------- hotspot iface
    def hotspot_iface(self) -> Optional[str]:
        """The Npcap device name for the hotspot's virtual adapter (clients land
        on 192.168.137.x there), so the Observer can capture it natively. Match
        the adapter that actually holds the 192.168.137.x IP — there can be other,
        inactive Wi-Fi-Direct adapters that must not be picked."""
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = list(get_windows_if_list())
        except Exception:  # noqa: BLE001
            return None
        for i in ifaces:   # the live hotspot: has a 192.168.137.x address
            if any(str(a).startswith("192.168.137") for a in i.get("ips", [])):
                if i.get("guid"):
                    return r"\Device\NPF_" + i["guid"]
        for i in ifaces:   # fallback: a Wi-Fi Direct Virtual Adapter
            desc = (i.get("description", "") + i.get("name", "")).lower()
            if "wi-fi direct virtual" in desc and i.get("guid"):
                return r"\Device\NPF_" + i["guid"]
        return None
