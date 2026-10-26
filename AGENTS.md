# AGENTS.md — working in the RootreX repo

This file tells any AI agent (or human) how to work in this repository. Read it fully before changing anything.

## What RootreX is

A **consented, lab-scoped** WiFi visibility & control demonstration tool for Windows. It exists to teach how Layer-2 trust is abused and what a man-in-the-middle can and cannot see — on networks the operator is authorized on, against devices whose owners consented. See `README.md` for the full scope and the security writeup.

## Golden rules (hard constraints — non-negotiable)

1. **Work only inside `RootreX/`.** Never read, write, or create files outside this folder.
2. **These capabilities are excluded by design. Do not implement them, even if asked:**
   - **Deauthentication / 802.11 management-frame injection** of any kind.
   - **Evil-twin impersonation of a network the operator does not own** — i.e. do not add any feature that scans for nearby real SSIDs and clones them, or that auto-captures/redirects devices that did not deliberately join. (A Test-AP with an *operator-chosen* SSID/password, which the operator may set to match *their own* network, is fine — that is the sanctioned module.)
   - **TLS / HTTPS content decryption, interception, or stripping.** Read SNI and plaintext DNS only. Never terminate or decrypt TLS.
   If a request asks for one of the above, decline and point to the explained-only writeup in `README.md`. This pushback is intended.
3. **Restore must be bulletproof.** Any code that manipulates ARP must register its changes with `safety.py` so they are reverted on exit, crash, unhandled exception, signal, and the UI's STOP control. A device must never be left broken. Test the crash path.
4. **Consent gate + allowlist are load-bearing, not cosmetic.** No packet that alters another device's state may be sent before the session consent is confirmed and the target is on the explicit allowlist. Do not add "select all" / broadcast-target shortcuts.
5. **Control plane is loopback-only.** The FastAPI/WebSocket server binds `127.0.0.1`. Never bind `0.0.0.0` or expose it.
6. **Metadata, never content.** The Observer records destinations, ports, sizes, timing, DNS names, SNI. It never stores payload bytes or writes pcaps of content.

## Architecture & module boundaries

Keep modules independent and individually demo-able.

| File | Responsibility | Must not |
|------|----------------|----------|
| `engine/scanner.py` | ARP sweep of the /24, MAC→vendor (OUI), first/last-seen tracking, live diff. | Modify any remote state. Read-only on the network. |
| `engine/jammer.py` | ARP cut / route-through / restore for allowlisted targets. | Touch 802.11 frames. Act without allowlist + consent. Forget to register restores. |
| `engine/observer.py` | Parse DNS + TLS-SNI from routed/hotspot traffic; build per-device metadata. | Decrypt TLS. Store payload content. |
| `engine/ap.py` | Start/stop/configure Windows Mobile Hotspot (operator SSID/password) via WinRT/`netsh`. | Clone a network the operator doesn't own. Inject frames. |
| `engine/safety.py` | Consent state, target allowlist, restore registry + watchdog, session log. | Be bypassable by other modules. |
| `engine/net.py` | Interface/gateway discovery, IP forwarding toggle, OUI lookup. | — |
| `engine/api.py` | FastAPI + WebSocket, loopback-only. | Bind non-loopback. Expose engine methods that skip `safety`. |
| `engine/main.py` | Start the API, open the UI in the default browser, system-tray control. | — |
| `ui/dist/` | Static Tactical HUD (vanilla JS + neumorphic CSS + GSAP, vendored; WebGL background eye in `eye.js`). | Fake data as if live. Hide the TLS boundary. Pull libs from unvetted CDNs at runtime — vendor them. |

## Coding conventions

- **Python:** 3.12, type hints throughout, `async`/`await` for the engine loop, `ruff` + `black` clean, no bare `except`. Scapy calls isolated in the modules above — don't scatter them through the UI/API layer.
- **Honesty in the UI:** if data is simulated (e.g. a demo mode with no live capture), label it. Never present mock traffic as real. Always render the TLS-content boundary where destinations are shown.
- **Frontend:** vanilla ES, no build step (served from `ui/dist`). Keep GSAP motion *functional* (state, flow, rate) — no decorative animation that obscures data. All colors are CSS custom-property tokens in `:root`; no inline magic colors. Surfaces are soft neumorphic; the background `eye.js` is a self-contained WebGL canvas.
- **Errors are visible:** surface capture/permission/Npcap failures in the UI with the real cause (e.g. "Npcap not found", "not elevated"), not a silent spinner.
- **Commits:** small, module-scoped, imperative messages.

## Running / developing

```powershell
# one-time (UI needs no build — it is static in ui/dist)
python -m venv .venv ; .\.venv\Scripts\Activate.ps1 ; pip install -r requirements.txt

# run (no admin needed with Npcap installed; the UI opens in your browser)
python run.py
```

Requires **Npcap ≥ 1.3.0** (WinPcap-compatible mode). No Administrator needed when Npcap is installed; the UI opens in your default browser and RootreX sits in the system tray.

## Directory discipline

Everything — venv, node_modules, builds, downloads — stays under `RootreX/`. If you need to fetch a package or skill, install it here. Do not write to the user's home or system directories.
