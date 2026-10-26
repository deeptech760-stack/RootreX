# Tooling, skills & research

What RootreX is built with, and why each choice was made. This doubles as the "skills/tools I'm using" record requested in the brief.

## Skills used during the build

| Skill / capability | Why |
|--------------------|-----|
| **Planning / architecture reasoning** | To finalize the stack and a modular design (scanner / jammer / observer / ap / safety) before writing code, and to settle the scope boundary (what is built vs explained-only) up front. |
| **frontend-design / artifact-design guidance** | To produce the "Tactical HUD" — an intentional, data-dense interface with *functional* motion — rather than a generic gradient layout. Drives the Tailwind token palette, typography, and GSAP usage. |
| **Web research (WebSearch/WebFetch)** | To ground the Windows-specific realities (Mobile Hotspot limits, Npcap/WebView2) and the current defensive landscape (client-isolation bypasses) in real sources rather than assumption. See [Sources](#research-sources). |

## Runtime stack & libraries

| Component | Package / tech | Why this one |
|-----------|----------------|--------------|
| Packet capture & send | **Scapy** over **Npcap ≥ 1.3.0** | Mandated by the brief and correct for Windows. Npcap is the maintained WinPcap successor; ≥1.3.0 fixes earlier 802.11 regressions. |
| MAC → vendor | **`mac-vendor-lookup`** (local OUI DB) | Offline vendor guess for the scanner; no per-scan network calls. |
| Control API | **FastAPI** + **uvicorn**, WebSocket | Async, streams live events to the UI, binds loopback-only. |
| Shell | **Default browser + system tray** (`pystray`) | The UI opens in the user's own browser (reliable, nothing to bundle); RootreX lives in the tray. No embedded webview — sidesteps WebView2-in-elevated-process rendering issues. |
| UI | **Static HTML/CSS/JS — no build** | Served straight from `ui/dist`; nothing to compile — the fastest path to "clone and it runs". |
| Background eye | **WebGL flame-iris shader** (ported from [evil-aye](https://github.com/sebastianvasquezechavarria1234/evil-aye), MIT) | A procedural "evil eye" on a full-screen canvas behind the UI — reimplemented dependency-free in `ui/dist/eye.js`. |
| Styling | **Hand-built token CSS** (soft neumorphic) | Palette + type as `:root` custom properties; Chakra Petch (display) / IBM Plex Mono (data) / IBM Plex Sans (body) — a deliberately non-default pairing for an ops console. |
| Motion | **GSAP 3.12.5** (vendored) | Functional animation: new-host flash-in, state-change pulse, armed-STOP breathing, live rate spark. |
| Privileges | **None required** | Npcap grants packet access to the normal user, so the app runs without UAC. |
| Test-AP control | **WinRT `NetworkOperatorTetheringManager`** / `netsh` | The only sane way to stand up a configurable software AP on Windows. The laptop becomes the real gateway, so the Observer sees traffic natively — no spoofing. |

## Why the Test-AP uses Windows Mobile Hotspot, not Scapy

Windows has **no userspace 802.11 AP/injection path** — you cannot build an access point from Scapy on Windows the way you can with `hostapd` on Linux. The supported mechanism is the OS **Mobile Hotspot** (WinRT `NetworkOperatorTetheringManager`, or legacy `netsh wlan hostednetwork`, now deprecated). This is also the *safer* design: it's a legitimate OS feature, the SSID/password are operator-chosen, devices join deliberately, and because the laptop is genuinely the gateway there is **zero spoofing** in this mode. Known limits (documented in the README): it needs upstream internet from another adapter (it can't rebroadcast the Wi-Fi it's on), caps at ~8 clients, and some carriers/drivers restrict it.

## Research sources

- **Windows Mobile Hotspot limits** (8-client cap; cannot rebroadcast the connected Wi-Fi; client/NAT isolation) — Connectify: <https://connectify.me/blog/virtual-router/windows-hotspot-device-limit/>
- **Client-isolation is only partial; PMF/802.1X/per-client-GTK/L3 controls** — AirSnitch (NDSS 2026), Kaspersky writeup: <https://www.kaspersky.com/blog/airsnitch-wi-fi-client-isolation-guest-network-vulnerability-and-mitigation/55597/> ; Arista advisory: <https://www.arista.com/en/support/advisories-notices/security-advisory/24108-security-advisory-0141>
- **Scapy** (cross-platform forge/send/capture; Npcap monitor-mode notes): <https://scapy.net> / <https://github.com/secdev/scapy>
- **Npcap** (install, WinPcap-compatible mode): <https://npcap.com>

## Third-party front-end

- **GSAP 3.12.5** (GreenSock standard "no-charge" license) — vendored under `ui/dist/vendor`; drives the functional UI motion: <https://gsap.com>
- **evil-aye** by Sebastián Vásquez Echavarría (MIT) — the procedural WebGL "evil eye"; its flame-iris shader was ported to a dependency-free module in `ui/dist/eye.js`: <https://github.com/sebastianvasquezechavarria1234/evil-aye>
- Design method: deliberate neutrals, token-first color, soft neumorphic surfaces, functional motion.
