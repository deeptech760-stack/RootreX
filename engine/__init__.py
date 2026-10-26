"""RootreX engine — consented, lab-scoped WiFi visibility & control.

Modules:
    safety   — consent gate, target allowlist, bulletproof restore (load-bearing).
    net      — interface / gateway discovery, OUI vendor lookup.
    scanner  — read-only ARP sweep of the local subnet.
    jammer   — ARP cut / route-through / restore for allowlisted targets.
    observer — DNS + TLS-SNI parsing into per-device metadata (destinations, never content).
    ap       — Windows Mobile Hotspot control for the Test-AP / Full-Observe mode.
    api      — FastAPI + WebSocket control plane (127.0.0.1 only).
    main     — UAC elevation, start API, open the pywebview window.

See AGENTS.md for the hard constraints. Nothing here injects 802.11 frames,
clones a network the operator does not own, or decrypts TLS.
"""

__version__ = "0.1.0"
