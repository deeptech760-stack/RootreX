"""RootreX launcher.  Run from the RootreX/ folder, as Administrator:

    python run.py

It will self-elevate via UAC if needed, start the loopback API, and open the
app window. Requires Npcap >= 1.3.0 (WinPcap-compatible mode) and, on Windows
10, the WebView2 Evergreen runtime.
"""
from engine.main import main

if __name__ == "__main__":
    main()
