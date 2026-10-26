# Third-Party Notices

RootreX is licensed under the MIT License (see `LICENSE`). It bundles or adapts
the following third-party components, each of which remains under its own
license.

---

## GSAP 3.12.5 — GreenSock Standard "No-Charge" License

Copyright © GreenSock. Vendored unmodified at `ui/dist/vendor/gsap.min.js` and
used for functional UI motion.

Licensed under the GreenSock Standard "No-Charge" License:
<https://gsap.com/standard-license/>

---

## evil-aye — MIT License

The procedural WebGL "evil eye" background (`ui/dist/eye.js`) is a
dependency-free port (reimplemented without React/OGL) of the flame-iris shader
from the **evil-aye** project by Sebastián Vásquez Echavarría.

<https://github.com/sebastianvasquezechavarria1234/evil-aye>

```
MIT License

Copyright (c) 2024 Sebastián Vásquez Echavarría

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

> If the upstream repository publishes a different copyright year or holder
> string in its `LICENSE`, update the block above to match it verbatim.

---

## Fonts

Chakra Petch, IBM Plex Mono, and IBM Plex Sans (SIL Open Font License 1.1) are
loaded from Google Fonts at runtime when online; they are **not** redistributed
in this repository.

---

## Python dependencies

Runtime Python packages (Scapy, FastAPI, uvicorn, pywebview, and others listed
in `requirements.txt`) are installed from PyPI and are **not** redistributed in
this repository. Each retains its own license (e.g. Scapy is GPLv2; FastAPI and
uvicorn are BSD/MIT-family). Npcap is **not** bundled — its license restricts
redistribution — so RootreX links users to the official installer instead.
