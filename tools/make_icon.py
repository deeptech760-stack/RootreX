"""Generate assets/rootrex.ico (and a PNG preview) — the Crimson Eye app icon.

Draws the same volcanic "evil eye" as assets/rootrex.svg with Pillow only (no
SVG renderer needed), so it runs in CI with just `pip install pillow`.

Run:  python tools/make_icon.py
"""
from __future__ import annotations

import math
import random
from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parent.parent / "assets"
ICO = ASSETS / "rootrex.ico"
PNG = ASSETS / "rootrex-256.png"
SIZES = [16, 24, 32, 48, 64, 128, 256]

# iris radial stops: (position 0..1 from centre, RGB)
IRIS = [(0.0, (42, 2, 8)), (0.30, (138, 0, 24)), (0.60, (210, 17, 47)),
        (0.85, (255, 47, 74)), (1.0, (72, 4, 19))]


def _lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _iris_color(t):
    t = max(0.0, min(1.0, t))
    for i in range(len(IRIS) - 1):
        p0, c0 = IRIS[i]
        p1, c1 = IRIS[i + 1]
        if t <= p1:
            return _lerp(c0, c1, (t - p0) / (p1 - p0) if p1 > p0 else 0)
    return IRIS[-1][1]


def draw_eye(S: int) -> Image.Image:
    cx = cy = S / 2
    R = S * 0.40
    scene = Image.new("RGBA", (S, S), (9, 4, 12, 255))

    # outer red glow (annulus, graded alpha) — composited so it blends on the bg
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    dg = ImageDraw.Draw(glow)
    Rg = R * 1.5
    for r in range(int(Rg), int(R), -1):
        a = int(150 * (1 - (r - R) / (Rg - R)))
        dg.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 44, 70, max(0, a)))
    scene = Image.alpha_composite(scene, glow)

    # iris (concentric opaque discs = radial gradient)
    di = ImageDraw.Draw(scene)
    for r in range(int(R), 0, -1):
        di.ellipse([cx - r, cy - r, cx + r, cy + r], fill=_iris_color(r / R) + (255,))

    # flame streaks
    st = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ds = ImageDraw.Draw(st)
    rng = random.Random(7)
    w = max(1, round(S / 256 * 1.6))
    for k in range(40):
        ang = k / 40 * 2 * math.pi + rng.uniform(-0.05, 0.05)
        r0, r1 = R * 0.30, R * rng.uniform(0.80, 0.97)
        col = (255, rng.randint(70, 110), rng.randint(84, 112), rng.randint(45, 110))
        ds.line([cx + math.cos(ang) * r0, cy + math.sin(ang) * r0,
                 cx + math.cos(ang) * r1, cy + math.sin(ang) * r1], fill=col, width=w)
    scene = Image.alpha_composite(scene, st)

    # bright limbal ring
    ring = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    dr = ImageDraw.Draw(ring)
    rr = R * 0.965
    dr.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=(255, 58, 84, 215),
               width=max(2, round(S / 256 * 3.2)))
    scene = Image.alpha_composite(scene, ring)

    # evil slit pupil (opaque) + glowing outline + catchlight
    px, py = R * 0.20, R * 0.66
    ImageDraw.Draw(scene).ellipse([cx - px, cy - py, cx + px, cy + py], fill=(6, 1, 3, 255))
    det = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    dd = ImageDraw.Draw(det)
    dd.ellipse([cx - px, cy - py, cx + px, cy + py], outline=(255, 42, 70, 225),
               width=max(2, round(S / 256 * 2.6)))
    cr = R * 0.09
    dd.ellipse([cx - px * 0.5 - cr, cy - py * 0.42 - cr, cx - px * 0.5 + cr, cy - py * 0.42 + cr],
               fill=(255, 211, 217, 190))
    scene = Image.alpha_composite(scene, det)

    # clip to a rounded square, add a faint rim
    pad, rad = S * 0.024, S * 0.20
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([pad, pad, S - pad, S - pad], radius=rad, fill=255)
    final = Image.composite(scene, Image.new("RGBA", (S, S), (0, 0, 0, 0)), mask)
    ImageDraw.Draw(final).rounded_rectangle(
        [pad, pad, S - pad, S - pad], radius=rad, outline=(255, 58, 84, 70),
        width=max(2, round(S / 256 * 2.5)))
    return final


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    master = draw_eye(512)
    base = master.resize((256, 256), Image.LANCZOS)
    base.save(PNG)
    # pre-render each size for crisp small icons, then pack into the .ico
    imgs = [master.resize((s, s), Image.LANCZOS) for s in SIZES]
    imgs[-1].save(ICO, format="ICO", sizes=[(s, s) for s in SIZES], append_images=imgs[:-1])
    print("wrote", ICO, "and", PNG)


if __name__ == "__main__":
    main()
