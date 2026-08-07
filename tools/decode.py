#!/usr/bin/env python3
"""decode.py -- turn a phone photo of one payload page into 8 bytes.

  python decode.py page1.jpg [page2.jpg ...]

The payload draws a 2 px lit border around the whole panel. That border is the
only reason hand-held photos work: it pins the origin and the scale, so cell
bloom can no longer walk the sampling grid off by a row.

Sampling geometry must match draw_page8() exactly:
  cells 8 x 8, pitch 14 px, 12 px lit core, inset 8 px, MSB leftmost.
"""
import sys, itertools
from PIL import Image, ImageFilter

# Your badge's own control value. Page 2 renders eight bytes of the UUID slot,
# which is unique per badge, so there is no universal constant to put here.
# Read yours once from a known-good run (or from `test proc` / the vault UI) and
# paste it in. Until you do, decode.py still works, it just cannot tell you when
# a photo set is untrustworthy, which is the entire point of the control.
CONTROL_PAGE2 = ""   # e.g. "0011223344556677"


def find_frame(im):
    """Bounding box of the lit border, tried over several crops and thresholds."""
    w, h = im.size
    for (a, b, c, d) in [(0.12, 0.08, 0.94, 0.94), (0.05, 0.05, 0.98, 0.98)]:
        X0, Y0, X1, Y1 = int(w*a), int(h*b), int(w*c), int(h*d)
        sub = im.crop((X0, Y0, X1, Y1)); sw, sh = sub.size; px = sub.load()
        for thr in (210, 190, 170, 150, 130, 110, 90):
            rows = [sum(1 for x in range(0, sw, 2) if px[x, y] > thr) for y in range(sh)]
            cols = [sum(1 for y in range(0, sh, 2) if px[x, y] > thr) for x in range(sw)]
            if max(rows) == 0 or max(cols) == 0:
                continue
            def edges(p):
                m = max(p); hot = [i for i, v in enumerate(p) if v > 0.55 * m]
                return hot[0], hot[-1]
            ry0, ry1 = edges(rows); cx0, cx1 = edges(cols)
            wp, hp = cx1 - cx0, ry1 - ry0
            # the panel is square, so reject anything wildly off-aspect
            if wp > 150 and hp > 150 and 0.72 < wp / hp < 1.40:
                return [X0 + cx0, X0 + cx1, Y0 + ry0, Y0 + ry1]
    return None


def sample(im, frame, off):
    """Rectify to 128x128 (x3 supersample) and read the 64 cells."""
    x0, x1, y0, y1 = frame
    a, b, c, d = off
    up = 3; N = 128 * up
    quad = (x0+a, y0+b,  x0+a, y1+d,  x1+c, y1+d,  x1+c, y0+b)
    # rotate(270): the badge is photographed on its side
    disp = im.transform((N, N), Image.QUAD, quad, Image.BICUBIC).rotate(270)
    p = disp.load()

    def box(X, Y, r):
        t = n = 0
        for dy in range(-r, r+1):
            for dx in range(-r, r+1):
                t += p[min(N-1, max(0, X+dx)), min(N-1, max(0, Y+dy))]; n += 1
        return t / n

    vals = [box((8 + col*14 + 6)*up, (8 + row*14 + 6)*up, 4*up)
            for row in range(8) for col in range(8)]
    lo, hi = min(vals), max(vals)
    thr = (lo + hi) / 2
    # margin: how close the least-confident cell sits to the threshold.
    # Maximising it is how we pick the right grid alignment.
    margin = min(abs(v - thr) for v in vals) / max(1e-9, hi - lo)
    bits = [1 if v > thr else 0 for v in vals]
    out = bytes(sum(bits[i*8 + j] << (7 - j) for j in range(8)) for i in range(8))
    return out, margin


def decode(path):
    im = Image.open(path).convert("L").filter(ImageFilter.MedianFilter(3))
    frame = find_frame(im)
    if frame is None:
        return None, 0.0
    cw = (frame[1] - frame[0]) * 14 / 128.0     # one cell, in photo pixels
    ch = (frame[3] - frame[2]) * 14 / 128.0
    # Search sub-cell offsets. Getting this wrong by one whole cell silently
    # inserts a byte, which looks like plausible data. Ask how large your
    # search step is in CELLS, never in pixels.
    best = None
    for k in itertools.product([-0.5, -0.25, 0, 0.25, 0.5], repeat=4):
        off = (k[0]*cw, k[1]*ch, k[2]*cw, k[3]*ch)
        out, margin = sample(im, frame, off)
        if best is None or margin > best[1]:
            best = (out, margin)
    return best


for path in sys.argv[1:]:
    out, margin = decode(path)
    if out is None:
        print(f"{path}: frame not found, reshoot with the whole panel in view")
        continue
    tag = ""
    if CONTROL_PAGE2 and out.hex() == CONTROL_PAGE2:
        tag = "  <- page 2 control EXACT"
    print(f"{path}  margin={margin:.2f}  {out.hex()}{tag}")
