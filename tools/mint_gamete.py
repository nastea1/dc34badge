#!/usr/bin/env python3
"""mint_gamete.py -- craft a valid DC34 light-gene gamete and render it as a QR.

This is not a protocol bypass. It speaks the protocol correctly, using k0, which is the
AES-256-GCM-SIV key the badges themselves use for the gene exchange.

  mint_gamete.py challenge                      make a phase-1 "my key" QR (header + nonce)
  mint_gamete.py scan <photo.jpg> [--respond]   read a badge's QR from a photo
  mint_gamete.py respond <nonce-hex> [options]  seal a gamete under THEIR nonce
  mint_gamete.py decode <base45>                decode/verify anything you scanned

THE EXCHANGE, from dc34-vault/src/main.rs:

  phase 1   base45( DC34_HEADER[16] || nonce[12] )
  phase 2   base45( AES-256-GCM-SIV(k0, their_nonce, plaintext[16]) )   -> 32 bytes ct||tag

  plaintext[16] = Haploid[9] || zeros[6] || badge_type[1]      (aad is empty)

The scanner tells the phases apart solely by testing data[..16] == DC34_HEADER, which is also
why generate_my_nonce() refuses to emit a nonce equal to DC34_HEADER[..12].

TWO THINGS THAT ARE NOT OBVIOUS:

1. You contribute a gamete, not a child. The receiver performs syngamy against its own
   get_egg(), so your haplotype is one of the resulting pair. You cannot choose the offspring.

2. Byte 15 is load-bearing, and 'none' is the safe answer. If incoming_type equals the receiver's
   own badge type the firmware flags inbreeding and RAISES the mutation rate, scrambling exactly
   the genes you tuned. incoming_type is used for nothing else (dc34-vault/src/main.rs:709), and a
   badge that can breed always has a concrete type from its SAO pins, so 'none' never collides.
"""
import argparse
import hashlib
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

# dc34-api/src/lib.rs:26
DC34_HEADER = bytes.fromhex("49db7671f34435ed5fddffdfcbb7508a")
K0_PATH = os.environ.get("DC34_K0", os.path.expanduser("~/dc34-badge/.k0.hex"))
K0_SHA_PREFIX = "dca9ea49"  # bunnie's own oracle, dc34-vault/src/main.rs:42

# dc34-api/src/lib.rs BadgeType
BADGE_TYPES = {
    "uber": 0, "other": 1, "comm": 2, "village": 3,
    "ctf": 4, "human": 5, "goon": 6, "none": 7,
}

# Haploid, #[repr(C)], nine u8 in declaration order. bytemuck::bytes_of, so no padding.
HAPLOID_FIELDS = [
    "cd_period", "cd_rate", "cd_dir", "sat",
    "hue_ratedir", "hue_base", "hue_bound", "chaser", "nonlin",
]

# The Uber extremes. hue_bound is forced to 255 for Uber by from_type(), and chaser/nonlin low
# ranges are reachable by no other badge type, which is what makes them rare.
UBER_MAX = {
    "cd_period": 3,      # Uber cd_period_max
    "cd_rate": 96,       # tau = map(cd_rate,0,255,60,700); lower is faster
    "cd_dir": 0,         # Uber range 0..=45, so always the same rotation
    "sat": 255,          # Uber range 130..=255
    "hue_ratedir": 255,  # hue_rate = low nibble = 15, max hue travel
    "hue_base": 220,     # Uber range 220..=255
    "hue_bound": 255,    # forced to 255 for Uber
    "chaser": 0,         # < 88 is the rare white-chaser branch. Uber 0..=45, others 90..=255
    "nonlin": 0,         # > 127 squares brightness (dims). Uber 0..=44, so Uber never dims
}

# A combination no badge can be BORN with. The hue band is the giveaway: hue_bound is only ever
# forced to 255 for Uber, whose hue_base starts at 220, and Goon is the only type with hue_base 0
# but its bound is capped at 20. So base 0 with bound 255 cannot be rolled by any type at birth.
# Paired with a guaranteed chaser and no dimming, this is unmistakable.
APEX = dict(UBER_MAX, hue_base=0, hue_bound=255)

PRESETS = {"uber": UBER_MAX, "apex": APEX}

# RFC 9285
B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def b45_encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data) - 1, 2):
        n = data[i] * 256 + data[i + 1]
        c, n = divmod(n, 45 * 45)
        d, e = divmod(n, 45)
        out += [B45_ALPHABET[e], B45_ALPHABET[d], B45_ALPHABET[c]]
    if len(data) % 2:
        d, e = divmod(data[-1], 45)
        out += [B45_ALPHABET[e], B45_ALPHABET[d]]
    return "".join(out)


def b45_decode(s: str) -> bytes:
    vals = [B45_ALPHABET.index(c) for c in s]
    out = bytearray()
    for i in range(0, len(vals) - 2, 3):
        n = vals[i] + vals[i + 1] * 45 + vals[i + 2] * 45 * 45
        if n > 0xFFFF:
            raise ValueError("base45 triplet out of range")
        hi, lo = divmod(n, 256)
        out.append(hi)
        out.append(lo)
    if len(vals) % 3 == 2:
        n = vals[-2] + vals[-1] * 45
        if n > 0xFF:
            raise ValueError("base45 pair out of range")
        out.append(n)
    elif len(vals) % 3 != 0:
        raise ValueError("bad base45 length")
    return bytes(out)


def load_k0() -> bytes:
    if not os.path.exists(K0_PATH):
        sys.exit(f"k0 not found at {K0_PATH}")
    k0 = bytes.fromhex(open(K0_PATH).read().strip())
    if len(k0) != 32:
        sys.exit(f"k0 is {len(k0)} bytes, expected 32")
    # Never operate on an unverified key. The oracle is bunnie's, not ours.
    got = hashlib.sha256(k0).hexdigest()
    if not got.startswith(K0_SHA_PREFIX):
        sys.exit(f"k0 FAILED the oracle: sha256 starts {got[:8]}, expected {K0_SHA_PREFIX}")
    return k0


def build_haploid(overrides: dict, preset: str = "uber") -> bytes:
    genes = dict(PRESETS[preset])
    genes.update(overrides)
    for k, v in genes.items():
        if not 0 <= v <= 255:
            sys.exit(f"{k}={v} out of range")
    return bytes(genes[f] for f in HAPLOID_FIELDS)


def render_qr(payload: str, path: str):
    import qrcode
    # EcLevel::M, matching QrCode::with_error_correction_level in main.rs
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(path)
    print(f"  QR written to {path} (version {qr.version}, EC level M)")


def cmd_challenge(args):
    # Mirrors generate_my_nonce(): 12 random bytes, never equal to DC34_HEADER[..12].
    while True:
        nonce = os.urandom(12)
        if nonce != DC34_HEADER[:12]:
            break
    blob = DC34_HEADER + nonce
    enc = b45_encode(blob)
    print(f"nonce   = {nonce.hex()}")
    print(f"raw     = {len(blob)} bytes")
    print(f"base45  = {enc}")
    render_qr(enc, args.out)
    print("\nShow this to the other badge. Keep the nonce: you need it to decrypt their reply.")


def cmd_respond(args):
    k0 = load_k0()
    their_nonce = bytes.fromhex(args.nonce)
    if len(their_nonce) != 12:
        sys.exit(f"nonce is {len(their_nonce)} bytes, expected 12")

    overrides = {}
    for spec in args.gene or []:
        k, _, v = spec.partition("=")
        if k not in HAPLOID_FIELDS:
            sys.exit(f"unknown gene {k}, expected one of {HAPLOID_FIELDS}")
        overrides[k] = int(v, 0)

    haploid = build_haploid(overrides, getattr(args, 'preset', 'uber'))
    bt = BADGE_TYPES[args.badge_type]
    plaintext = haploid + b"\x00" * 6 + bytes([bt])
    assert len(plaintext) == 16

    ct = AESGCMSIV(k0).encrypt(their_nonce, plaintext, None)  # aad empty, as in Payload{aad:&[]}
    enc = b45_encode(ct)

    print("plaintext:")
    for f, v in zip(HAPLOID_FIELDS, haploid):
        print(f"  {f:<12} {v}")
    print(f"  badge_type   {args.badge_type} ({bt})")
    print(f"\nraw      = {plaintext.hex()}")
    print(f"sealed   = {len(ct)} bytes (16 ct + 16 tag)")
    print(f"base45   = {enc}")
    render_qr(enc, args.out)

    if args.badge_type == "none":
        print("\nbyte 15 = none: cannot trip inbreeding. A badge that can breed has a concrete "
              "type from its SAO pins, and a badge typed None never had init_light_gene() called, "
              "so it has no gene to mate with. Your haplotype arrives unmutated.")
    else:
        print(f"\nWARNING: byte 15 is '{args.badge_type}'. If the target badge is also "
              f"{args.badge_type}, the firmware flags inbreeding and raises the mutation rate "
              "(~25 to 39% per gene), scrambling these genes. 'none' avoids this entirely.")


def read_qr_from_image(path: str) -> str:
    """Pull the QR text out of a phone photo.

    Badge screens are small, glossy and usually photographed at an angle, so a single detect
    attempt on the raw image fails often. Try the plain detector first, then OpenCV's own
    upscaling/deskew path, then a few rescales, and give up loudly rather than silently
    returning something from the wrong code.
    """
    import cv2
    import numpy as np

    img = cv2.imread(path)
    if img is None:
        sys.exit(f"could not read image {path}")
    det = cv2.QRCodeDetector()
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    def attempt(im, label):
        try:
            text, _, _ = det.detectAndDecode(im)
        except cv2.error:
            return None
        return text or None

    # Isolate the lit panel. Two things about badge photos defeat a naive detect: the code runs
    # to the edge of the OLED with no quiet zone, which the QR spec requires, and the panel's
    # pixel grid lays a fine mesh over the modules that reads as noise. Cropping to the bright
    # region and adding our own white margin fixes the first; mild blur and rescaling the second.
    candidates = []
    _, th = cv2.threshold(gray, 120, 255, cv2.THRESH_BINARY)
    th = cv2.morphologyEx(th, cv2.MORPH_CLOSE, np.ones((25, 25), np.uint8))
    contours, _ = cv2.findContours(th, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if contours:
        x, y, w, h = cv2.boundingRect(max(contours, key=cv2.contourArea))
        candidates.append(gray[max(0, y - 10):y + h + 10, max(0, x - 10):x + w + 10])
    candidates.append(gray)

    for crop in candidates:
        if crop.size == 0:
            continue
        for scale in (1.0, 0.5, 0.35, 0.25, 2.0):
            s = cv2.resize(crop, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
            for blur in (0, 3, 5):
                b = cv2.GaussianBlur(s, (blur, blur), 0) if blur else s
                for meth in ("raw", "otsu", "adaptive"):
                    if meth == "otsu":
                        _, im = cv2.threshold(b, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                    elif meth == "adaptive":
                        im = cv2.adaptiveThreshold(b, 255, cv2.ADAPTIVE_THRESH_MEAN_C,
                                                   cv2.THRESH_BINARY, 31, 5)
                    else:
                        im = b
                    q = cv2.copyMakeBorder(im, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
                    r = attempt(cv2.cvtColor(q, cv2.COLOR_GRAY2BGR), meth)
                    if r:
                        return r
    sys.exit("no QR found. Reshoot with the whole code in frame, square on, and in focus.")


def cmd_scan(args):
    text = read_qr_from_image(args.image)
    print(f"QR text  = {text}")
    data = b45_decode(text)
    print(f"decoded  = {len(data)} bytes")

    if data[:16] != DC34_HEADER:
        print("-> phase 2, a sealed gamete. Use 'decode' with the nonce you issued.")
        return

    nonce = data[16:28]
    print("-> phase 1, their key")
    print(f"   nonce = {nonce.hex()}")
    if not args.respond:
        print(f"\nNext: mint_gamete.py respond {nonce.hex()} --badge-type <not-their-type>")
        return

    # Chain straight into minting, so the whole exchange runs off one photo.
    print()
    inner = argparse.Namespace(nonce=nonce.hex(), badge_type=args.badge_type,
                               gene=args.gene, out=args.out,
                               preset=getattr(args, 'preset', 'uber'))
    cmd_respond(inner)


def cmd_decode(args):
    data = b45_decode(args.data)
    print(f"decoded {len(data)} bytes: {data.hex()}")
    if data[:16] == DC34_HEADER:
        print("-> phase 1, a challenge")
        print(f"   nonce = {data[16:28].hex()}")
        return
    print("-> phase 2, a sealed gamete")
    if not args.nonce:
        print("   pass --nonce <hex> (the nonce YOU issued) to decrypt")
        return
    k0 = load_k0()
    try:
        pt = AESGCMSIV(k0).decrypt(bytes.fromhex(args.nonce), data, None)
    except Exception as e:
        sys.exit(f"   decrypt FAILED: {e}")
    print(f"   plaintext = {pt.hex()}")
    for f, v in zip(HAPLOID_FIELDS, pt[:9]):
        print(f"     {f:<12} {v}")
    inv = {v: k for k, v in BADGE_TYPES.items()}
    print(f"     badge_type   {inv.get(pt[15], pt[15])}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("challenge", help="emit a phase-1 key QR")
    c.add_argument("--out", default="challenge.png")
    c.set_defaults(func=cmd_challenge)

    s = sub.add_parser("scan", help="read a badge's QR out of a photo")
    s.add_argument("image")
    s.add_argument("--respond", action="store_true",
                   help="on a phase-1 code, go straight on to minting the reply")
    s.add_argument("--badge-type", default="none", choices=sorted(BADGE_TYPES),
                   help="byte 15. Default 'none' can never trip inbreeding")
    s.add_argument("--preset", default="uber", choices=sorted(PRESETS))
    s.add_argument("--gene", action="append", metavar="name=value")
    s.add_argument("--out", default="gamete.png")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("respond", help="seal a gamete under their nonce")
    r.add_argument("nonce", help="their 12-byte nonce, hex, from their phase-1 QR")
    r.add_argument("--badge-type", default="none", choices=sorted(BADGE_TYPES),
                   help="byte 15. Default 'none' can never trip inbreeding")
    r.add_argument("--preset", default="uber", choices=sorted(PRESETS),
                   help="uber = authentic Uber extremes; apex = impossible to be born with")
    r.add_argument("--gene", action="append", metavar="name=value",
                   help="override a gene, repeatable. default is the Uber extremes")
    r.add_argument("--out", default="gamete.png")
    r.set_defaults(func=cmd_respond)

    d = sub.add_parser("decode", help="decode a scanned base45 blob")
    d.add_argument("data")
    d.add_argument("--nonce", help="the nonce you issued, to decrypt a phase-2 blob")
    d.set_defaults(func=cmd_decode)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
