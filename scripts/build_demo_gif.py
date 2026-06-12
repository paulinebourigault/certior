import os
from PIL import Image, ImageDraw, ImageFont, ImageFilter

W, H = 1000, 560
OUT = "docs/landing/multi-agent-demo.gif"

# palette
NAVY_T, NAVY_B = (13, 21, 38), (8, 13, 24)
CREAM = (248, 239, 227)
INK = (15, 23, 42)
SLATE = (148, 163, 184)
DIM = (88, 101, 122)
TEXT = (210, 219, 232)
GREEN = (52, 211, 153)
GREEN_S = (16, 185, 129)
RED = (248, 113, 113)
RED_S = (239, 68, 68)
NODE = (18, 27, 46)
NODE_BD = (37, 49, 73)


def F(path, size):
    return ImageFont.truetype(path, size)


DV = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
DVB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf"
f_word = F(DVB, 26)
f_tag = F(DV, 14)
f_scn = F(MONO, 15)
f_node = F(DVB, 17)
f_sub = F(DV, 12)
f_chip = F(MONO, 15)
f_ban = F(DVB, 30)
f_cap = F(DV, 18)
f_small = F(MONO, 13)


def gradient_bg():
    # flat background: crisper and far smaller as a GIF than a gradient
    return Image.new("RGB", (W, H), (10, 16, 30))


def ctext(d, cx, y, text, font, fill):
    bb = d.textbbox((0, 0), text, font=font)
    d.text((cx - (bb[2] - bb[0]) / 2, y), text, font=font, fill=fill)


def glow_layer(draw_fn):
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw_fn(ImageDraw.Draw(layer))
    return layer.filter(ImageFilter.GaussianBlur(10))


def shield_pts(cx, cy, s=1.0):
    return [(cx, cy - 40 * s), (cx + 31 * s, cy - 27 * s), (cx + 31 * s, cy + 8 * s),
            (cx, cy + 42 * s), (cx - 31 * s, cy + 8 * s), (cx - 31 * s, cy - 27 * s)]


def database(d, cx, cy, color, fill):
    w, h, eh = 70, 64, 18
    l, r, t, b = cx - w / 2, cx + w / 2, cy - h / 2, cy + h / 2
    d.rectangle([l, t + eh / 2, r, b - eh / 2], fill=fill)
    for yy in (t, cy - 8, cy + 14):
        d.ellipse([l, yy, r, yy + eh], outline=color, width=2,
                  fill=fill if yy != t else fill)
    d.ellipse([l, t, r, t + eh], outline=color, width=2, fill=fill)
    d.line([l, t + eh / 2, l, b - eh / 2], fill=color, width=2)
    d.line([r, t + eh / 2, r, b - eh / 2], fill=color, width=2)
    d.arc([l, b - eh, r, b], 0, 180, fill=color, width=2)


def node(d, cx, cy, w, h, title, subs, accent):
    l, t, r, b = cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2
    d.rounded_rectangle([l, t, r, b], radius=14, fill=NODE, outline=NODE_BD, width=1)
    d.rounded_rectangle([l, t, l + 5, b], radius=2, fill=accent)
    ctext(d, cx, t + 16, title, f_node, TEXT)
    yy = t + 44
    for s, col in subs:
        ctext(d, cx, yy, s, f_sub, col)
        yy += 18


def page_icon(d, cx, cy):
    l, t, r, b = cx - 26, cy - 32, cx + 26, cy + 32
    d.rounded_rectangle([l, t, r, b], radius=6, fill=(30, 41, 59), outline=SLATE, width=2)
    for i, yy in enumerate(range(int(t) + 12, int(b) - 6, 11)):
        ln = r - 10 if i % 2 else r - 18
        col = RED if i == 2 else DIM
        d.line([l + 9, yy, ln, yy], fill=col, width=3)


def chip(d, cx, cy, text, fg, bg):
    bb = d.textbbox((0, 0), text, font=f_chip)
    w = (bb[2] - bb[0]) + 24
    d.rounded_rectangle([cx - w / 2, cy - 15, cx + w / 2, cy + 15], radius=9, fill=bg,
                        outline=fg, width=1)
    ctext(d, cx, cy - 9, text, f_chip, fg)
    return w


def connector(d, x1, x2, y, color, dashed=False):
    if dashed:
        x = x1
        while x < x2 - 8:
            d.line([x, y, min(x + 8, x2 - 8), y], fill=color, width=2)
            x += 16
    else:
        d.line([x1, y, x2 - 8, y], fill=color, width=2)
    d.polygon([(x2, y), (x2 - 9, y - 5), (x2 - 9, y + 5)], fill=color)


# layout
PAGE = (150, 280)
CREW = (430, 280)
GATE = (660, 280)
DB = (850, 280)


def header(img, d):
    # shield logo + wordmark
    sx, sy = 52, 46
    d.polygon(shield_pts(sx, sy, 0.42), fill=GREEN_S)
    d.text((78, 32), "Certior", font=f_word, fill=CREAM)
    d.text((80, 64), "a capability boundary for AI agents", font=f_tag, fill=DIM)
    t = "LangChain  ·  multi-agent  ·  GPT-4o"
    bb = d.textbbox((0, 0), t, font=f_scn)
    d.text((W - 52 - (bb[2] - bb[0]), 50), t, font=f_scn, fill=SLATE)
    d.line([52, 92, W - 52, 92], fill=(28, 38, 58), width=1)


def scene(payload_x=None, payload_kind="attack", gate=None, db="normal",
          banner=None, caption=None, dim_payload=False):
    img = gradient_bg()

    # glow passes
    if gate == "active":
        img = Image.alpha_composite(img.convert("RGBA"),
            glow_layer(lambda g: g.polygon(shield_pts(*GATE), fill=(16, 185, 129, 180)))).convert("RGB")
    if db == "dropped":
        img = Image.alpha_composite(img.convert("RGBA"),
            glow_layer(lambda g: g.ellipse([DB[0]-45, DB[1]-45, DB[0]+45, DB[1]+45], fill=(239,68,68,150)))).convert("RGB")
    if payload_x is not None and not dim_payload:
        col = (239, 68, 68, 130) if payload_kind == "attack" else (52, 211, 153, 130)
        px = payload_x
        img = Image.alpha_composite(img.convert("RGBA"),
            glow_layer(lambda g: g.ellipse([px-30, 232, px+30, 292], fill=col))).convert("RGB")

    d = ImageDraw.Draw(img)
    header(img, d)

    # connectors
    connector(d, PAGE[0] + 60, CREW[0] - 95, 280, (60, 74, 100))
    connector(d, CREW[0] + 95, GATE[0] - 36, 280, (60, 74, 100))
    gate_col = GREEN if gate == "active" else (60, 74, 100)
    connector(d, GATE[0] + 36, DB[0] - 42, 280,
              RED_S if db == "dropped" else gate_col,
              dashed=(gate == "active"))

    # nodes
    page_icon(d, *PAGE)
    ctext(d, PAGE[0], PAGE[1] + 40, "Untrusted web page", f_sub, SLATE)
    node(d, CREW[0], CREW[1], 190, 110, "Agent crew",
         [("Researcher  →  Operator", SLATE), ("LangChain", DIM)], (96, 165, 250))

    # gate / shield
    if gate:
        gc = GREEN if gate == "active" else DIM
        d.polygon(shield_pts(*GATE), outline=gc, width=3,
                  fill=(12, 40, 30) if gate == "active" else None)
        if gate == "active":
            cx, cy = GATE
            d.line([cx - 12, cy, cx - 3, cy + 11], fill=GREEN, width=4)
            d.line([cx - 3, cy + 11, cx + 14, cy - 12], fill=GREEN, width=4)
        ctext(d, GATE[0], GATE[1] + 48, "Certior", f_sub, gc)

    # database
    dbc = RED if db == "dropped" else (GREEN if db == "safe" else SLATE)
    database(d, DB[0], DB[1], dbc, (40, 18, 22) if db == "dropped" else NODE)
    lbl = "DROPPED" if db == "dropped" else ("intact" if db == "safe" else "production DB")
    ctext(d, DB[0], DB[1] + 44, lbl, f_sub, dbc)

    # payload chip traveling
    if payload_x is not None:
        fg, bg = ((RED, (40, 18, 22)) if payload_kind == "attack" else (GREEN, (12, 40, 30)))
        chip(d, payload_x, 262, "DROP TABLE orders;", fg, bg)

    # banner
    if banner:
        text, fg, bg = banner
        by = 446
        d.rounded_rectangle([52, by, W - 52, by + 56], radius=12, fill=bg)
        ctext(d, W / 2, by + 13, text, f_ban, fg)

    # caption
    if caption:
        ctext(d, W / 2, 510, caption[0], f_cap, caption[1])

    return img


frames, durs = [], []
def add(img, ms): frames.append(img); durs.append(ms)

TAG = ("A prompt can’t stop this. A capability check can.", SLATE)

# 1 setup
add(scene(caption=TAG), 1100)
# 2-4 attack travels (no gate)
for x in (300, 430, 560):
    add(scene(payload_x=x, caption=TAG), 650)
# 5 reaches DB unguarded
add(scene(payload_x=700, caption=("WITHOUT CERTIOR", RED)), 500)
# 6 dropped
add(scene(db="dropped", banner=("DATABASE  DROPPED", RED, (46, 16, 20)),
          caption=("a web page just dropped your production database", RED)), 2300)
# 7 the turn: shield slides in
add(scene(gate="idle", caption=("…now turn Certior on", GREEN)), 700)
# 8-9 attack travels into the shield
add(scene(payload_x=520, gate="active", caption=("WITH CERTIOR", GREEN)), 650)
add(scene(payload_x=600, gate="active", caption=("WITH CERTIOR", GREEN)), 650)
# 10 blocked at the gate, db safe
add(scene(payload_x=612, gate="active", db="safe",
          banner=("CertiorBlocked  ·  needs db:admin", GREEN, (10, 34, 26)),
          caption=("the agent holds db:read — the drop never runs", GREEN)), 2600)

master = max(frames, key=lambda im: len(im.getcolors(1 << 24) or [1] * 999)).convert(
    "P", palette=Image.ADAPTIVE, colors=128)
fp = [f.quantize(palette=master, dither=Image.NONE) for f in frames]
fp[0].save(OUT, save_all=True, append_images=fp[1:], duration=durs, loop=0,
           disposal=2, optimize=True)
print("wrote", OUT, "frames", len(frames), "size", os.path.getsize(OUT) // 1024, "KB")
