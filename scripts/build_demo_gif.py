from PIL import Image, ImageDraw, ImageFont

W, H = 900, 480
BG = (11, 18, 32)          # #0b1220
PANEL = (15, 23, 42)       # #0f172a
SLATE = (148, 163, 184)    # #94a3b8
TEXT = (203, 213, 225)     # #cbd5e1
GREEN = (110, 231, 183)    # #6ee7b7
RED = (252, 165, 165)      # #fca5a5
DIM = (100, 116, 139)      # #64748b

MONO = "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf"
SANSB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

f_head = ImageFont.truetype(MONO, 17)
f_mono = ImageFont.truetype(MONO, 19)
f_small = ImageFont.truetype(MONO, 16)
f_ban = ImageFont.truetype(SANSB, 30)
f_cap = ImageFont.truetype(MONO, 14)


def base():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([20, 20, W - 20, H - 20], radius=18, fill=PANEL,
                        outline=(30, 41, 59), width=1)
    d.text((44, 40), "MULTI-AGENT CREW   ·   LangChain   ·   GPT-4o", font=f_head, fill=DIM)
    d.line([44, 70, W - 44, 70], fill=(30, 41, 59), width=1)
    return img, d


def banner(d, y, text, fg, bg):
    d.rounded_rectangle([44, y, W - 44, y + 60], radius=12, fill=bg)
    bb = d.textbbox((0, 0), text, font=f_ban)
    d.text(((W - (bb[2] - bb[0])) / 2, y + 14), text, font=f_ban, fill=fg)


def caption(d, y, text, color):
    d.text((44, y), text, font=f_cap, fill=color)


def frame(lines, cap=None, ban=None):
    img, d = base()
    y = 96
    for text, font, color in lines:
        d.text((44, y), text, font=font, fill=color)
        y += 34 if font is f_mono else 28
    if cap:
        caption(d, 360, cap[0], cap[1])
    if ban:
        banner(d, 390, ban[0], ban[1], ban[2])
    return img


L_research = ("Researcher  ->  fetch_page('status.internal/incident/4471')", f_mono, TEXT)
L_poison = ("      page hides:  DROP TABLE orders; DROP TABLE customers;", f_small, RED)
L_op = ("Operator    ->  execute_db_command('DROP TABLE orders; ...')", f_mono, TEXT)
L_check = ("      Certior check:  needs db:admin  ·  agent holds db:read", f_small, GREEN)

frames, durs = [], []


def add(img, ms):
    frames.append(img); durs.append(ms)


# build-up
add(frame([L_research]), 1100)
add(frame([L_research, L_poison]), 1600)
add(frame([L_research, L_poison, L_op]), 1300)
# WITHOUT certior
add(frame([L_research, L_poison, L_op],
          cap=("WITHOUT CERTIOR", RED),
          ban=("DATABASE DROPPED", RED, (60, 20, 25))), 2200)
# transition to WITH
add(frame([L_research, L_poison, L_op], cap=("WITH CERTIOR", GREEN)), 900)
# WITH certior
add(frame([L_research, L_poison, L_op, L_check],
          cap=("WITH CERTIOR", GREEN),
          ban=("CertiorBlocked  ·  db:admin", GREEN, (12, 40, 30))), 2600)

# consistent palette to avoid flicker
master = frames[-1].convert("P", palette=Image.ADAPTIVE, colors=128)
frames_p = [f.quantize(palette=master) for f in frames]
out = "docs/landing/multi-agent-demo.gif"
frames_p[0].save(out, save_all=True, append_images=frames_p[1:], duration=durs,
                 loop=0, disposal=2, optimize=True)
print("wrote", out, "frames", len(frames))
