import os, math
from PIL import Image, ImageDraw, ImageFont, ImageFilter

W, H = 1080, 560
OUT = "docs/landing/multi-agent-demo.gif"
# game palette
WALL2=(33,26,58); WALL1=(44,35,72); FLOOR=(58,46,87)
INK=(245,239,230); MUTED=(185,174,208); LINE=(65,54,95)
GOLD=(244,162,89); GREEN=(126,217,87); RED=(255,107,107)
AGENT=(226,200,156); EYE=(32,32,58); SHADOW=(14,10,26)

UB="/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf"
UR="/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf"
MB="/usr/share/fonts/truetype/ubuntu/UbuntuMono-B.ttf"
def F(p,s): return ImageFont.truetype(p,s)
f_word=F(UB,30); f_hook=F(UB,29); f_lbl=F(UR,17); f_big=F(UB,46); f_cap=F(UR,21); f_note=F(MB,17)
LOGO=Image.open("/home/pbour/certior-mvp/docs/landing/logo.png").convert("RGBA").resize((46,46),Image.LANCZOS)

def base():
    img=Image.new("RGB",(W,H),WALL2)
    d=ImageDraw.Draw(img)
    # crisp inner panel for clean depth (no soft gradients -> stays neat in GIF)
    d.rounded_rectangle([22,22,W-22,H-22],radius=24,fill=(38,30,66),outline=(60,48,92),width=1)
    img.paste(LOGO,(46,36),LOGO)
    d=ImageDraw.Draw(img)
    d.text((102,42),"Certior",font=f_word,fill=INK)
    return img,d

def ctext(d,cx,y,t,f,fill):
    bb=d.textbbox((0,0),t,font=f); d.text((cx-(bb[2]-bb[0])/2,y),t,font=f,fill=fill)

def glow(img,fn,blur=9):
    L=Image.new("RGBA",img.size,(0,0,0,0)); fn(ImageDraw.Draw(L))
    return Image.alpha_composite(img.convert("RGBA"),L.filter(ImageFilter.GaussianBlur(blur))).convert("RGB")

def pill(d,cx,y,t,f,fg):
    bb=d.textbbox((0,0),t,font=f); w=(bb[2]-bb[0])+22
    d.rounded_rectangle([cx-w/2,y-3,cx+w/2,y+24],radius=999,fill=(0,0,0,90) if False else (22,16,40))
    ctext(d,cx,y,t,f,fg)

def blob(d,cx,cy,color):
    w,h,r=78,74,28; l,t,rr,b=cx-w/2,cy-h/2,cx+w/2,cy+h/2
    d.rounded_rectangle([l,t+9,rr,b+9],radius=r,fill=SHADOW)          # drop shadow
    d.rounded_rectangle([l,t,rr,b],radius=r,fill=color)               # body
    d.rounded_rectangle([l+7,t+5,rr-7,t+22],radius=12,fill=tuple(min(255,c+22) for c in color)) # sheen
    for ex in (cx-15,cx+15):                                          # eyes
        d.ellipse([ex-7,cy-10,ex+6,cy+6],fill=EYE)
        d.ellipse([ex+1,cy-7,ex+5,cy-3],fill=(255,255,255))

def note(d,cx,cy):
    w,h=86,96; l,t,r,b=cx-w/2,cy-h/2,cx+w/2,cy+h/2
    d.rounded_rectangle([l,t+8,r,b+8],radius=12,fill=SHADOW)
    d.rounded_rectangle([l,t,r,b],radius=12,fill=(247,238,224),outline=RED,width=3)
    d.polygon([(r-16,t),(r,t),(r,t+16)],fill=(206,196,176))
    for i,yy in enumerate(range(int(t)+22,int(b)-10,13)):
        col=RED if i==2 else (150,140,125); d.line([l+12,yy,(r-14 if i%2 else r-24),yy],fill=col,width=3)

def shield(d,cx,cy,active):
    s=1.0; pts=[(cx,cy-44*s),(cx+34*s,cy-30*s),(cx+34*s,cy+9*s),(cx,cy+46*s),(cx-34*s,cy+9*s),(cx-34*s,cy-30*s)]
    d.polygon([(p[0],p[1]+8) for p in pts],fill=SHADOW)
    col=GREEN if active else GOLD
    d.polygon(pts,fill=(28,52,30) if active else (60,46,30),outline=col,width=4)
    if active:
        d.line([cx-14,cy,cx-3,cy+13],fill=GREEN,width=6); d.line([cx-3,cy+13,cx+16,cy-13],fill=GREEN,width=6)

def database(d,cx,cy,state):
    w,h,e=86,80,22; l,r,t,b=cx-w/2,cx+w/2,cy-h/2,cy+h/2
    col=RED if state=="dropped" else (GREEN if state=="safe" else GOLD)
    fill=(70,28,30) if state=="dropped" else ((26,52,30) if state=="safe" else (52,40,26))
    d.rounded_rectangle([l,b-e+9,r,b+9],radius=8,fill=SHADOW)
    d.rectangle([l,t+e/2,r,b-e/2],fill=fill)
    d.line([l,t+e/2,l,b-e/2],fill=col,width=3); d.line([r,t+e/2,r,b-e/2],fill=col,width=3)
    d.arc([l,b-e,r,b],0,180,fill=col,width=3)
    for yy in (cy-6,cy+16): d.ellipse([l,yy,r,yy+e],outline=col,width=2)
    d.ellipse([l,t,r,t+e],fill=fill,outline=col,width=3)

def arrow(d,x1,x2,y,color,dash=False):
    if dash:
        x=x1
        while x<x2-12: d.line([x,y,min(x+10,x2-12),y],fill=color,width=4); x+=20
    else: d.line([x1,y,x2-12,y],fill=color,width=4)
    d.polygon([(x2,y),(x2-13,y-7),(x2-13,y+7)],fill=color)

ROW=250
WEB=(165,ROW); A1=(388,ROW); A2=(476,ROW); CREW=(432,ROW); GATE=(720,ROW); DB=(940,ROW)

def scene(phase, db="normal", big=None, cap=None, hook=None, bob=0.0, chip=None):
    img,_=base(); gate=phase=="with"
    if gate=="with" or phase=="with":
        img=glow(img,lambda g:g.polygon([(GATE[0],ROW-44),(GATE[0]+34,ROW-30),(GATE[0]+34,ROW+9),(GATE[0],ROW+46),(GATE[0]-34,ROW+9),(GATE[0]-34,ROW-30)],fill=(126,217,87,150)))
    if db=="dropped":
        img=glow(img,lambda g:g.ellipse([DB[0]-55,ROW-55,DB[0]+55,ROW+55],fill=(255,107,107,140)))
    d=ImageDraw.Draw(img)
    # connectors
    arrow(d,WEB[0]+52,CREW[0]-100,ROW,LINE)
    if gate:
        arrow(d,CREW[0]+100,GATE[0]-46,ROW,LINE)
        arrow(d,GATE[0]+46,DB[0]-54,ROW,GREEN if db=="safe" else LINE,dash=True)
    else:
        arrow(d,CREW[0]+100,DB[0]-54,ROW,RED if db=="dropped" else LINE)
    # actors
    note(d,*WEB); pill(d,WEB[0],ROW+58,"web page",f_lbl,MUTED)
    blob(d,A1[0],A1[1]+bob,AGENT); blob(d,A2[0],A2[1]-bob,AGENT); pill(d,CREW[0],ROW+58,"2 AI agents",f_lbl,MUTED)
    if gate: shield(d,*GATE,True); pill(d,GATE[0],ROW+62,"Certior",f_lbl,GREEN)
    database(d,*DB,db); pill(d,DB[0],ROW+56,"database",f_lbl,RED if db=="dropped" else (GREEN if db=="safe" else MUTED))
    if chip is not None:
        cx,ccol=chip; txt="DROP TABLE"; bb=d.textbbox((0,0),txt,font=f_note); w=(bb[2]-bb[0])+22; cy=ROW-60
        d.rounded_rectangle([cx-w/2,cy-15,cx+w/2,cy+15],radius=10,fill=(58,20,24),outline=ccol,width=2)
        ctext(d,cx,cy-9,txt,f_note,ccol)
    if hook: ctext(d,W/2,118,hook[0],f_hook,INK)
    if big: ctext(d,W/2,418,big[0],f_big,big[1])
    if cap: ctext(d,W/2,482,cap[0],f_cap,cap[1])
    return img

frames,durs=[],[]
def add(im,ms): frames.append(im); durs.append(ms)

HOOK=("A web page tells two AI agents to wipe the database.",INK)
def bobv(i): return math.sin(i*0.85)*4.0
i=0
# WITHOUT — establish with gentle bob
for _ in range(3):
    add(scene("without",bob=bobv(i),hook=HOOK,cap=("with no boundary, they just do it…",MUTED)),300); i+=1
# malicious chip slides web -> database
for x in range(WEB[0]+30, DB[0]-30, 72):
    add(scene("without",bob=bobv(i),chip=(x,RED),cap=("WITHOUT CERTIOR",RED)),120); i+=1
# dropped (hold)
add(scene("without",bob=bobv(i),db="dropped",big=("Database dropped",RED),cap=("the web page hijacked the agents",RED)),2300); i+=1
# WITH — shield appears
for _ in range(2):
    add(scene("with",bob=bobv(i),cap=("now put Certior between the agents and the data",GREEN)),450); i+=1
# chip slides toward the shield and stops
for x in range(CREW[0]+90, GATE[0]-110, 42):
    add(scene("with",bob=bobv(i),chip=(x,RED),cap=("WITH CERTIOR",GREEN)),140); i+=1
# blocked (hold)
add(scene("with",bob=bobv(i),chip=(GATE[0]-112,RED),db="safe",big=("Blocked",GREEN),cap=("the agents only have db:read — the drop never runs",GREEN)),2500)

# build ONE palette from ALL frames so reds and greens both survive quantization
montage=Image.new("RGB",(W,H*len(frames)))
for i,f in enumerate(frames): montage.paste(f,(0,i*H))
master=montage.convert("P",palette=Image.ADAPTIVE,colors=256)
fp=[f.quantize(palette=master,dither=Image.NONE) for f in frames]
fp[0].save(OUT,save_all=True,append_images=fp[1:],duration=durs,loop=0,disposal=2,optimize=True)
print("wrote",OUT,"frames",len(frames),"size",os.path.getsize(OUT)//1024,"KB")
