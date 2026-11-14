"""Build the presentation deck, part 1 (attack investigation), as one self-contained HTML file.

Run from the repository root:  python slides/build_deck.py
Needs data/raw/dns.log (Canvas download) and data/labels.csv. Every number and every chart on the
slides is computed here from those two files, so the deck cannot drift from the data.
Output: slides/Group 3 Part 1 Attack investigation.html (open in a browser, print to PDF to hand in).
"""
from __future__ import annotations

import base64
import html
import math
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path(__file__).resolve().parent / "assets"
OUT = Path(__file__).resolve().parent / "Group 3 Part 1 Attack investigation.html"

BURST_SPLIT = pd.Timestamp("2023-01-07 18:30:00")
_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")
# first character of a tunnel name = iodine command (same mapping as src/prepare.py)
LANE_BY_PREFIX = {"v": 0, "l": 0, "n": 0, "y": 0, "z": 0, "s": 0, "o": 0, "r": 1, "p": 2, "1": 3}


# ---------------------------------------------------------------- data
def load() -> pd.DataFrame:
    log = ROOT / "data" / "raw" / "dns.log"
    with open(log, encoding="latin-1") as f:
        cols = next(line for line in f if line.startswith("#fields")).rstrip("\n").split("\t")[1:]
    df = pd.read_csv(log, sep="\t", comment="#", names=cols, na_values=["-"],
                     keep_default_na=False, encoding="latin-1")
    df.index.name = "row_id"
    df = df.join(pd.read_csv(ROOT / "data" / "labels.csv", index_col="row_id")).reset_index()
    # Zeek writes non-printable bytes as \xNN; turn them back so one character is one wire byte
    df["name"] = df["query"].map(lambda q: _ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), q))
    df["name_bytes"] = df["name"].str.len()

    def parent(name: str) -> str:
        labels = name.rstrip(".").lower().split(".")
        two = ".".join(labels[-2:])
        return ".".join(labels[-3:]) if two in ("co.uk", "com.au", "co.jp") else two

    df["parent"] = df["name"].map(parent)
    df["tunnel"] = df["label"] == "tunnel"
    df["dt"] = pd.to_datetime(df["ts"], unit="s")
    return df.sort_values("ts").reset_index(drop=True)


def facts(df: pd.DataFrame) -> dict:
    minutes = pd.date_range(df["dt"].min().floor("min"), df["dt"].max().floor("min"), freq="min")
    per_min = (df.assign(m=df["dt"].dt.floor("min")).groupby(["m", "tunnel"]).size()
               .unstack(fill_value=0).reindex(minutes, fill_value=0))
    uniq = (df.groupby("parent")["name"].nunique().sort_values(ascending=False))
    b1 = df[df["tunnel"] & (df["dt"] < BURST_SPLIT)].copy()
    b2 = df[df["tunnel"] & (df["dt"] >= BURST_SPLIT)]
    b1["s"] = b1["ts"] - b1["ts"].min()
    b1["lane"] = b1["name"].str[0].map(LANE_BY_PREFIX)
    if b1["lane"].isna().any():
        raise ValueError("tunnel query with an unknown first character")
    data = b1[b1["lane"] == 3]
    f = {
        "rows": len(df),
        "benign": int((~df["tunnel"]).sum()),
        "minutes": minutes,
        "per_min_benign": per_min[False].tolist(),
        "per_min_tunnel": per_min[True].tolist(),
        "peak_benign": int(per_min[False].max()),
        "peak_benign_at": per_min[False].idxmax(),
        "uniq_top": [(p, int(u)) for p, u in uniq.head(5).items()],
        "longest_tunnel": int(df[df["tunnel"]]["name_bytes"].max()),
        "longest_benign": int(df[~df["tunnel"]]["name_bytes"].max()),
        "session": b1,
        "session_n": len(b1),
        "session_s": float(b1["s"].max()),
        "lane_counts": b1["lane"].value_counts().sort_index().astype(int).tolist(),
        "call_from": float(data["s"].min()),
        "call_to": float(data["s"].max()),
        "b1_start": b1["dt"].min(),
        "b1_end": b1["dt"].max(),
        "b2_start": b2["dt"].min(),
        "replay_identical": bool((b1["name"].values == b2["name"].values).all()),
        "setup_ms": float(b1[(b1["lane"] == 0) & (b1["s"] < 1)]["s"].max() * 1000),
        "probe_end": float(b1[b1["lane"] == 1]["s"].max()),
        "setup_early": int(((b1["lane"] == 0) & (b1["s"] < 1)).sum()),
    }
    # guards: the slide text quotes these, so fail loudly if the data ever disagrees
    assert f["rows"] == 3645 and f["session_n"] == 222 and len(b2) == 222, "row counts changed"
    assert f["replay_identical"], "burst 2 is no longer an exact replay"
    assert f["uniq_top"][0] == ("pirate.sea", 222) and f["uniq_top"][1] == ("yahoo.com", 35)
    assert f["longest_tunnel"] == 252 and f["longest_benign"] == 103 and f["peak_benign"] == 598
    assert f["lane_counts"] == [12, 13, 173, 24], f["lane_counts"]
    return f


# ---------------------------------------------------------------- figures (inline SVG, 1 unit = 1 stage px)
def fig_volume(f: dict) -> str:
    """Slide 2: stacked queries per minute. Tunnel share is grey until the reveal step."""
    w, h, x0, x1, base, top, ymax = 1144, 372, 64, 1136, 318, 28, 700
    n = len(f["minutes"])
    step = (x1 - x0) / n
    sy = (base - top) / ymax
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="DNS queries per minute, benign and tunnel">']
    for v in (0, 200, 400, 600):
        y = base - v * sy
        out.append(f'<line class="grid" x1="{x0}" x2="{x1}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text class="ax" x="{x0 - 12}" y="{y + 6:.1f}" text-anchor="end">{v}</text>')
    for i, (m, b, t) in enumerate(zip(f["minutes"], f["per_min_benign"], f["per_min_tunnel"])):
        if b + t == 0:
            continue
        x = x0 + i * step + (step - 8) / 2
        hb, ht = b * sy, t * sy
        seg = f'<rect class="bn" x="{x:.1f}" y="{base - hb:.1f}" width="8" height="{hb:.1f}"/>' if b else ""
        if t:
            seg += f'<rect class="tn" x="{x:.1f}" y="{base - hb - ht:.1f}" width="8" height="{ht:.1f}"/>'
        out.append(f'<g class="grow-y" style="animation-delay:{i * 8}ms">{seg}</g>')
    for label in ("17:35", "18:00", "18:30", "19:00"):
        i = (pd.Timestamp(f"2023-01-07 {label}") - f["minutes"][0]) // pd.Timedelta(minutes=1)
        out.append(f'<text class="ax" x="{x0 + i * step + step / 2:.1f}" y="{base + 30}" '
                   f'text-anchor="{"start" if i == 0 else "middle"}">{label}</text>')
    # reveal annotations, anchored to the first minute of each burst
    for start, title, sub in ((f["b1_start"], "burst 1", f'{f["session_n"]} queries in 25 seconds'),
                              (f["b2_start"], "burst 2", "inside the busiest normal minute")):
        i = (start.floor("min") - f["minutes"][0]) // pd.Timedelta(minutes=1)
        tot = (f["per_min_benign"][i] + f["per_min_tunnel"][i]) * sy
        x = x0 + i * step
        y = max(base - tot - 34, 52)
        out.append(f'<g class="st1"><text class="an-t" x="{x - 10:.1f}" y="{y:.1f}" text-anchor="end">'
                   f'{start:%H:%M} · {title}</text><text class="an-s" x="{x - 10:.1f}" y="{y + 25:.1f}" '
                   f'text-anchor="end">{sub}</text></g>')
    out.append("</svg>")
    return "".join(out)


def fig_unique(f: dict) -> str:
    """Slide 4: unique names per parent domain, horizontal bars grown from the axis."""
    w, h, ax, maxw, pitch, y0 = 640, 384, 176, 360, 68, 46
    top = f["uniq_top"][0][1]
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="Unique query names per parent domain">',
           '<text class="ax" x="0" y="20">Unique query names per parent domain</text>']
    for i, (dom, u) in enumerate(f["uniq_top"]):
        y = y0 + i * pitch
        bw = maxw * u / top
        hot = " hot" if i == 0 else ""
        out.append(f'<text class="bar-l{hot}" x="0" y="{y + 25}">{html.escape(dom)}</text>'
                   f'<rect class="bar grow-x{hot}" data-v="{u}" data-max="{top}" x="{ax}" y="{y}" '
                   f'width="{bw:.1f}" height="36" rx="4" style="animation-delay:{i * 110}ms"/>'
                   f'<text class="bar-v count{hot}" data-to="{u}" x="{ax + bw + 14:.1f}" y="{y + 28}">{u}</text>')
    out.append(f'<line class="axis" x1="{ax}" x2="{ax}" y1="{y0 - 10}" y2="{y0 + 5 * pitch - 22}"/></svg>')
    return "".join(out)


def fig_session(f: dict) -> str:
    """Slide 6: the 222 queries of one session on a 25 second rail, one lane per kind of query."""
    w, h, lx, x0, x1 = 1144, 292, 236, 250, 1124
    names = ["Set-up", "Size tests", "Pings", "Data"]
    span = 25.0
    sx = (x1 - x0) / span
    tops = [10, 64, 118, 172]
    axis_y = 236
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="Timeline of the tunnel session by kind of query">']
    # the voice call: from the first to the last data query
    cx0, cx1 = x0 + f["call_from"] * sx, x0 + f["call_to"] * sx
    for name, n, y in zip(names, f["lane_counts"], tops):
        out.append(f'<rect class="lane" x="{lx}" y="{y}" width="{w - lx}" height="44" rx="8"/>'
                   f'<text class="lane-l" x="0" y="{y + 29}">{name}</text>'
                   f'<text class="lane-n" x="{lx - 18}" y="{y + 29}" text-anchor="end">{n}</text>')
    out.append(f'<rect class="call" x="{cx0 - 6:.1f}" y="{tops[2] - 6}" width="{cx1 - cx0 + 12:.1f}" '
               f'height="{tops[3] + 44 + 6 - tops[2] + 6}" rx="8"/>')
    for s, lane in zip(f["session"]["s"], f["session"]["lane"].astype(int)):
        x = x0 + s * sx
        delay = 1200 + s / span * 2500
        out.append(f'<rect class="tick" x="{x - 1:.1f}" y="{tops[lane] + 8}" width="2" height="28" '
                   f'style="animation-delay:{delay:.0f}ms"/>')
    setup_ms = math.ceil(f["setup_ms"] / 10) * 10
    out.append(f'<text class="an-s" x="{x0 + 16}" y="{tops[0] + 29}">{f["setup_early"]} queries in the first '
               f'{setup_ms} ms</text>')
    out.append(f'<text class="an-s" x="{x0 + f["probe_end"] * sx + 16:.1f}" y="{tops[1] + 29}">'
               f'{f["probe_end"]:.0f} s lost on answers that never arrive</text>')
    out.append(f'<line class="rail" pathLength="1" x1="{x0}" x2="{x1}" y1="{axis_y}" y2="{axis_y}"/>')
    out.append(f'<line class="rail-call" x1="{cx0:.1f}" x2="{cx1:.1f}" y1="{axis_y}" y2="{axis_y}"/>')
    out.append(f'<text class="ax" x="{x0}" y="{axis_y + 32}">{f["b1_start"]:%H:%M:%S}</text>'
               f'<text class="ax" x="{x1}" y="{axis_y + 32}" text-anchor="end">'
               f'{f["b1_start"] + pd.Timedelta(seconds=span):%H:%M:%S}</text>'
               f'<text class="an-t call-l" x="{(cx0 + cx1) / 2:.1f}" y="{axis_y + 32}" text-anchor="middle">'
               f'the voice call, {f["call_to"] - f["call_from"]:.1f} s</text></svg>')
    return "".join(out)


def fig_flow() -> str:
    """Slide 3: client, resolver, attacker's name server, with a payload that travels out and back."""
    w, h = 1144, 200
    nodes = [(0, "Infected client", "10.0.2.30, runs iodine", ""),
             (432, "Trusted resolver", "relays any name it is asked", ""),
             (864, "Attacker's name server", "answers for pirate.sea", " hot")]
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="A DNS query travels from the client through the resolver to the attacker and back">',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
           'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="arr-h"/></marker></defs>']
    for gx in (280, 712):
        out.append(f'<line class="link" x1="{gx + 10}" x2="{gx + 142}" y1="82" y2="82" marker-end="url(#arr)"/>'
                   f'<line class="link" x1="{gx + 142}" x2="{gx + 10}" y1="122" y2="122" marker-end="url(#arr)"/>')
    out.append('<circle class="payload" r="9" cx="0" cy="0"/>')
    for x, title, sub, hot in nodes:
        out.append(f'<g class="node{hot}"><rect x="{x}" y="46" width="280" height="112" rx="14"/>'
                   f'<text class="node-t" x="{x + 24}" y="96">{title}</text>'
                   f'<text class="node-s" x="{x + 24}" y="126">{sub}</text></g>')
    out.append('<text class="an-s" x="572" y="26" text-anchor="middle">out: the data rides inside the query name'
               '</text><text class="an-s" x="572" y="190" text-anchor="middle">back: the data rides inside the '
               'answer</text></svg>')
    return "".join(out)


def fig_shells() -> str:
    """Slide 7: what wraps what. Core first, then the shells outward."""
    shells = [(0, 0, 620, 392, "s-dns", "DNS", "222 queries for names under pirate.sea"),
              (30, 60, 560, 302, "s-iod", "iodine", "compressed, Base128 in the query name"),
              (60, 120, 500, 212, "s-ip", "IPv4", "200 packets, 10.20.30.3 to 10.20.30.1")]
    out = ['<svg class="fig" width="620" height="392" viewBox="0 0 620 392" role="img" '
           'aria-label="A voice call inside IPv4 inside iodine inside DNS">']
    for i, (x, y, w, h, cls, name, sub) in enumerate(shells):
        out.append(f'<g class="shell {cls}" style="animation-delay:{740 - i * 180}ms">'
                   f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{20 - i * 3}"/>'
                   f'<text x="{x + 24}" y="{y + 38}"><tspan class="sh-t">{name}</tspan>'
                   f'<tspan class="sh-s" dx="12">{sub}</tspan></text></g>')
    out.append('<g class="shell s-core" style="animation-delay:200ms"><rect x="90" y="180" width="440" '
               'height="122" rx="11"/><text class="core-t" x="310" y="234" text-anchor="middle">One H.323 '
               'voice call</text><text class="core-s" x="310" y="268" text-anchor="middle">3.4 seconds of audio'
               '</text></g></svg>')
    return "".join(out)


# ---------------------------------------------------------------- page
CSS = r"""
@font-face{font-family:Inter;src:url(data:font/woff2;base64,__FONT__) format('woff2');font-weight:100 900;font-display:block}
:root{--brand:#7E3B34;--red:#C00000;--ink:#2A1D1B;--muted:#6A5A57;--grey:#8F8684;--rule:#E4DAD7;
--tint:#F7F1EF;--tint2:#EFE3E0;--paper:#FFFFFF;--onbrand:#F4E6E3;--panel:#2A1D1B;--onpanel:#D9CBC7;
--mono:Consolas,'Cascadia Mono',Menlo,'DejaVu Sans Mono',monospace;--ease:cubic-bezier(.22,.61,.36,1)}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#191211;overflow:hidden}
body{font-family:Inter,'Segoe UI',Helvetica,Arial,sans-serif;font-optical-sizing:auto;color:var(--ink);
font-size:21px;line-height:1.4;-webkit-font-smoothing:antialiased;cursor:default;user-select:none}
.stage{position:absolute;left:50%;top:50%;width:1280px;height:720px;margin:-360px 0 0 -640px;
background:var(--paper);overflow:hidden;transform-origin:50% 50%}
/* visibility: these two rules are the only ones that set display on a slide */
.slide{display:none;position:absolute;left:0;top:0;width:1280px;height:720px;padding:68px;background:var(--paper)}
.slide.is-active{display:block}
.badge{position:absolute;left:0;top:0;width:64px;height:44px;background:var(--brand);color:#fff;
font-weight:700;font-size:19px;line-height:44px;text-align:center;border-bottom-right-radius:8px}
.eyebrow{font-size:19px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--brand);line-height:1.2}
h1{font-size:56px;line-height:1.06;font-weight:700;letter-spacing:-.035em;margin-top:10px}
h2{font-size:28px;line-height:1.2;font-weight:700;letter-spacing:-.01em}
.body{margin-top:28px;position:relative}
.src{position:absolute;left:68px;right:68px;bottom:68px;font-size:19px;font-weight:500;color:var(--muted);line-height:1.2}
.fig{display:block;overflow:visible}
.fig text{font-family:Inter,'Segoe UI',Helvetica,Arial,sans-serif}
.ax{font-size:19px;font-weight:500;fill:var(--muted)}
.grid{stroke:var(--rule);stroke-width:1}
.axis{stroke:var(--ink);stroke-width:2}
.an-t{font-size:19px;font-weight:700;fill:var(--red)}
.an-s{font-size:19px;font-weight:500;fill:var(--muted)}
.cols{display:flex;gap:64px;align-items:flex-start}
.cols>*{flex:none}
mark{background:none;color:inherit;font-weight:700}

/* title */
.slide.title{padding:0;background:var(--brand);color:#fff}
.t-left{position:absolute;left:0;top:0;width:400px;height:720px;background:#fff}
.t-left img{position:absolute;left:68px;top:306px;width:264px;height:auto}
.t-line{position:absolute;left:400px;top:0;width:8px;height:720px;background:var(--red)}
.t-right{position:absolute;left:408px;top:0;width:872px;height:720px;padding:68px 68px 68px 64px}
.slide.title .eyebrow{color:#fff}
.display{font-size:96px;line-height:1;font-weight:700;letter-spacing:-.035em;margin-top:96px}
.t-sub{font-size:28px;line-height:1.25;font-weight:400;margin-top:32px;color:var(--onbrand)}
.t-meta{position:absolute;left:64px;right:68px;bottom:68px;font-size:19px;line-height:1.5;font-weight:500;color:var(--onbrand)}

/* slide 2 */
.bn{fill:var(--grey)}
.tn{fill:var(--grey);transition:fill .6s var(--ease)}
.note{font-size:21px;margin-top:6px}
/* slide 3 */
.link{stroke:var(--grey);stroke-width:2}
.arr-h{fill:var(--grey)}
.node rect{fill:var(--tint);stroke:var(--rule);stroke-width:1.5}
.node-t{font-size:21px;font-weight:700;fill:var(--ink)}
.node-s{font-size:19px;font-weight:500;fill:var(--muted)}
.node.hot rect{fill:var(--brand);stroke:var(--brand)}
.node.hot .node-t{fill:#fff}
.node.hot .node-s{fill:var(--onbrand)}
.payload{fill:var(--red);opacity:0}
.cards{display:flex;gap:24px;margin-top:22px}
.card{flex:1 1 0;background:var(--tint);border-radius:14px;padding:18px 24px 20px;border-top:4px solid var(--brand)}
.card p{margin-top:6px}
/* slide 4 */
.bar{fill:var(--grey)}
.bar.hot{fill:var(--red)}
.bar-l{font-size:21px;font-weight:500;fill:var(--ink)}
.bar-l.hot{font-weight:700;fill:var(--red)}
.bar-v{font-size:28px;font-weight:700;fill:var(--ink)}
.bar-v.hot{fill:var(--red)}
.points{list-style:none;width:440px}
.points li{position:relative;padding:15px 0 15px 30px;border-bottom:1px solid var(--rule)}
.points li:first-child{padding-top:4px}
.points li:first-child::before{top:13px}
.points li::before{content:"";position:absolute;left:0;top:24px;width:11px;height:11px;border-radius:3px;background:var(--brand)}
.points li:last-child{border-bottom:0}
/* slide 5 */
.panel{width:700px;background:var(--panel);border-radius:14px;padding:22px 24px 24px;color:var(--onpanel)}
.panel .eyebrow{color:var(--onpanel)}
.row{display:flex;gap:18px;font-family:var(--mono);font-size:19px;line-height:1.3;margin-top:16px;white-space:nowrap}
.row .no{color:var(--onpanel);width:36px;flex:none}
.row b{color:#fff;font-weight:700;border-bottom:2px solid var(--red)}
.cap{font-size:19px;font-weight:500;color:var(--muted);margin-top:14px}
.proof{width:380px;list-style:none;counter-reset:p}
.proof li{position:relative;padding:0 0 18px 52px;counter-increment:p}
.proof li::before{content:counter(p);position:absolute;left:0;top:2px;width:34px;height:34px;border-radius:8px;
background:var(--brand);color:#fff;font-weight:700;font-size:19px;line-height:34px;text-align:center}
.proof p{font-size:19px;font-weight:500;color:var(--muted);margin-top:4px;line-height:1.35}
/* slide 6 */
.lane{fill:var(--tint)}
.lane-l{font-size:21px;font-weight:700;fill:var(--ink)}
.lane-n{font-size:21px;font-weight:500;fill:var(--muted)}
.tick{fill:var(--brand)}
.call{fill:var(--tint2)}
.rail{stroke:var(--ink);stroke-width:2;stroke-dasharray:1;stroke-dashoffset:0}
.rail-call{stroke:var(--red);stroke-width:6;stroke-linecap:round}
.callout{background:var(--brand);color:#fff;border-radius:14px;padding:18px 26px;margin-top:20px}
.callout b{font-weight:700}
/* slide 7 */
.shell rect{stroke:var(--rule);stroke-width:1.5}
.s-dns rect{fill:var(--tint)}
.s-iod rect{fill:var(--tint2)}
.s-ip rect{fill:#fff}
.s-core rect{fill:var(--brand);stroke:var(--brand)}
.sh-t{font-size:21px;font-weight:700;fill:var(--ink)}
.sh-s{font-size:19px;font-weight:500;fill:var(--muted)}
.core-t{font-size:28px;font-weight:700;fill:#fff;letter-spacing:-.01em}
.core-s{font-size:19px;font-weight:500;fill:var(--onbrand)}
.verdict{margin-top:20px;border-left:6px solid var(--red);background:var(--tint);border-radius:0 14px 14px 0;padding:14px 22px}
/* slide 8 */
.groups{display:flex;gap:20px}
.grp{font-size:19px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);
border-bottom:3px solid var(--rule);padding-bottom:8px;line-height:1.2}
.strip{display:flex;gap:20px;margin-top:16px}
.stage-c{position:relative;flex:1 1 0;background:var(--tint);border-radius:14px;padding:18px 18px 20px;min-height:232px}
.stage-c + .stage-c::before{content:"";position:absolute;left:-20px;top:36px;width:20px;height:2px;background:var(--grey)}
.stage-c .id{font-size:28px;font-weight:700;letter-spacing:-.01em;line-height:1.2}
.stage-c .nm{font-weight:700;margin-top:6px;min-height:58px;line-height:1.35}
.stage-c .ev{font-size:19px;font-weight:500;color:var(--muted);margin-top:8px;line-height:1.35;min-height:76px}
.stage-c .tag{font-size:19px;font-weight:700;color:var(--brand);margin-top:8px}
.stage-c.hot{background:var(--brand);color:#fff}
.stage-c.hot .ev,.stage-c.hot .tag{color:var(--onbrand)}
.absent{margin-top:20px;border:2px dashed var(--grey);border-radius:14px;padding:14px 22px}
/* slide 9 */
.vs{display:flex;gap:24px}
.vs .side{flex:1 1 0;border-radius:14px;padding:22px 26px 14px;background:var(--tint)}
.vs .side.rec{border-top:6px solid var(--brand);padding-top:16px}
.vs .side.weak{border-top:6px solid var(--grey);padding-top:16px}
.vs .lbl{font-size:19px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-top:4px;line-height:1.2}
.vs ul{list-style:none;margin-top:10px}
.vs li{position:relative;padding:9px 0 9px 26px;border-top:1px solid var(--rule);line-height:1.3}
.vs li::before{content:"";position:absolute;left:0;top:17px;width:11px;height:11px;border-radius:3px;background:var(--brand)}
.vs .weak li::before{background:var(--grey)}

/* motion: the base state of every element is its final state, so print and reduced motion need nothing */
@keyframes rise{from{opacity:0;transform:translateY(16px)}}
@keyframes growY{from{transform:scaleY(0)}}
@keyframes growX{from{transform:scaleX(0)}}
@keyframes draw{from{stroke-dashoffset:1}}
@keyframes pop{from{opacity:0}}
@keyframes shell{from{opacity:0;transform:scale(.94)}}
@keyframes trip{0%{opacity:0;transform:translate(290px,82px)}6%{opacity:1}
46%{transform:translate(1004px,82px)}52%{transform:translate(1004px,122px)}
94%{opacity:1}100%{opacity:0;transform:translate(290px,122px)}}
.slide.is-active .rv{animation:rise .42s var(--ease) backwards;animation-delay:calc(var(--i,0)*50ms)}
.slide.is-active .grow-y{animation:growY .9s var(--ease) backwards;transform-box:fill-box;transform-origin:50% 100%}
.slide.is-active .grow-x{animation:growX .9s var(--ease) backwards;transform-box:fill-box;transform-origin:0 50%}
.slide.is-active .rail{animation:draw 1.2s var(--ease) backwards}
.slide.is-active .tick{animation:pop .2s linear backwards}
.slide.is-active .rail-call,.slide.is-active .call,.slide.is-active .call-l{animation:pop .5s linear 3.4s backwards}
.slide.is-active .shell{animation:shell .5s var(--ease) backwards;transform-box:fill-box;transform-origin:50% 50%}
.slide.is-active .payload{animation:trip 2.8s linear .9s 2}
/* progressive reveal, only where the order is the argument. Gated on script being alive */
.js .st1{opacity:0;transition:opacity .45s var(--ease)}
.js .slide.s1 .st1{opacity:1}
.slide.s1 .tn{fill:var(--red)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media print{
@page{size:1280px 720px;margin:0}
*{animation:none!important;transition:none!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
html,body{height:auto;overflow:visible;background:#fff}
.stage{position:static;margin:0;width:1280px;height:auto;overflow:visible;transform:none!important}
.slide{display:block!important;position:relative;break-after:page;page-break-after:always;overflow:hidden}
.js .st1{opacity:1}
.tn{fill:var(--red)}
}
"""

JS = r"""
(function(){
  document.documentElement.classList.add('js');
  var stage=document.querySelector('.stage'),slides=[].slice.call(document.querySelectorAll('.slide'));
  var cur=0,step=0,reduce=window.matchMedia('(prefers-reduced-motion:reduce)').matches;
  function fit(){var s=Math.min(window.innerWidth/1280,window.innerHeight/720);stage.style.transform='scale('+s+')';}
  function steps(i){return +(slides[i].getAttribute('data-steps')||0);}
  function paint(){
    slides.forEach(function(el,i){
      el.classList.toggle('is-active',i===cur);
      for(var k=1;k<=steps(i);k++){el.classList.toggle('s'+k,i===cur&&k<=step);}
    });
  }
  function count(el){
    var to=+el.getAttribute('data-to'),t0=null,delay=+(el.getAttribute('data-delay')||0);
    if(reduce){el.textContent=to;return;}
    el.textContent='0';
    function tick(t){if(t0===null){t0=t+delay;}var p=Math.min(Math.max((t-t0)/1100,0),1);
      el.textContent=Math.round(to*(1-Math.pow(1-p,3)));if(p<1){requestAnimationFrame(tick);}}
    requestAnimationFrame(tick);
  }
  function go(i,s){
    i=Math.max(0,Math.min(slides.length-1,i));
    var changed=i!==cur||!slides[cur].classList.contains('is-active');
    cur=i;step=Math.max(0,Math.min(steps(cur),s||0));paint();
    if(changed){[].forEach.call(slides[cur].querySelectorAll('.count'),count);}
    sync();
  }
  function sync(){var h='#'+(cur+1)+(step?'.'+step:'');
    if(location.hash!==h){try{history.replaceState(null,'',h);}catch(e){}}}
  function next(){if(step<steps(cur)){step++;paint();sync();}else if(cur<slides.length-1){go(cur+1,0);}}
  function prev(){if(step>0){step--;paint();sync();}else if(cur>0){go(cur-1,steps(cur-1));}}
  function fromHash(){var m=location.hash.slice(1).split('.'),n=parseInt(m[0],10);
    go(isNaN(n)?0:n-1,parseInt(m[1],10)||0);}
  document.addEventListener('keydown',function(e){
    if(e.ctrlKey||e.metaKey||e.altKey){return;}
    var k=e.key;
    if(k==='ArrowRight'||k===' '||k==='PageDown'||k==='Enter'){e.preventDefault();next();}
    else if(k==='ArrowLeft'||k==='PageUp'||k==='Backspace'){e.preventDefault();prev();}
    else if(k==='Home'){e.preventDefault();go(0,0);}
    else if(k==='End'){e.preventDefault();go(slides.length-1,steps(slides.length-1));}
  });
  document.addEventListener('click',next);
  window.addEventListener('hashchange',fromHash);
  window.addEventListener('resize',fit);
  fit();fromHash();
})();
"""


def b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def slide(n: int, eyebrow: str, title: str, body: str, src: str = "", steps: int = 0) -> str:
    attr = f' data-steps="{steps}"' if steps else ""
    source = f'<p class="src">{src}</p>' if src else ""
    return (f'<section class="slide"{attr}><div class="badge">{n:02d}</div>'
            f'<p class="eyebrow rv" style="--i:0">{eyebrow}</p><h1 class="rv" style="--i:1">{title}</h1>'
            f'<div class="body">{body}</div>{source}</section>')


def build() -> str:
    f = facts(load())
    logo = b64(ASSETS / "jads_logo.png")
    ratio = f["uniq_top"][0][1] / f["uniq_top"][1][1]
    s = []

    s.append(f'''<section class="slide title"><div class="t-left"><img alt="JADS" src="data:image/png;base64,{logo}"></div>
<div class="t-line"></div><div class="t-right"><p class="eyebrow rv" style="--i:0">JM2030 Cybersecurity · Group 3</p>
<p class="display rv" style="--i:1">A tunnel<br>hidden in DNS</p>
<p class="t-sub rv" style="--i:2">Case 1: finding, dissecting and detecting<br>a DNS tunnel with Isolation Forest</p>
<p class="t-meta rv" style="--i:3">Gilbert Laanen · Rick de Rijk · Thom Verzantvoort<br>Tycho van Rooij · Samir Sabitli · Yannick Leroy</p></div></section>''')

    s.append(slide(2, "The case", "Can you spot the attack?",
                   fig_volume(f) + f'<p class="note st1">Volume points at the wrong machine: the busiest minute, '
                   f'<mark>{f["peak_benign"]} queries</mark>, is ordinary browsing.</p>',
                   f'DNS queries per minute · {f["rows"]:,} queries in dns.log · 7 January 2023, 17:35 to 19:10 UTC',
                   steps=1))

    s.append(slide(3, "The protocol", "DNS gets out of almost every network",
                   f'<div class="rv" style="--i:2">{fig_flow()}</div><div class="cards">'
                   '<div class="card rv" style="--i:3"><h2>Allowed out</h2><p>DNS leaves almost every network and '
                   'is rarely inspected.</p></div>'
                   '<div class="card rv" style="--i:4"><h2>Relayed for you</h2><p>The resolver passes any name on '
                   'to the server that owns the domain.</p></div>'
                   '<div class="card rv" style="--i:5"><h2>Never cached</h2><p>A repeated name never reaches the '
                   'attacker, so every query needs a new name.</p></div></div>',
                   'In our capture the client reached the tunnel server directly, on the same network segment.'))

    s.append(slide(4, "Discovery", "One domain gives itself away",
                   f'<div class="cols">{fig_unique(f)}<ul class="points">'
                   f'<li class="rv" style="--i:2"><mark>{ratio:.0f} times</mark> more unique names than any other '
                   f'domain.</li>'
                   f'<li class="rv" style="--i:3">Its longest name is <mark>{f["longest_tunnel"]} bytes</mark>. DNS '
                   f'allows 255. The longest normal name is {f["longest_benign"]}.</li>'
                   '<li class="rv" style="--i:4">The only domain asked for <mark>NULL</mark> records.</li>'
                   '<li class="rv" style="--i:5">Every query comes from one host, <mark>10.0.2.30</mark>, which asks '
                   'for nothing else.</li></ul></div>',
                   'Name lengths counted in bytes on the wire, not as Zeek prints them.'))

    s.append(slide(5, "Naming the tool", "The tool is iodine",
                   '<div class="cols" style="gap:64px"><div><div class="panel rv" style="--i:2">'
                   '<p class="eyebrow">Wireshark · dns.qry.type == 10</p>'
                   '<div class="row"><span class="no">489</span><span><b>v</b>aaaakardli.pirate.sea</span></div>'
                   '<div class="row"><span class="no">490</span><span>answer: <b>56 41 43 4b</b> 44 03 c5 e9 01 '
                   '&nbsp;= <b>VACK</b></span></div>'
                   '<div class="row"><span class="no">495</span><span>zi03aA-<b>Aaahhh-Drink-mal-ein-Jägermeister</b>-'
                   '</span></div>'
                   '<div class="row"><span class="no">497</span><span>zi04aA-<b>La-flûte-naïve-française-est-retirée-'
                   'à-Crête</b></span></div></div>'
                   '<p class="cap rv" style="--i:3">Four of the first frames of the session in case1.pcap.</p></div>'
                   '<ol class="proof">'
                   '<li class="rv" style="--i:3"><h2>VACK</h2><p>The first answer is iodine\'s version '
                   'acknowledgement.</p></li>'
                   '<li class="rv" style="--i:4"><h2>Version 00000502</h2><p>Decoded from the first query. It is '
                   'the published protocol version.</p></li>'
                   '<li class="rv" style="--i:5"><h2>Built-in test sentences</h2><p>The German and French strings '
                   'are hard-coded in iodine\'s client.</p></li></ol></div>',
                   'MITRE ATT&amp;CK lists iodine under T1572, Protocol Tunneling.'))

    s.append(slide(6, "Timeline", "The whole session takes 25 seconds",
                   fig_session(f) + '<p class="callout st1"><b>18:50:50, the same 222 queries again.</b> Identical '
                   'byte for byte, down to the login challenge. A replay in the dataset, so one session and not two.</p>',
                   steps=1))

    s.append(slide(7, "The payload", "Inside the tunnel: one voice call",
                   f'<div class="cols" style="gap:56px">{fig_shells()}<div style="width:468px"><ul class="points" '
                   'style="width:468px">'
                   '<li class="rv" style="--i:2">An answering machine picks up. <mark>169 audio frames</mark> come '
                   'down, 2 go up.</li>'
                   '<li class="rv" style="--i:3"><mark>4.5 KB up</mark>, 14.5 KB down. The upload is the call '
                   'set-up.</li>'
                   '<li class="rv" style="--i:4">Each audio frame arrives as the answer to a ping.</li></ul>'
                   '<p class="verdict rv" style="--i:5"><b>No sign of data theft.</b> The same channel could carry '
                   'commands or stolen files.</p></div></div>',
                   'Decoded from case1.pcap with the iodine protocol specification.'))

    def st(tid, name, ev, tag, hot=False, i=0):
        return (f'<div class="stage-c{" hot" if hot else ""} rv" style="--i:{i}"><p class="id">{tid}</p>'
                f'<p class="nm">{name}</p><p class="ev">{ev}</p><p class="tag">{tag}</p></div>')

    s.append(slide(8, "MITRE ATT&amp;CK", "Five techniques form one chain",
                   '<div class="groups rv" style="--i:2"><p class="grp" style="flex:2 1 0">Resource development</p>'
                   '<p class="grp" style="flex:3 1 0;margin-left:8px">Command and control</p></div><div class="strip">'
                   + st("T1588.002", "Obtain a tool", "A public tool, iodine", "Inferred", i=2)
                   + st("T1583.004", "Acquire a server", "iodine server at 10.0.2.20", "Inferred", i=3)
                   + st("T1071.004", "DNS as the channel", "444 NULL queries over UDP 53", "Observed", i=3)
                   + st("T1132.002", "Non-standard encoding", "iodine's own Base32 and Base128", "Observed", i=4)
                   + st("T1572", "Protocol tunnelling", "Whole IP packets inside DNS", "Observed", hot=True, i=4)
                   + '</div><p class="absent rv" style="--i:5"><b>T1041 Exfiltration: not observed.</b> Only 4.5 KB '
                   'went up, all of it call set-up. The channel makes it possible.</p>'))

    s.append(slide(9, "Attack mechanics", "What a tunnel cannot hide",
                   '<div class="vs"><div class="side rec rv" style="--i:2"><h2>Any DNS tunnel shows these</h2>'
                   '<p class="lbl">Hard to change</p><ul>'
                   '<li>Many new names under one domain</li>'
                   '<li>Long, random-looking names</li>'
                   '<li>A steady stream of queries, even when idle</li>'
                   '<li>Answers that carry data</li></ul></div>'
                   '<div class="side weak rv" style="--i:3"><h2>Only this tool, or this lab</h2>'
                   '<p class="lbl">Easy to change</p><ul>'
                   '<li>iodine\'s start-up letters and VACK</li>'
                   '<li>Queries sent straight to the attacker</li>'
                   '<li>One source port, TTL 0, EDNS0</li></ul></div></div>'
                   f'<p class="callout rv" style="--i:4"><b>{f["lane_counts"][2]} of the {f["session_n"]} tunnel '
                   'queries are short pings that look normal on their own.</b> So the detector has to judge the '
                   'domain, not the single query.</p>'))

    page = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Group 3 · A tunnel hidden in DNS</title><style>'
            + CSS.replace("__FONT__", b64(ASSETS / "inter-subset.woff2"))
            + '</style></head><body><main class="stage">' + "\n".join(s)
            + '</main><script>' + JS + '</script></body></html>')
    return page


if __name__ == "__main__":
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT.name}, {OUT.stat().st_size / 1024:.0f} KB")
