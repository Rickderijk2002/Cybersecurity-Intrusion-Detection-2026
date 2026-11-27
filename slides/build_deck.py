"""Build the presentation deck (attack investigation, detection, evaluation, mitigation) as one self-contained HTML file.

Run from the repository root:  python slides/build_deck.py
Slides 2 to 9 (attack investigation) are computed here from data/raw/dns.log (Canvas download) and
data/labels.csv. Slides 10 to 20 (detector) read slides/results.json, which `python slides/compute_results.py`
writes from src/ and checks against the report's tables. Both parts assert the numbers they quote, so the
deck fails loudly instead of drifting from the data.
Output: slides/Group 3 Presentation.html (open in a browser, print to PDF to hand in).
The earlier part 1 only deck was removed on 2026-11-23; it is in git history (commit 321e26c).
"""
from __future__ import annotations

import base64
import html
import json
import math
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path(__file__).resolve().parent / "assets"
OUT = Path(__file__).resolve().parent / "Group 3 Presentation.html"
RESULTS = Path(__file__).resolve().parent / "results.json"

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


# ---------------------------------------------------------------- detector figures (slides 10 to 19)
# Numbers taken from the report and not recomputed here: the tuned comparison runs live in notebook 05.
# Report Table 3.3 (300 s window, val_max). Local Outlier Factor and One-Class SVM: one configuration each.
ALT = [("Isolation Forest", 0.9865, 0.0021, 1.9), ("Local Outlier Factor", 0.9279, 0.0068, 10.0),
       ("One-Class SVM", 0.9820, 0.0746, 9.0)]
SLOW_TUNNEL_RECALL = 98.3      # report 3.4: tunnel 60 times slower, chosen configuration
STRESS_INCIDENTS = (1.8, 9.6)  # report 3.4.2 and notebook 05 cell 17: nine extra normal clients, first five seeds
QUIET_TRAINING_FPR = (4.79, 25.90)  # report 3.3: 60 s window, all training rows against 244 quiet ones


def load_results() -> dict:
    r = json.loads(RESULTS.read_text(encoding="utf-8"))
    rows = r["test_rows"]
    assert r["split"] == {"fit": 1274, "val": 318, "test": 1831, "test_tunnel": 222}
    assert len(rows) == 1831 and sum(x[2] for x in rows) == 222
    assert r["missed_same_every_seed"] and r["missed_by_seed"] == [3] * 10
    tun = [x for x in rows if x[2] == 1]
    assert [x[3] for x in tun[:4]] == [0, 0, 0, 1], "the first alert is no longer the fourth tunnel query"
    return r


def fig_split(r: dict) -> str:
    """Slide 11: the time split. Segment widths are proportional to the number of queries."""
    s = r["split"]
    total = s["fit"] + s["val"] + s["test"]
    w, h, base_y, bh = 1144, 196, 74, 64
    sc = w / total
    xs = [0, s["fit"] * sc, (s["fit"] + s["val"]) * sc]
    ws = [s["fit"] * sc, s["val"] * sc, s["test"] * sc]
    names = [("Fit the forest", "start"), ("Threshold", "middle"), ("Evaluate", "start")]
    inner = [f'{s["fit"]:,} normal queries', f'{s["val"]}', f'{s["test"]:,} queries']
    inner_x = [xs[0] + ws[0] / 2, xs[1] + ws[1] / 2, xs[2] + 24]
    inner_a = ["middle", "middle", "start"]
    cls = ["seg-fit", "seg-val", "seg-test"]
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="Chronological split: {s["fit"]} to fit, {s["val"]} for the threshold, {s["test"]} to test">']
    for i in range(3):
        d = i * 140
        lab_x = xs[i] + {0: 0, 1: ws[i] / 2, 2: 14}[i]
        out.append(f'<g class="grow-x" style="animation-delay:{d}ms"><rect class="{cls[i]}" x="{xs[i]:.1f}" '
                   f'y="{base_y}" width="{ws[i]:.1f}" height="{bh}" rx="6"/></g>'
                   f'<text class="sp-t rv" style="--i:{i + 2}" x="{lab_x:.1f}" y="{base_y - 34}" '
                   f'text-anchor="{names[i][1]}">{names[i][0]}</text>'
                   f'<line class="sp-br" x1="{xs[i] + 2:.1f}" x2="{xs[i] + ws[i] - 2:.1f}" y1="{base_y - 18}" '
                   f'y2="{base_y - 18}"/>'
                   f'<text class="sp-n rv" style="--i:{i + 2}" x="{inner_x[i]:.1f}" y="{base_y + 41}" '
                   f'text-anchor="{inner_a[i]}">{inner[i]}</text>')
    # the tunnel session inside the test period (seed 0 clock, seconds from the first test query)
    rows = r["test_rows"]
    span = max(x[0] for x in rows)
    tun = [x for x in rows if x[2] == 1]
    a, b = tun[0][0], tun[-1][0]
    ta, tb = xs[2] + a / span * ws[2], xs[2] + b / span * ws[2]
    out.append(f'<rect class="seg-tun" x="{ta - 3:.1f}" y="{base_y}" width="{max(tb - ta, 0) + 6:.1f}" '
               f'height="{bh}" rx="3"/>')
    out.append(f'<line class="sp-lead" x1="{(ta + tb) / 2:.1f}" x2="{(ta + tb) / 2:.1f}" y1="{base_y + bh}" '
               f'y2="{base_y + bh + 24}"/>')
    out.append(f'<text class="an-t sp-lead-t" x="{(ta + tb) / 2 - 12:.1f}" y="{base_y + bh + 32}" text-anchor="end">'
               f'222 tunnel queries in {b - a:.0f} seconds</text>')
    out.append(f'<text class="ax" x="0" y="{h - 4}">time, oldest first</text>'
               f'<text class="ax" x="{w}" y="{h - 4}" text-anchor="end">newest</text></svg>')
    return "".join(out)


def fig_scores(r: dict) -> str:
    """Slide 12: anomaly scores of the test queries, stacked histogram, tunnel red after the reveal."""
    rows, thr = r["test_rows"], r["threshold"]
    lo, hi, step = 0.38, 0.80, 0.02
    nb = round((hi - lo) / step)
    ben, tun = [0] * nb, [0] * nb
    for _, sc, y, _, _ in rows:
        i = min(int((sc - lo) / step), nb - 1)
        (tun if y else ben)[i] += 1
    assert sum(ben) == 1609 and sum(tun) == 222, "scores fall outside the histogram range"
    w, h, x0, x1, base, top, ymax = 1144, 336, 64, 1136, 262, 24, 220
    sy = (base - top) / ymax

    def xx(v):
        return x0 + (v - lo) / (hi - lo) * (x1 - x0)

    bw = (x1 - x0) / nb
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="Anomaly scores of normal and tunnel queries in the test period">']
    for v in (0, 50, 100, 150, 200):
        y = base - v * sy
        out.append(f'<line class="grid" x1="{x0}" x2="{x1}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text class="ax" x="{x0 - 12}" y="{y + 6:.1f}" text-anchor="end">{v}</text>')
    for i in range(nb):
        if ben[i] + tun[i] == 0:
            continue
        x = x0 + i * bw + 3
        seg = ""
        if ben[i]:
            seg += f'<rect class="bn" x="{x:.1f}" y="{base - ben[i] * sy:.1f}" width="{bw - 6:.1f}" height="{ben[i] * sy:.1f}"/>'
        if tun[i]:
            seg += (f'<rect class="tn" x="{x:.1f}" y="{base - (ben[i] + tun[i]) * sy:.1f}" width="{bw - 6:.1f}" '
                    f'height="{tun[i] * sy:.1f}"/>')
        out.append(f'<g class="grow-y" style="animation-delay:{i * 35}ms">{seg}</g>')
    for v in (0.4, 0.5, 0.6, 0.7, 0.8):
        out.append(f'<text class="ax" x="{xx(v):.1f}" y="{base + 30}" text-anchor="middle">{v:.1f}</text>')
    out.append(f'<text class="ax" x="{x1}" y="{base + 64}" text-anchor="end">anomaly score, higher means stranger</text>')
    tx = xx(thr)
    out.append(f'<g class="st1"><line class="thr" x1="{tx:.1f}" x2="{tx:.1f}" y1="{top - 4}" y2="{base}"/>'
               f'<text class="an-t" x="{tx - 12:.1f}" y="{top + 12}" text-anchor="end">threshold {thr:.2f}</text>'
               f'<text class="an-t" x="{x1}" y="{top + 12}" text-anchor="end">222 tunnel queries</text>'
               f'<text class="an-s" x="{x0 + 8}" y="{top + 12}">1,609 normal queries</text></g></svg>')
    return "".join(out)


def fig_timeline(r: dict) -> str:
    """Slide 16: every test query as a dot (time against score), the threshold, and the errors named."""
    rows, thr = r["test_rows"], r["threshold"]
    w, h, x0, x1, base, top = 1144, 272, 70, 1136, 214, 58
    lo, hi = 0.35, 0.82
    span = max(x[0] for x in rows)

    def px(t):
        return x0 + t / span * (x1 - x0)

    def py(v):
        return base - (v - lo) / (hi - lo) * (base - top)

    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="Anomaly score of every test query over the test period">']
    for v in (0.4, 0.5, 0.6, 0.7, 0.8):
        out.append(f'<line class="grid" x1="{x0}" x2="{x1}" y1="{py(v):.1f}" y2="{py(v):.1f}"/>'
                   f'<text class="ax" x="{x0 - 12}" y="{py(v) + 6:.1f}" text-anchor="end">{v:.1f}</text>')
    for m in (0, 10, 20, 30):
        out.append(f'<text class="ax" x="{px(m * 60):.1f}" y="{base + 30}" '
                   f'text-anchor="{"start" if m == 0 else "middle"}">{m} min</text>')
    seen, benign, tunnel = set(), [], []
    for t, sc, y, a, par in rows:
        key = (round(px(t)), round(py(sc)), y)
        if key in seen:
            continue
        seen.add(key)
        (tunnel if y else benign).append((px(t), py(sc)))
    out.append('<g class="wipe">' + "".join(f'<circle class="dot" cx="{x:.1f}" cy="{y:.1f}" r="3"/>' for x, y in benign)
               + "".join(f'<circle class="dot t" cx="{x:.1f}" cy="{y:.1f}" r="3.5"/>' for x, y in tunnel) + "</g>")
    out.append(f'<line class="thr draw" pathLength="1" x1="{x0}" x2="{x1}" y1="{py(thr):.1f}" y2="{py(thr):.1f}"/>')
    # the errors: first tunnel queries (all at one instant) and the single false alarm of this seed
    t_first = [x for x in rows if x[2] == 1][0][0]
    misses = [x for x in rows if x[2] == 1 and x[3] == 0]
    fps = [x for x in rows if x[2] == 0 and x[3] == 1]
    mx = px(t_first)
    out.append('<g class="ann">')
    for _, sc, *_ in misses:
        out.append(f'<circle class="ring" cx="{mx:.1f}" cy="{py(sc):.1f}" r="9"/>')
    out.append(f'<line class="lead" x1="{mx + 14:.1f}" x2="{mx + 40:.1f}" y1="{py(0.76):.1f}" y2="34"/>'
               f'<text class="an-t" x="{mx + 46:.1f}" y="40">tunnel session: first 3 queries missed</text>')
    for t, sc, *_ in fps:
        fx = px(t)
        out.append(f'<circle class="ring" cx="{fx:.1f}" cy="{py(sc):.1f}" r="9"/>'
                   f'<line class="lead" x1="{fx:.1f}" x2="{fx - 20:.1f}" y1="{py(sc) - 11:.1f}" y2="34"/>'
                   f'<text class="an-t" x="{fx - 26:.1f}" y="40" text-anchor="end">a false alarm</text>')
    out.append("</g></svg>")
    return "".join(out)


def fig_window(r: dict) -> str:
    """Slide 14: false-positive queries with a 60 and a 300 second window (folds_median, ten seeds)."""
    vals = [("60 seconds", r["window_60"]["fp"], ""), ("300 seconds", r["window_300"]["fp"], " hot")]
    w, h, ax, maxw, pitch, y0 = 640, 200, 176, 360, 68, 46
    top = vals[0][1]
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="False-positive queries with a 60 and a 300 second window">',
           '<text class="ax" x="0" y="20">False-positive queries in the test period</text>']
    for i, (name, v, hot) in enumerate(vals):
        y = y0 + i * pitch
        bw = maxw * v / top
        out.append(f'<text class="bar-l{hot}" x="0" y="{y + 25}">{name}</text>'
                   f'<rect class="bar grow-x{hot}" x="{ax}" y="{y}" width="{bw:.1f}" height="36" rx="4" '
                   f'style="animation-delay:{i * 110}ms"/>'
                   f'<text class="bar-v count{hot}" data-to="{v:.1f}" data-dec="1" x="{ax + bw + 14:.1f}" '
                   f'y="{y + 28}">{v:.1f}</text>')
    out.append(f'<line class="axis" x1="{ax}" x2="{ax}" y1="{y0 - 10}" y2="{y0 + 2 * pitch - 22}"/></svg>')
    return "".join(out)


def fig_alt() -> str:
    """Slide 15: tunnel queries found, and normal queries wrongly flagged, for three algorithms."""
    w, h, lw = 1144, 244, 236
    p1, p2, pw = lw, 690, 320
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="Isolation Forest, Local Outlier Factor and One-Class SVM compared">',
           f'<text class="ax" x="{p1}" y="22">Tunnel queries found</text>'
           f'<text class="ax" x="{p2}" y="22">Normal queries flagged</text>'
           f'<text class="ax" x="{w}" y="22" text-anchor="end">False incidents</text>']
    for i, (name, rec, fpr, inc) in enumerate(ALT):
        y = 48 + i * 66
        hot = " hot" if i == 0 else ""
        out.append(f'<text class="bar-l{hot}" x="0" y="{y + 27}">{name}</text>')
        out.append(f'<rect class="bar grow-x{hot}" x="{p1}" y="{y}" width="{pw * rec:.1f}" height="38" rx="4" '
                   f'style="animation-delay:{i * 110}ms"/>'
                   f'<text class="bar-v{hot}" x="{p1 + pw * rec + 12:.1f}" y="{y + 29}">{rec * 100:.2f}%</text>')
        fw = max(250 * fpr / 0.08, 4)
        out.append(f'<rect class="bar grow-x{hot}" x="{p2}" y="{y}" width="{fw:.1f}" height="38" rx="4" '
                   f'style="animation-delay:{i * 110 + 60}ms"/>'
                   f'<text class="bar-v{hot}" x="{p2 + fw + 12:.1f}" y="{y + 29}">{fpr * 100:.2f}%</text>')
        out.append(f'<text class="bar-v{hot}" x="{w}" y="{y + 29}" text-anchor="end">{inc:.1f}</text>')
    out.append("</svg>")
    return "".join(out)


def fig_choke() -> str:
    """Slide 18: the resolver as the one place DNS may leave the network, the direct path closed."""
    w, h = 1144, 216
    nodes = [(0, "Client", "may only ask the resolver", ""),
             (432, "Internal resolver", "logs every query", " hot"),
             (864, "Outside DNS", "the attacker's included", "")]
    out = [f'<svg class="fig" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="DNS may only leave through the internal resolver">',
           '<defs><marker id="arr2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
           'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="arr-h"/></marker></defs>']
    for gx in (280, 712):
        out.append(f'<line class="link" x1="{gx + 10}" x2="{gx + 142}" y1="76" y2="76" marker-end="url(#arr2)"/>')
    for x, title, sub, hot in nodes:
        out.append(f'<g class="node{hot}"><rect x="{x}" y="28" width="280" height="96" rx="14"/>'
                   f'<text class="node-t" x="{x + 24}" y="70">{title}</text>'
                   f'<text class="node-s" x="{x + 24}" y="100">{sub}</text></g>')
    out.append('<path class="direct" d="M140 134 V170 H1004 V134"/>')
    out.append('<g class="shut"><circle cx="572" cy="170" r="16"/><path d="M563 161 L581 179 M581 161 L563 179"/></g>')
    out.append('<text class="an-t shut-l" x="572" y="210" text-anchor="middle">direct DNS out: closed</text>')
    out.append('<text class="an-s" x="572" y="18" text-anchor="middle">the only way out</text></svg>')
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
/* slides 10 to 19: detector, results, mitigation */
.fn{font-family:var(--mono);font-size:19px;font-weight:700;color:var(--brand);line-height:1.2;margin-bottom:6px}
.seg-fit{fill:var(--tint2);stroke:var(--rule);stroke-width:1.5}
.seg-val{fill:#DFCBC7;stroke:var(--rule);stroke-width:1.5}
.seg-test{fill:var(--tint);stroke:var(--rule);stroke-width:1.5}
.seg-tun{fill:var(--red)}
.sp-t{font-size:21px;font-weight:700;fill:var(--ink)}
.sp-n{font-size:21px;font-weight:500;fill:var(--ink)}
.sp-br{stroke:var(--grey);stroke-width:2}
.sp-lead{stroke:var(--red);stroke-width:2}
.thr{stroke:var(--red);stroke-width:3}
.thr.draw{stroke-dasharray:1;stroke-dashoffset:0}
.dot{fill:var(--grey)}
.dot.t{fill:var(--red)}
.ring{fill:none;stroke:var(--red);stroke-width:2.5}
.lead{stroke:var(--red);stroke-width:2}
.stats{display:flex;gap:24px}
.stat{flex:1 1 0;background:var(--tint);border-radius:14px;padding:22px 26px 24px;border-top:6px solid var(--brand)}
.stat .big{font-size:84px;line-height:1;font-weight:700;letter-spacing:-.035em;color:var(--ink);white-space:nowrap}
.stat .big small{font-size:48px;font-weight:700;letter-spacing:-.02em;color:var(--muted);margin-left:4px}
.stat .lb{margin-top:14px;font-weight:500;color:var(--muted);line-height:1.35}
.stat.hot{background:var(--brand);border-top-color:var(--brand)}
.stat.hot .big,.stat.hot .big small{color:#fff}
.stat.hot .lb{color:var(--onbrand)}
.direct{fill:none;stroke:var(--grey);stroke-width:3;stroke-dasharray:3 9;stroke-linecap:round}
.shut circle{fill:var(--red)}
.shut path{fill:none;stroke:#fff;stroke-width:4;stroke-linecap:round}

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
@keyframes wipe{from{clip-path:inset(0 100% 0 0)}}
.slide.is-active .wipe{animation:wipe 2.2s linear .3s backwards}
.slide.is-active .thr.draw{animation:draw 1.2s var(--ease) 1.4s backwards}
.slide.is-active .ann,.slide.is-active .seg-tun,.slide.is-active .sp-lead,.slide.is-active .sp-lead-t,.slide.is-active .shut,.slide.is-active .shut-l{animation:pop .5s linear 2.6s backwards}
.slide.is-active .seg-tun,.slide.is-active .sp-lead,.slide.is-active .sp-lead-t{animation-delay:1.3s}
.slide.is-active .shut,.slide.is-active .shut-l{animation-delay:1s}
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
    var to=+el.getAttribute('data-to'),dec=+(el.getAttribute('data-dec')||0),t0=null,delay=+(el.getAttribute('data-delay')||0);
    function fmt(v){return dec?v.toFixed(dec):String(Math.round(v));}
    if(reduce){el.textContent=fmt(to);return;}
    el.textContent=fmt(0);
    function tick(t){if(t0===null){t0=t+delay;}var p=Math.min(Math.max((t-t0)/1100,0),1);
      el.textContent=fmt(to*(1-Math.pow(1-p,3)));if(p<1){requestAnimationFrame(tick);}}
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
    res = load_results()
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
                   'How a tunnel normally travels. In our capture the client reached the tunnel server directly, '
                   'on the same network segment.'))

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

    fin, w60, w300 = res["final"], res["window_60"], res["window_300"]

    def card(fn, head, text, i):
        return (f'<div class="card rv" style="--i:{i}"><p class="fn">{fn}</p><h2>{head}</h2><p>{text}</p></div>')

    # 10: the features
    s.append(slide(10, "Detection", "Four features, none about the tool",
                   '<div class="cards" style="margin-top:0">'
                   + card("name_bytes", "Name length", "Long names carry data. Counted in bytes, as on the wire.", 2)
                   + card("uniq_names_300s", "Unique names", "Different names asked under one domain in the last 5 minutes.", 3)
                   + card("uniq_ratio_300s", "Share of new names", "Normal sites repeat names. A tunnel almost never does.", 4)
                   + card("norepeat_tol", "No repeats yet", "The log of unique names times the share of new names, with no time window.", 5)
                   + '</div><p class="absent rv" style="--i:6"><b>Left out on purpose:</b> IP addresses, source port, '
                   'answer flags, TTL, EDNS0 and record type. They separate this capture perfectly and say nothing about tunnels.</p>',
                   'Counted per client and parent domain, from the earlier queries only. Report section 3.1.'))

    # 11: how Isolation Forest decides (figure from `python -m src.plots`, report Figure 3.1)
    iforest_png = ROOT / "notebooks" / "figures" / "isolation_forest_view_300s.png"
    assert iforest_png.exists(), "run `python -m src.plots` first"
    s.append(slide(11, "The model", "Isolation Forest: how easy is a query to isolate?",
                   '<div class="cols" style="gap:48px;align-items:center">'
                   # only the right panel of the figure (the cuts); the left panel is in the report
                   '<div class="rv" style="--i:2;width:460px;height:368px;overflow:hidden">'
                   f'<img alt="Number of random cuts needed to isolate each test query" '
                   f'style="height:368px;width:auto;margin-left:-460px" '
                   f'src="data:image/png;base64,{b64(iforest_png)}"></div>'
                   '<div style="display:flex;flex-direction:column;gap:12px;width:636px">'
                   '<div class="card rv" style="--i:3"><h2>1 · Random cuts</h2><p>300 trees cut normal traffic on a '
                   'random feature at a random value, until every query stands alone.</p></div>'
                   '<div class="card rv" style="--i:4"><h2>2 · Few cuts = strange</h2><p>A normal query needs about '
                   '<mark>11</mark> cuts, a tunnel query about <mark>4.5</mark>.</p></div>'
                   '<div class="card rv" style="--i:5"><h2>3 · A line on the score</h2><p>Fewer cuts, higher score. '
                   'Past the line (<mark>5.3</mark> cuts): alert.</p></div></div></div>',
                   'Average number of random cuts per test query, 300 second window, one seed. Report Figure 3.1.'))

    # 12: the split
    s.append(slide(12, "Training", "Trained on normal traffic only",
                   fig_split(res) + '<div class="cards" style="margin-top:14px">'
                   '<div class="card rv" style="--i:5"><h2>Normal only</h2><p>The forest learns what normal DNS '
                   'looks like. The tunnel is never in training.</p></div>'
                   '<div class="card rv" style="--i:6"><h2>Time order</h2><p>Neighbouring queries are near copies, '
                   'so a random split would leak.</p></div>'
                   '<div class="card rv" style="--i:7"><h2>Line from validation</h2><p>The threshold is the highest '
                   'score of any normal validation query.</p></div></div>',
                   'The first burst is left out: it is an exact copy of the second, so it would be tested twice.'))

    # 13: the score histogram, tunnel coloured on the click
    s.append(slide(13, "Result", "One line catches the tunnel",
                   fig_scores(res) + f'<p class="note st1">The threshold is <mark>{res["threshold"]:.2f}</mark>, set '
                   f'on the validation period. <mark>No test query</mark> was used to compute it.</p>',
                   'Anomaly score of the 1,831 test queries, one seed. The tunnel turns red on the click.', steps=1))

    # 14: the headline numbers
    s.append(slide(14, "Result", "Almost every tunnel query found",
                   '<div class="stats">'
                   f'<div class="stat rv" style="--i:2"><p class="big"><span class="count" data-to="{fin["recall"] * 100:.2f}" '
                   f'data-dec="2">{fin["recall"] * 100:.2f}</span><small>%</small></p><p class="lb">of the 222 tunnel '
                   'queries found</p></div>'
                   f'<div class="stat rv" style="--i:3"><p class="big"><span class="count" data-to="{fin["precision"] * 100:.1f}" '
                   f'data-dec="1">{fin["precision"] * 100:.1f}</span><small>%</small></p><p class="lb">of the alerts '
                   'were real tunnel queries</p></div>'
                   f'<div class="stat hot rv" style="--i:4"><p class="big"><span class="count" data-to="{fin["false_incidents"]:.1f}" '
                   f'data-dec="1">{fin["false_incidents"]:.1f}</span></p><p class="lb">false incidents in 40 minutes '
                   'of normal traffic</p></div></div>'
                   '<ul class="points rv" style="--i:5;width:auto;margin-top:26px">'
                   f'<li>False-positive rate <mark>{fin["fpr"] * 100:.2f}%</mark>, PR AUC <mark>{fin["pr_auc"]:.3f}</mark>, '
                   f'the same on ten random seeds (spread {res["pr_auc_sd"]:.4f}).</li>'
                   '<li>The first alert comes on the <mark>fourth query</mark> of the session, before the data transfer starts.</li></ul>',
                   'Mean of ten random seeds, 300 second window, threshold from the validation period. Report section 3.3.'))

    # 15: window
    s.append(slide(15, "Choices", "A longer window, fewer false alarms",
                   f'<div class="cols">{fig_window(res)}<ul class="points">'
                   f'<li class="rv" style="--i:2">Recall stays the same: <mark>{w60["recall"] * 100:.2f}%</mark> and <mark>{w300["recall"] * 100:.2f}%</mark>.</li>'
                   f'<li class="rv" style="--i:3">PR AUC is almost the same: {w60["pr_auc"]:.4f} and {w300["pr_auc"]:.4f}.</li>'
                   f'<li class="rv" style="--i:4"><mark>{(1 - w300["fp"] / w60["fp"]) * 100:.0f}% fewer</mark> '
                   'false-positive queries.</li>'
                   '<li class="rv" style="--i:5">We chose 300 seconds after seeing the test period. That is a '
                   'limit, not a result.</li></ul></div>'
                   '<p class="verdict rv" style="--i:6"><b>Final:</b> the validation maximum as threshold gives '
                   f'<mark>{fin["fp"]:.1f}</mark> false-positive queries.</p>',
                   'Bars: threshold from five time ordered folds. Mean of ten seeds. Report section 3.3.'))

    # 16: alternatives
    s.append(slide(16, "Alternatives", "Isolation Forest scores best in our comparison",
                   fig_alt() + '<p class="verdict rv" style="--i:6"><b>One configuration each.</b> We did not tune '
                   'Local Outlier Factor or One-Class SVM, so we cannot say why they score lower.</p>',
                   'Same four features, same split, same threshold rule. Isolation Forest is the mean of ten seeds. '
                   'Report Table 3.3.'))

    # 17: errors
    s.append(slide(17, "Errors", "Where the detector goes wrong",
                   fig_timeline(res) + '<div class="cards" style="margin-top:14px">'
                   '<div class="card rv" style="--i:5"><h2>Missed: always the same three</h2><p>The first queries of '
                   'the session. One to three names so far looks like any first lookup of a new domain.</p></div>'
                   f'<div class="card rv" style="--i:6"><h2>False incidents: {fin["false_incidents"]:.1f} per 40 minutes</h2>'
                   '<p>Yahoo asks for 19 to 25 names in one window. Azure sends a few long names that are not '
                   'repeated.</p></div></div>',
                   'Each dot is one test query. Red: tunnel. Grey: normal. One seed. Report sections 3.3.4 and 3.4.3.'))

    # 18: limits
    rec, fpr, prev = 0.9865, 0.0021, 0.001
    prec_rare = rec * prev / (rec * prev + fpr * (1 - prev))
    assert 0.315 < prec_rare < 0.325, prec_rare
    s.append(slide(18, "Limits", "What the numbers do not prove",
                   '<div class="vs"><div class="side rec rv" style="--i:2"><h2>Holds up</h2><p class="lbl">Tested</p><ul>'
                   '<li>The same result on ten random seeds</li>'
                   f'<li>A tunnel 60 times slower: <mark>{SLOW_TUNNEL_RECALL}%</mark> still found</li>'
                   '<li>An alert on the fourth query of a session</li></ul></div>'
                   '<div class="side weak rv" style="--i:3"><h2>Does not carry over</h2><p class="lbl">Limits</p><ul>'
                   '<li>One tunnel session, one normal host</li>'
                   '<li>Window and threshold chosen after seeing the test period</li>'
                   f'<li>Tunnels at 0.1% of traffic: precision falls to about <mark>{prec_rare * 100:.0f}%</mark></li>'
                   f'<li>Little training data: false alarms rise from {QUIET_TRAINING_FPR[0]:.2f}% to '
                   f'{QUIET_TRAINING_FPR[1]:.2f}%</li>'
                   f'<li>Nine extra normal clients: false incidents rise from {STRESS_INCIDENTS[0]} to '
                   f'<mark>{STRESS_INCIDENTS[1]}</mark></li></ul></div></div>'
                   '<p class="callout rv" style="--i:4"><b>A retrospective benchmark, not an independent validation.</b> '
                   'Real traffic would need new data.</p>'))

    # 19: mitigation
    s.append(slide(19, "Mitigation", "Make DNS leave through one door",
                   fig_choke() + '<div class="cards" style="margin-top:14px">'
                   '<div class="card rv" style="--i:4"><h2>Prevention</h2><p>Only the resolver may send DNS out. '
                   'Refuse or flag NULL records, cap unique names per client.</p></div>'
                   '<div class="card rv" style="--i:5"><h2>Detection</h2><p>Run the detector on resolver logs, plus '
                   'cheap rules such as NULL queries.</p></div>'
                   '<div class="card rv" style="--i:6"><h2>Response</h2><p>Isolate the client, keep the logs, then '
                   'decode the tunnel to see what went through.</p></div></div>',
                   'MITRE mitigations M1037 and M1031. Report section 4.'))

    # 20: conclusion
    s.append(slide(20, "Conclusion", "What we take away",
                   '<div class="vs"><div class="side rec rv" style="--i:2"><h2>What we found</h2><p class="lbl">Result</p><ul>'
                   f'<li>An <mark>iodine</mark> tunnel, found through one domain with {f["uniq_top"][0][1]} unique names</li>'
                   '<li>Inside it one voice call, no sign of data theft</li>'
                   f'<li>Isolation Forest finds <mark>{fin["recall"] * 100:.2f}%</mark> of the tunnel queries with '
                   f'{fin["false_incidents"]:.1f} false incidents</li></ul></div>'
                   '<div class="side weak rv" style="--i:3"><h2>Next time</h2><p class="lbl">What we would change</p><ul>'
                   '<li>Check every number from the log against the packets</li>'
                   '<li>Fix window and threshold before looking at the test period</li>'
                   '<li>Record other tunnel tools and slower tunnels</li></ul></div></div>',
                   'Report sections 5 and 6.'))

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
