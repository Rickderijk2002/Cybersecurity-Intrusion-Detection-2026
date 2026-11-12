"""Stress-test variants of the prepared table. Each function takes the output of `prepare()` and returns a
new table in the same format (sorted by ts, `split` re-assigned, benign-only training), so it can go straight
into `build_features()`.

Usage:
    from src.prepare import load_raw, prepare
    from src.variants import add_benign_clients, collapse_clients, slow_tunnel, inject_repeats
    prep = prepare(load_raw())
    noisy = add_benign_clients(prep, n_extra=9)       # 10 benign hosts that share the same domains
    slow = slow_tunnel(prep, k=20)                    # the tunnel 20 times slower
    m = build_features(noisy, window_s=60)

These are simulations built from the one capture we have. They test whether the features and the model
hold up under other conditions; they are not new data and do not prove generalisation.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.prepare import DEFAULT_CUT


def _finish(df: pd.DataFrame, cut: pd.Timestamp) -> pd.DataFrame:
    """Sort by time, rebuild `dt`, re-assign the split from the cut. A stable sort keeps ties in input order."""
    df = df.sort_values("ts", kind="mergesort").reset_index(drop=True)
    df["dt"] = pd.to_datetime(df["ts"], unit="s")
    df["split"] = np.where(df["dt"] < cut, "train", "test")
    return df


def add_benign_clients(prep: pd.DataFrame, n_extra: int = 9, max_shift_s: float = 600.0, seed: int = 0,
                       host_specific: float = 0.5, cut: pd.Timestamp | None = None) -> pd.DataFrame:
    """Noisier network: copy the benign traffic onto `n_extra` more clients, each shifted in time by a random
    offset in +-max_shift_s. Tunnel rows are left untouched.

    In a real network different hosts ask different subdomains of the same domain (CDN tokens, session
    names). To mimic that, a share `host_specific` of each copy's distinct names that have a subdomain get a
    host tag in front of the subdomain (`h3-` ...). The renaming is the same every time that host asks that
    name, so per host nothing changes (repeats stay repeats), but across hosts the number of distinct names
    under one parent grows with the number of hosts. A count per parent domain alone then inflates, while a
    count per (client, parent) does not. With `host_specific=0` all copies ask identical names.

    Training stays benign only: the tunnel is only in the test period. The copies are plausible but not
    independent users.
    """
    cut = pd.Timestamp(cut) if cut is not None else DEFAULT_CUT["second"]
    rng = np.random.default_rng(seed)
    benign = prep[prep["y"] == 0]
    parts = [prep]
    for i in range(n_extra):
        c = benign.copy()
        c["client"] = f"sim-{i + 1}"
        c["ts"] = c["ts"] + rng.uniform(-max_shift_s, max_shift_s)
        c["row_id"] = -(i + 1) * 100_000 - np.arange(len(c))   # unique negative ids: not real log rows
        if host_specific > 0:
            c = _host_specific_names(c, tag=f"h{i + 1}-", share=host_specific, rng=rng)
        parts.append(c)
    return _finish(pd.concat(parts, ignore_index=True), cut)


def _host_specific_names(c: pd.DataFrame, tag: str, share: float, rng: np.random.Generator) -> pd.DataFrame:
    """Put `tag` in front of the subdomain of a random `share` of the distinct names (not the bare domain,
    and not if the first label would pass the 63 byte limit or the name the 255 byte limit)."""
    new_name = {}
    for name, sub, parent in c[["name", "subdomain", "parent"]].drop_duplicates("name").itertuples(index=False):
        if not sub or rng.random() >= share:
            continue
        labels = (tag + sub).split(".")
        full = ".".join(labels + [parent])
        if max(map(len, labels)) <= 63 and len(full) <= 255:
            new_name[name] = (tag + sub, full)
    if not new_name:
        return c
    hit = c["name"].isin(new_name)
    sub_map = {k: v[0] for k, v in new_name.items()}
    full_map = {k: v[1] for k, v in new_name.items()}
    c.loc[hit, "subdomain"] = c.loc[hit, "name"].map(sub_map)
    c.loc[hit, "name"] = c.loc[hit, "name"].map(full_map)
    c.loc[hit, "query"] = c.loc[hit, "name"]
    c.loc[hit, "name_bytes"] = c.loc[hit, "name"].str.len()
    c.loc[hit, "labels_bytes"] = c.loc[hit, "name"].map(lambda n: [x.encode("latin-1") for x in n.split(".")])
    return c


def collapse_clients(prep: pd.DataFrame) -> pd.DataFrame:
    """Give every row the same client. Makes the context features count per parent domain only, i.e. the
    behaviour before the per-client grouping. Used to measure what the grouping buys."""
    return prep.assign(client="all")


def slow_tunnel(prep: pd.DataFrame, k: float, cut: pd.Timestamp | None = None) -> pd.DataFrame:
    """Stretch the tunnel session in time by a factor k around its first query (k = 1 changes nothing).
    The queries and names stay the same, only the gaps grow. Benign rows are untouched."""
    cut = pd.Timestamp(cut) if cut is not None else DEFAULT_CUT["second"]
    d = prep.copy()
    t = d["y"] == 1
    t0 = d.loc[t, "ts"].min()
    d.loc[t, "ts"] = t0 + k * (d.loc[t, "ts"] - t0)
    return _finish(d, cut)


def inject_repeats(prep: pd.DataFrame, n: int = 1, at: int = 30, cut: pd.Timestamp | None = None) -> pd.DataFrame:
    """Repeat the tunnel query number `at` (0-based, in time order) `n` times, 1 ms apart. Mimics a
    retransmission, or an attacker repeating a name on purpose."""
    cut = pd.Timestamp(cut) if cut is not None else DEFAULT_CUT["second"]
    tun = prep[prep["y"] == 1].sort_values("ts", kind="mergesort")
    extra = tun.iloc[[at] * n].copy()
    extra["ts"] = extra["ts"] + 0.001 * np.arange(1, n + 1)
    extra["row_id"] = -1 - np.arange(n)
    return _finish(pd.concat([prep, extra], ignore_index=True), cut)
