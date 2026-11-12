"""Acceptance checks for src/variants.py. Run with `python tests/test_variants.py` or `pytest tests`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from src.features import build_features, feature_sets
from src.prepare import load_raw, prepare
from src.variants import add_benign_clients, collapse_clients, inject_repeats, slow_tunnel

PREP = prepare(load_raw(), session="second")
FS = feature_sets(60)


def _valid(v):
    assert v["ts"].is_monotonic_increasing
    assert v.loc[v.split == "train", "y"].sum() == 0, "training must stay benign only"
    assert (v.loc[v.split == "train", "dt"] < v.loc[v.split == "test", "dt"].min()).all()
    build_features(v, window_s=60)   # must be accepted by the feature code


def test_add_benign_clients():
    v = add_benign_clients(PREP, n_extra=4, seed=1)
    assert len(v) == len(PREP) + 4 * (PREP.y == 0).sum()
    assert v["client"].nunique() == 2 + 4 and (v.y == 1).sum() == 222
    assert v.loc[v.y == 1, "client"].nunique() == 1 and v.row_id.is_unique
    _valid(v)


def test_add_benign_clients_is_reproducible():
    a = add_benign_clients(PREP, n_extra=2, seed=3)
    b = add_benign_clients(PREP, n_extra=2, seed=3)
    assert a["ts"].equals(b["ts"])


def test_per_client_grouping_stops_hosts_inflating_each_other():
    noisy = add_benign_clients(PREP, n_extra=9, seed=0)
    per_client = build_features(noisy, window_s=60)
    per_parent = build_features(collapse_clients(noisy), window_s=60)
    col = "uniq_names_60s"
    assert per_client.loc[per_client.y == 0, col].max() < per_parent.loc[per_parent.y == 0, col].max()
    # the tunnel is one client under one domain: its counts do not change
    t = per_client.y == 1
    assert np.allclose(per_client.loc[t, col].to_numpy(), per_parent.loc[t, col].to_numpy())


def test_host_specific_names_make_distinct_names_grow_with_hosts():
    same = add_benign_clients(PREP, n_extra=9, seed=0, host_specific=0.0)
    diff = add_benign_clients(PREP, n_extra=9, seed=0, host_specific=0.5)
    b0, b1 = same[same.y == 0], diff[diff.y == 0]
    assert b1["name"].nunique() > 2 * b0["name"].nunique()
    # per host nothing changes: a name that repeats for a host still repeats
    for client, g in b1.groupby("client"):
        orig = g["name"].nunique()
        assert orig <= PREP.loc[PREP.y == 0, "name"].nunique()
    # lengths stay valid and consistent
    assert (b1["name"].str.len() == b1["name_bytes"]).all() and (b1["name_bytes"] <= 255).all()
    assert (b1["labels_bytes"].map(lambda l: max(map(len, l))) <= 63).all()
    per_client = build_features(diff, window_s=60)
    per_parent = build_features(collapse_clients(diff), window_s=60)
    col = "uniq_names_60s"
    assert per_parent.loc[per_parent.y == 0, col].max() > 2 * per_client.loc[per_client.y == 0, col].max()


def test_slow_tunnel():
    assert slow_tunnel(PREP, k=1)["ts"].equals(PREP["ts"])
    v = slow_tunnel(PREP, k=10)
    d0 = PREP.loc[PREP.y == 1, "ts"].agg(lambda s: s.max() - s.min())
    d1 = v.loc[v.y == 1, "ts"].agg(lambda s: s.max() - s.min())
    assert abs(d1 - 10 * d0) < 1e-6 and (v.y == 1).sum() == 222
    _valid(v)


def test_inject_repeats():
    v = inject_repeats(PREP, n=3, at=30)
    assert len(v) == len(PREP) + 3 and v.row_id.is_unique
    tun = v[v.y == 1]
    assert tun["name"].duplicated().sum() == 3
    _valid(v)


if __name__ == "__main__":
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except AssertionError as e:
            failed += 1
            print("FAIL", name, "-", e)
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
