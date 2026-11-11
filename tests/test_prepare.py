"""Acceptance checks for src/prepare.py. Run with `python tests/test_prepare.py` or `pytest tests`.

Needs data/raw/dns.log and data/labels.csv. The expected numbers were verified in the discovery and
baseline notebooks (docs/handoff-2026-11-10-1230.md, docs/Baseline findings.md).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd

from src.prepare import load_raw, prepare, to_wire_bytes

RAW = load_raw()
FIRST = prepare(RAW, session="first")
SECOND = prepare(RAW, session="second")
BOTH = prepare(RAW, session="both")


def test_raw_counts_and_row_id():
    assert len(RAW) == 3645
    assert RAW["row_id"].tolist() == list(range(3645)), "row_id must be file order"
    assert RAW["label"].value_counts().to_dict() == {"benign": 3201, "tunnel": 444}


def test_labels_follow_the_rule():
    is_domain = RAW["query"].str.endswith(".pirate.sea")
    assert ((RAW["label"] == "tunnel") == is_domain).all()


def test_labels_are_joined_before_sorting():
    # The log is not in time order; the label of every row must still match its own query.
    assert not RAW["ts"].is_monotonic_increasing
    for p in (FIRST, SECOND, BOTH):
        assert ((p["label"] == "tunnel") == p["query"].str.endswith(".pirate.sea")).all()
        assert p["ts"].is_monotonic_increasing


def test_session_row_counts():
    assert len(BOTH) == 3645 and BOTH["y"].sum() == 444
    for p in (FIRST, SECOND):
        assert len(p) == 3423 and p["y"].sum() == 222


def test_session_keeps_one_burst():
    assert set(FIRST.loc[FIRST.y == 1, "burst"]) == {1} and not FIRST["is_replay"].any()
    assert set(SECOND.loc[SECOND.y == 1, "burst"]) == {2} and SECOND.loc[SECOND.y == 1, "is_replay"].all()
    assert set(BOTH.loc[BOTH.y == 1, "burst"]) == {1, 2}


def test_wire_byte_lengths():
    assert BOTH.groupby("label")["name_bytes"].max().to_dict() == {"benign": 103, "tunnel": 252}
    assert to_wire_bytes(r"a\xebb") == b"a\xebb" and len(to_wire_bytes(r"a\xebb")) == 3


def test_phase_counts_per_burst():
    for p in (FIRST, SECOND):
        t = p[p["y"] == 1]["phase"].value_counts().to_dict()
        assert t == {"ping": 173, "data": 24, "size_probe": 13, "encoding_test": 9, "handshake": 3}, t
        assert t["handshake"] + t["encoding_test"] == 12  # the report's "12 set-up queries"
    assert (BOTH.loc[BOTH.y == 0, "phase"] == "benign").all()


def test_split_primary_run():
    train, test = SECOND[SECOND.split == "train"], SECOND[SECOND.split == "test"]
    assert train["y"].sum() == 0, "training must be benign only"
    assert (len(train), len(test)) == (1592, 1831)
    assert test["y"].sum() == 222 and (test["y"] == 0).sum() == 1609
    assert train["ts"].max() < test["ts"].min()


def test_split_strict_variant():
    train, test = FIRST[FIRST.split == "train"], FIRST[FIRST.split == "test"]
    assert train["y"].sum() == 0 and len(train) == 244
    assert test["y"].sum() == 222


def test_parent_domains():
    assert (BOTH.loc[BOTH.y == 1, "parent"] == "pirate.sea").all()
    assert BOTH.loc[BOTH.y == 0, "parent"].nunique() > 200
    co_uk = BOTH[BOTH["parent"] == "co.uk"]
    assert co_uk.empty, "co.uk is a public suffix, not a registered domain"
    assert (BOTH.loc[BOTH["query"].str.endswith(".co.uk"), "parent"].str.endswith(".co.uk")).all()


def test_subdomain_and_labels_consistent():
    tun = BOTH[BOTH.y == 1]
    assert (tun["subdomain"] + ".pirate.sea" == tun["name"]).all()
    assert (BOTH["labels_bytes"].map(len) >= 1).all()
    assert (BOTH["labels_bytes"].map(lambda l: max(map(len, l))) <= 63).all()


def test_no_missing_values_in_core_columns():
    core = ["row_id", "ts", "dt", "split", "label", "y", "burst", "phase", "client", "query", "name",
            "name_bytes", "parent", "qtype", "qtype_name"]
    for p in (FIRST, SECOND, BOTH):
        assert not p[core].isna().any().any()


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
