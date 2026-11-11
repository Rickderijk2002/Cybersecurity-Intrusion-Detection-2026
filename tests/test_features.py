"""Acceptance checks for src/features.py. Run with `python tests/test_features.py` or `pytest tests`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from src.features import META_COLUMNS, build_features, feature_sets, shannon_entropy
from src.prepare import load_raw, prepare

RAW = load_raw()
PREP = prepare(RAW, session="second")
M = build_features(PREP, window_s=60)
FS = feature_sets(60)
ALL = FS["full"]


def test_shape_and_no_missing_values():
    assert len(M) == len(PREP) == 3423
    assert not M[ALL].isna().any().any()
    assert np.isfinite(M[ALL].to_numpy(dtype=float)).all()


def test_feature_sets_are_consistent():
    assert set(ALL) <= set(M.columns)
    assert not set(ALL) & set(META_COLUMNS), "metadata must never be a feature"
    assert FS["forced"] == FS["shape"] + FS["context"] and FS["full"] == FS["forced"] + FS["qtype"]


def test_excluded_signals_are_not_features():
    banned = {"client", "id.orig_h", "id.orig_p", "id.resp_h", "AA", "RA", "TTLs", "rtt", "rcode_name",
              "phase", "burst", "is_replay", "parent", "label", "y", "split", "ts"}
    assert not banned & set(ALL)


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0 and shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9


def test_window_size_changes_column_names_and_values():
    m300 = build_features(PREP, window_s=300)
    assert "uniq_names_300s" in m300 and "uniq_names_60s" not in m300
    assert (m300["uniq_names_300s"].to_numpy() >= M["uniq_names_60s"].to_numpy()).all()


def test_tunnel_context_features_stand_out():
    benign, tunnel = M[M.y == 0], M[M.y == 1]
    assert benign["uniq_names_60s"].max() <= 35        # baseline: at most 35 (whole capture), 27-28 per minute
    assert tunnel["uniq_names_60s"].max() == 222       # the whole 24.5 s session fits in one 60 s window
    assert tunnel["uniq_ratio_60s"].median() == 1.0    # a tunnel never repeats a name
    assert tunnel["norepeat_evidence"].median() > benign["norepeat_evidence"].max()


def test_no_leak_of_the_dropped_burst():
    # With both bursts in the stream, burst 2 repeats burst 1's names, so "never repeated a name" is 0 for it.
    both = build_features(prepare(RAW, session="both"), window_s=60)
    assert (both.loc[both.burst == 2, "norepeat_evidence"] == 0).all()
    # prepare(session="second") removed burst 1, so the surviving copy keeps its evidence
    assert M.loc[M.y == 1, "norepeat_evidence"].median() > 4


def test_causality():
    """A row's features must not change when every later row is removed."""
    idx = list(range(0, len(PREP), 97)) + list(PREP.index[PREP.y == 1][::40])
    for i in idx:
        ts_i = PREP.loc[i, "ts"]
        cut = PREP[PREP["ts"] <= ts_i].reset_index(drop=True)
        truncated = build_features(cut, window_s=60)
        row_id = PREP.loc[i, "row_id"]
        a = M.loc[M.row_id == row_id, ALL].to_numpy(dtype=float)
        b = truncated.loc[truncated.row_id == row_id, ALL].to_numpy(dtype=float)
        assert np.allclose(a, b), f"row_id {row_id} changed when later rows were removed"


def test_unsorted_input_is_rejected():
    try:
        build_features(PREP.iloc[::-1], window_s=60)
    except ValueError:
        return
    raise AssertionError("unsorted input must raise")


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
