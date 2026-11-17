"""Acceptance checks for src/baselines.py. Run with `python tests/test_baselines.py` or `pytest tests`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from src.baselines import run_rule
from src.evaluation import confusion
from src.features import build_features
from src.prepare import load_raw, prepare

M = build_features(prepare(load_raw(), session="second"), window_s=60)


def test_format_matches_the_detector_output():
    s = run_rule(M, "unique_names")
    assert len(s) == len(M) and s["row_id"].is_unique
    assert set(s["role"]) == {"fit", "val", "test"} and {"score", "alert"} <= set(s.columns)
    assert set(s.loc[s.role == "test", "row_id"]) == set(M.loc[M.split == "test", "row_id"])


def test_no_training_row_alerts_with_train_max():
    for kind in ("unique_names", "shape"):
        s = run_rule(M, kind)
        assert s.loc[s.role != "test", "alert"].sum() == 0


def test_line_does_not_depend_on_test_rows():
    m2 = M.copy()
    te = m2.split == "test"
    cols = ["uniq_names_60s", "name_bytes", "entropy"]
    m2.loc[te, cols] = m2.loc[te, cols].sample(frac=1, random_state=1).to_numpy()
    for kind in ("unique_names", "shape"):
        assert run_rule(m2, kind).attrs["threshold"] == run_rule(M, kind).attrs["threshold"]


def test_val_max_line_uses_only_the_validation_slice():
    a, b = run_rule(M, "unique_names", threshold="train_max"), run_rule(M, "unique_names", threshold="val_max")
    assert b.attrs["threshold"] <= a.attrs["threshold"]
    assert b.loc[b.role == "val", "alert"].sum() == 0


def test_unique_names_rule_finds_the_loud_tunnel_and_shape_rule_does_not():
    t = run_rule(M, "unique_names"); t = t[t.role == "test"]
    s = run_rule(M, "shape"); s = s[s.role == "test"]
    assert confusion(t["y"], t["alert"])["recall"] > 0.9
    assert confusion(s["y"], s["alert"])["recall"] < 0.5   # only the data and probe queries have odd names


def test_unknown_kind_is_rejected():
    try:
        run_rule(M, "nope")
    except AssertionError:
        return
    raise AssertionError("unknown kind accepted")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
