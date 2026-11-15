"""Acceptance checks for src/detector.py and src/evaluation.py.
Run with `python tests/test_detector.py` or `pytest tests`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from src.detector import run_detector, split_validation
from src.evaluation import confusion, feature_importance, plot_score_distribution, summarize
from src.features import build_features, feature_sets
from src.prepare import load_raw, prepare

M = build_features(prepare(load_raw(), session="second"), window_s=60)
FS = feature_sets(60)
SCORED, INFO = run_detector(M, FS["forced"])


def test_validation_slice_is_the_end_of_training_and_benign():
    train = M[M.split == "train"]
    fit, val = split_validation(train)
    assert len(fit) + len(val) == len(train) and fit["ts"].max() <= val["ts"].min()
    assert not fit["y"].any() and not val["y"].any()


def test_every_row_scored_once_and_roles_match_split():
    assert len(SCORED) == len(M) and SCORED["row_id"].is_unique
    assert set(SCORED.loc[SCORED.role == "test", "row_id"]) == set(M.loc[M.split == "test", "row_id"])
    assert SCORED["score"].notna().all()


def test_threshold_is_not_chosen_on_test_rows():
    # shuffling the test feature values must not change the threshold
    m2 = M.copy()
    te = m2.split == "test"
    m2.loc[te, FS["forced"]] = m2.loc[te, FS["forced"]].sample(frac=1, random_state=1).to_numpy()
    _, info2 = run_detector(m2, FS["forced"])
    assert info2["threshold"] == INFO["threshold"]


def test_folds_use_training_rows_only_and_cover_them_once():
    folds = INFO["folds"]
    train = M[M.split == "train"]
    assert folds["rows"].sum() == len(train) and len(folds) == 5
    assert folds["end"].max() < M.loc[M.split == "test", "ts"].min()
    assert folds["start"].is_monotonic_increasing
    assert INFO["candidates"]["folds_max"] >= INFO["candidates"]["folds_median"]


def test_fold_threshold_ignores_test_rows():
    m2 = M.copy()
    te = m2.split == "test"
    m2.loc[te, FS["forced"]] = m2.loc[te, FS["forced"]].sample(frac=1, random_state=1).to_numpy()
    _, info2 = run_detector(m2, FS["forced"], threshold="folds_median")
    assert info2["threshold"] == INFO["candidates"]["folds_median"]


def test_no_validation_row_alerts_with_val_max():
    assert SCORED.loc[SCORED.role == "val", "alert"].sum() == 0


def test_metadata_cannot_be_a_feature():
    try:
        run_detector(M, FS["forced"] + ["y"])
    except AssertionError:
        return
    raise AssertionError("y accepted as a feature")


def test_confusion():
    p = confusion(np.array([1, 1, 0, 0]), np.array([1, 0, 1, 0]))
    assert (p["tp"], p["fp"], p["fn"], p["tn"]) == (1, 1, 1, 1) and p["precision"] == p["recall"] == 0.5


def test_default_run_finds_the_tunnel():
    t = SCORED[SCORED.role == "test"]
    c = confusion(t["y"], t["alert"])
    assert c["recall"] > 0.95 and c["tp"] > 200


def test_summary_runs():
    assert "threshold" in summarize(SCORED, INFO)


def test_feature_importance_covers_every_feature():
    t = SCORED[SCORED.role == "test"]
    imp = feature_importance(INFO["model"], t[FS["forced"]], t["y"].to_numpy(), n_repeats=2)
    assert set(imp.index) == set(FS["forced"]) and imp.index[0] == "uniq_names_60s"


def test_score_plot_is_saved(tmp=Path(__file__).resolve().parents[1] / "data" / "processed" / "_test_plot.png"):
    path = plot_score_distribution(SCORED, INFO, tmp)
    assert path.exists() and path.stat().st_size > 0
    path.unlink()


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
