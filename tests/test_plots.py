"""Acceptance checks for src/plots.py. Run with `python tests/test_plots.py` or `pytest tests`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from src.detector import run_detector
from src.features import build_features, feature_sets
from src.plots import average_cuts, plot_isolation_view
from src.prepare import load_raw, prepare

M = build_features(prepare(load_raw(), session="second"), window_s=60)
SCORED, INFO = run_detector(M, feature_sets(60)["forced"])


def test_average_cuts_is_decreasing_in_the_score():
    # a more anomalous row (higher score) needs fewer cuts to isolate
    scores = np.array([0.40, 0.50, 0.60, 0.70, 0.80])
    cuts = average_cuts(scores, 256)
    assert np.all(np.diff(cuts) < 0) and np.all(cuts > 0)
    # score 0.5 is the "normal" reference point: E[h] = c(n)
    n = 256
    c = 2 * (np.log(n - 1) + np.euler_gamma) - 2 * (n - 1) / n
    assert abs(float(average_cuts(0.5, n)) - c) < 1e-9


def test_tunnel_needs_fewer_cuts_than_normal_traffic():
    t = SCORED[SCORED.role == "test"]
    cuts = average_cuts(t["score"], INFO["model"].max_samples_)
    assert np.median(cuts[t["y"].to_numpy() == 1]) < np.median(cuts[t["y"].to_numpy() == 0])


def test_figure_is_saved(tmp=Path(__file__).resolve().parents[1] / "data" / "processed" / "_test_isolation_view.png"):
    path = plot_isolation_view(SCORED, INFO, tmp)
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
