"""Compute every detector number the presentation quotes and write it to slides/results.json.

Run from the repository root (after `python main.py --all`, which needs data/raw/dns.log):
    python slides/compute_results.py
build_deck.py reads results.json, so the deck builds without scikit-learn and the numbers cannot drift
from the detector: they come from src/ with the same settings as the report (features `forced`, 300 s window,
threshold `val_max`, 300 trees, seeds 0 to 9). The report's Tables 1 and 2 are asserted below.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.detector import run_detector  # noqa: E402
from src.evaluation import confusion  # noqa: E402
from src.features import feature_sets, make_matrix  # noqa: E402
from src.incidents import incident_metrics  # noqa: E402

SEEDS = range(10)


def one(m, window, threshold, seed):
    scored, info = run_detector(m, feature_sets(window)["forced"], threshold=threshold, random_state=seed)
    t = scored[scored["role"] == "test"]
    c = confusion(t["y"], t["alert"])
    c["pr_auc"] = float(average_precision_score(t["y"], t["score"]))
    c["false_incidents"] = incident_metrics(scored)["false_incidents"]
    return scored, info, c


def mean_over_seeds(m, window, threshold):
    runs = [one(m, window, threshold, s) for s in SEEDS]
    keys = ["precision", "recall", "fpr", "fp", "fn", "pr_auc", "false_incidents"]
    return runs, {k: float(np.mean([r[2][k] for r in runs])) for k in keys}


def main() -> None:
    out: dict = {}
    m60, m300 = make_matrix(window_s=60, write=False), make_matrix(window_s=300, write=False)

    # window comparison, folds_median, as in the report's Table 1
    for w, m in ((60, m60), (300, m300)):
        _, mean = mean_over_seeds(m, w, "folds_median")
        out[f"window_{w}"] = mean

    # final configuration: 300 s, val_max, ten seeds
    runs, final = mean_over_seeds(m300, 300, "val_max")
    out["final"] = final
    out["pr_auc_sd"] = float(np.std([r[2]["pr_auc"] for r in runs], ddof=0))

    # seed 0 for the figures
    scored, info, c0 = runs[0]
    t = scored[scored["role"] == "test"].sort_values("ts")
    train = scored[scored["role"] != "test"]
    out["split"] = {"fit": int((scored["role"] == "fit").sum()), "val": int((scored["role"] == "val").sum()),
                    "test": int(len(t)), "test_tunnel": int(t["y"].sum())}
    out["threshold"] = float(info["threshold"])
    out["seed0"] = c0
    t0 = float(t["ts"].min())
    out["test_rows"] = [[round(float(r.ts) - t0, 1), round(float(r.score), 4), int(r.y), int(r.alert), r.parent]
                        for r in t.itertuples()]
    out["train_span_s"] = float(train["ts"].max() - train["ts"].min())
    missed = t[(t["y"] == 1) & (t["alert"] == 0)]
    out["missed_seed0"] = [[round(float(r.ts) - t0, 1), r.phase] for r in missed.itertuples()]
    # false positives and misses over all ten seeds: which parents, which tunnel queries
    fps, miss = [], []
    for r in runs:
        tt = r[0][r[0]["role"] == "test"]
        fps.append(tt[(tt["y"] == 0) & (tt["alert"] == 1)]["parent"].value_counts())
        miss.append(tt[(tt["y"] == 1) & (tt["alert"] == 0)]["ts"].sub(t0).round(1).astype(str))
    mean_fp = pd.concat(fps, axis=1).fillna(0).sum(axis=1) / len(runs)
    out["fp_by_parent_mean"] = {k: round(float(v), 2) for k, v in mean_fp.sort_values(ascending=False).items()}
    assert abs(sum(out["fp_by_parent_mean"].values()) - out["final"]["fp"]) < 0.01
    out["missed_by_seed"] = [len(x) for x in miss]
    out["missed_same_every_seed"] = bool(all(set(x) == set(miss[0]) for x in miss))
    tun = t[t["y"] == 1]
    out["tunnel_first_s"] = float(tun["ts"].min() - t0)

    # the report's own numbers must hold, or this script fails loudly
    w60, w300, f = out["window_60"], out["window_300"], out["final"]
    assert abs(w60["precision"] - 0.7442) < 5e-4 and abs(w300["precision"] - 0.9609) < 5e-4, (w60, w300)
    assert abs(w60["fp"] - 75.6) < 0.05 and abs(w300["fp"] - 9.0) < 0.05, (w60["fp"], w300["fp"])
    assert abs(f["precision"] - 0.9853) < 5e-4 and abs(f["recall"] - 0.9865) < 5e-4, f
    assert abs(f["fpr"] - 0.0021) < 5e-4 and abs(f["pr_auc"] - 0.9934) < 5e-4, f
    assert abs(f["false_incidents"] - 1.9) < 0.05, f
    assert out["split"] == {"fit": 1274, "val": 318, "test": 1831, "test_tunnel": 222}, out["split"]

    path = Path(__file__).resolve().parent / "results.json"
    path.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {path.name} ({path.stat().st_size / 1024:.0f} KB)")
    print(json.dumps({k: v for k, v in out.items() if k != "test_rows"}, indent=1)[:2500])


if __name__ == "__main__":
    main()
