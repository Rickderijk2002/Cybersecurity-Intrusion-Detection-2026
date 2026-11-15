"""Isolation Forest detector: fit on benign training rows, score every row, pick a threshold without the test rows.

Run it:
    python main.py                                   # once, builds data/processed/features.csv
    python -m src.detector                           # default run, prints results, writes data/processed/scores.csv
    python -m src.detector --threshold val_p99       # another threshold method
    python -m src.detector --threshold folds_median  # line from the time-ordered folds
    python -m src.detector --features all --seed 3   # another feature set / random seed
    python -m src.detector --window 300              # 300 s window (features are rebuilt in memory)
    python -m src.detector --checks                  # also the model checks (importance, trees, score plot)
    The editor's run button on this file also works (default run + the model checks).

Use it from code:
    from src.features import load_matrix, feature_sets
    from src.detector import run_detector
    from src.evaluation import summarize
    scored, info = run_detector(load_matrix(), feature_sets(60)["forced"])
    print(summarize(scored, info))

This file is the model only: it never looks at the labels (y) except to refuse tunnel rows in training.
Everything that compares alerts with the labels (metrics, error tables, plots) is in src/evaluation.py.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):  # started as a loose file (e.g. an editor's run button): make `src` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.features import META_COLUMNS, feature_sets, load_matrix, make_matrix
from src.prepare import PROCESSED, ROOT

"""Here are the default parameters for the Isolation Forest: you can change them to tune the model"""

DEFAULTS = dict(n_estimators=300, max_samples="auto", max_features=1.0, random_state=0)
VAL_FRAC = 0.2
THRESHOLD = "val_max"


# ---------------------------------------------------------------- model
def split_validation(train: pd.DataFrame, val_frac: float = VAL_FRAC) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Last `val_frac` of the training rows (in time order) become the validation slice."""
    train = train.sort_values("ts", kind="mergesort")
    k = int(round(len(train) * (1 - val_frac)))
    return train.iloc[:k], train.iloc[k:]


def fit_forest(X: pd.DataFrame, **params) -> IsolationForest:
    return IsolationForest(**{**DEFAULTS, **params}).fit(X)


def anomaly_score(model: IsolationForest, X: pd.DataFrame) -> np.ndarray:
    """Higher = more anomalous."""
    return -model.score_samples(X)


def tukey_fence(scores: np.ndarray, k: float = 1.5) -> float:
    q1, q3 = np.percentile(scores, [25, 75])
    return float(q3 + k * (q3 - q1))


def threshold_methods(fit_scores: np.ndarray, val_scores: np.ndarray) -> dict[str, float]:
    """Candidate thresholds. None of them look at the test rows.
    val_max      highest validation score: no benign validation row alerts
        This picks the highest score of the held back normal rows, so if a row is stranger then every normal row
        it flags it
    val_p995     99.5th percentile of validation: 0.5% of validation alerts
    val_p99      99th percentile of validation: 1% of validation alerts
    tukey_val    Q3 + 1.5 IQR on the validation scores 
                     Takes a more reserved approach to threshold, it takes 75th percentile and then adds
                     1.5 iqr to it.
    tukey_train  Q3 + 1.5 IQR on the fit scores
    (run_detector adds folds_median and folds_max from fold_thresholds)"""
        
    return {
        "val_max": float(np.max(val_scores)),
        "val_p995": float(np.percentile(val_scores, 99.5)),
        "val_p99": float(np.percentile(val_scores, 99)),
        "tukey_val": tukey_fence(val_scores),
        "tukey_train": tukey_fence(fit_scores),
    }


def fold_thresholds(train, features, n_folds=5, **params):
    """Time-ordered folds: our own version of 5-fold cross-validation

    Explained simply: normal 5-fold cross-validation cuts the data into 5 pieces, trains on 4, tests on the 5th,
    and does that 5 times so every piece gets its turn. This does kind of the same but some caveats,
      1. The pieces are cut in TIME ORDER (first 20% of the training period, next 20%, ...), not by shuffling.
         Rows next to each other are near copies (rolling window), so shuffling would let the forest "peek".
      2. We do not measure accuracy on the held-back piece (it has no tunnel, only normal traffic). We ask:
         "what is the strangest normal row in this piece?" That highest score is this piece's line.
    
     Why 5 lines: every piece gets its turn to be held back, and every turn gives one line.
    So 5 turns = 5 lines, each one set on a different moment of the training period.
      - If the 5 lines are close together, it does not matter when the line was set: the line is robust.
      - If they are far apart, the line depends on WHEN it was set (quiet or busy traffic): not robust. 
        An important robustness check because normal traffic also has ups and downs so folding over 20% splits 
        important.
    folds_median takes the middle of the 5 lines, folds_max the highest (no normal row in any piece alerts).
    Returns one row per fold: fold number, start, end, rows, line."""

    train = train.sort_values("ts", kind="mergesort")                # time order
    blocks = np.array_split(np.arange(len(train)), n_folds)          # 5 pieces, equal row counts, consecutive in time
    rows = []
    for i, idx in enumerate(blocks):
        held, rest = train.iloc[idx], train.drop(train.index[idx])   # this piece held back, the other 4 to train on
        model = fit_forest(rest[features], **params)                 # a fresh forest on the other 4 pieces
        rows.append({"fold": i + 1, "start": held["ts"].min(), "end": held["ts"].max(), "rows": len(held),
                     "line": float(anomaly_score(model, held[features]).max())})   # strangest normal row = line
    return pd.DataFrame(rows)


def run_detector(m, features, threshold="val_max", val_frac=0.2, **params):
    """Fit on benign training rows, set the threshold on the validation slice, score every row.
    Returns (scored, info): scored = every row + role (fit/val/test) + score + alert; info = threshold and model. 

      **params: extra IsolationForest settings, e.g. random_state=3 or n_estimators=500. They override DEFAULTS
    (see fit_forest), so settings change without editing the code. Pass nothing and DEFAULTS apply, including
    random_state=0, so every run gives the same result."""

    assert not set(features) & set(META_COLUMNS), "metadata columns cannot be features"
    train, test = m[m["split"] == "train"], m[m["split"] == "test"]
    assert not train["y"].any(), "training rows must be benign only, do not use the tunnel rows as training"
    fit_rows, val_rows = split_validation(train, val_frac)

    # train the model on all chosen features at once
    model = fit_forest(fit_rows[features], **params)
    # Here we compute all the candidate thresholds on the validation slice then the threshold is picked which is specified up top
    candidates = threshold_methods(anomaly_score(model, fit_rows[features]), anomaly_score(model, val_rows[features]))
    # time-ordered folds: A bit like 5 fold cross val, normally it takes the last 20% of training rows
    # but what would happen when you take another block of the training slice?
    folds = fold_thresholds(train, features, **params)
    candidates["folds_median"] = float(folds["line"].median())   # middle of the 5 lines: robust to one odd block
    candidates["folds_max"] = float(folds["line"].max())         # highest line: no normal row in any block alerts
    thr = candidates[threshold]

    scored = pd.concat([fit_rows.assign(role="fit"), val_rows.assign(role="val"), test.assign(role="test")])
    scored = scored.sort_values("ts", kind="mergesort")
    scored["score"] = anomaly_score(model, scored[features])
    scored["alert"] = (scored["score"] > thr).astype(int)

    info = {"threshold_method": threshold, "threshold": thr, "candidates": candidates,
            "features": list(features), "model": model, "folds": folds}
    return scored, info

def write_scores(scored: pd.DataFrame, name: str = "scores"):
    path = PROCESSED / f"{name}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(path, index=False)
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description="Isolation Forest DNS tunnel detector")
    ap.add_argument("--features", default="forced", help="feature set from feature_sets() (default: forced)")
    ap.add_argument("--threshold", default=THRESHOLD, help="val_max, val_p995, val_p99, tukey_val, tukey_train, folds_median, folds_max")
    ap.add_argument("--val-frac", type=float, default=VAL_FRAC, help="share of training used for validation")
    ap.add_argument("--window", type=int, default=60, help="window size in seconds (default 60)")
    ap.add_argument("--seed", type=int, default=0, help="random_state of the forest")
    ap.add_argument("--checks", action="store_true",
                    help="also run the slice 4 model checks: feature importance, n_estimators/max_samples, score plot")
    args = ap.parse_args()
    if len(sys.argv) == 1:  # no options given (run button): run the model checks too
        args.checks = True

    m = load_matrix() if args.window == 60 else make_matrix(window_s=args.window, write=False)
    features = feature_sets(args.window)[args.features]
    scored, info = run_detector(m, features, threshold=args.threshold, val_frac=args.val_frac,
                                random_state=args.seed)
    path = write_scores(scored)
    print(f"wrote {path.relative_to(ROOT)} ({len(scored)} rows)\n")
    # the printout comes from src/evaluation.py (imported here so this file itself stays label-free)
    from src.evaluation import feature_importance, parameter_check, plot_score_distribution, summarize
    print(summarize(scored, info))

    if args.checks:
        t = scored[scored["role"] == "test"]
        print("\nwhich features drive the isolation (drop in PR AUC when shuffled; explanation only):")
        print(feature_importance(info["model"], t[features], t["y"].to_numpy()).round(3).to_string())
        print("\nn_estimators / max_samples check (one setting changed at a time):")
        print(parameter_check(m, features, threshold=args.threshold).round(3).to_string(index=False))
        plot = plot_score_distribution(scored, info, PROCESSED / "score_distribution.png")
        print(f"\nscore distribution plot saved to {plot.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
