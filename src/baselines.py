"""Simple rule baselines to compare the Isolation Forest against.

A rule has nothing to fit: it scores each query with one number and alerts when that number is higher than
anything seen in normal training traffic. The result has the same format as `run_detector` (a `scored` table
with role, score and alert), so `src/evaluation.py` and `src/incidents.py` work on it unchanged.

    from src.baselines import run_rule
    scored = run_rule(m, "unique_names")        # alert when uniq_names_60s exceeds its training maximum
    scored = run_rule(m, "shape")               # alert when the name is longer or has higher entropy than in training

Kinds:
    unique_names   score = uniq_names_<window>s (distinct names per client and domain in the window)
    shape          score = max(name_bytes / training max, entropy / training max): a long or random-looking name

The line is the highest score on `threshold` rows: "train_max" (all training rows, the default, since a rule has
nothing to fit) or "val_max" (only the validation slice, the same rows the detector uses for its line).
Test rows are never used to choose anything. `scored.attrs["threshold"]` holds the line.
"""
from __future__ import annotations

import pandas as pd

from src.detector import VAL_FRAC, split_validation

KINDS = ("unique_names", "shape")


def _scale(ref: pd.DataFrame, kind: str, window_s: int) -> dict:
    if kind == "unique_names":
        return {}
    return {"name_bytes": float(ref["name_bytes"].max()), "entropy": float(ref["entropy"].max())}


def _score(frame: pd.DataFrame, kind: str, window_s: int, scale: dict) -> pd.Series:
    if kind == "unique_names":
        return frame[f"uniq_names_{window_s}s"].astype(float)
    return pd.concat([frame["name_bytes"] / scale["name_bytes"], frame["entropy"] / scale["entropy"]], axis=1).max(axis=1)


def run_rule(m: pd.DataFrame, kind: str = "unique_names", window_s: int = 60, threshold: str = "train_max",
             val_frac: float = VAL_FRAC) -> pd.DataFrame:
    """Score every row with the rule and alert above the highest score on the reference rows."""
    assert kind in KINDS, f"kind must be one of {KINDS}"
    assert threshold in ("train_max", "val_max"), "threshold must be train_max or val_max"
    train, test = m[m["split"] == "train"], m[m["split"] == "test"]
    assert not train["y"].any(), "training rows must be benign only"
    fit_rows, val_rows = split_validation(train, val_frac)
    ref = train if threshold == "train_max" else val_rows

    scale = _scale(ref, kind, window_s)
    line = float(_score(ref, kind, window_s, scale).max())
    scored = pd.concat([fit_rows.assign(role="fit"), val_rows.assign(role="val"), test.assign(role="test")])
    scored = scored.sort_values("ts", kind="mergesort")
    scored["score"] = _score(scored, kind, window_s, scale)
    scored["alert"] = (scored["score"] > line).astype(int)
    scored.attrs["threshold"] = line
    scored.attrs["rule"] = kind
    return scored
