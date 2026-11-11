"""Turn the prepared queries into a numeric feature matrix.

Usage:
    from src.features import make_matrix, load_matrix, feature_sets
    m = make_matrix()                     # session="second", cut 18:30, window 60 s, writes data/processed/features.csv
    fs = feature_sets(60)                 # {"shape": [...], "context": [...], "qtype": [...], "forced": [...], "full": [...]}
    train, test = m[m.split == "train"], m[m.split == "test"]
    X_train = train[fs["forced"]]

"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from pathlib import Path

import numpy as np
import pandas as pd

from src.prepare import PROCESSED, ROOT, load_raw, prepare

META_COLUMNS = ["row_id", "ts", "split", "label", "y", "burst", "is_replay", "phase", "parent", "client"]

# record types that can carry data downstream: NULL (10) and TXT (16). Ablation switch, iodine prefers NULL.
DATA_QTYPES = (10, 16)


def feature_sets(window_s: int = 60) -> dict[str, list[str]]:
    """Named column groups. Column names carry the window size, e.g. uniq_names_60s."""
    shape = ["name_bytes", "longest_label", "entropy"]
    context = [f"uniq_names_{window_s}s", f"uniq_ratio_{window_s}s", "norepeat_evidence", "log_cum_uniq"]
    qtype = ["data_qtype"]
    return {
        "shape": shape,
        "context": context,
        "qtype": qtype,
        "forced": shape + context,
        "full": shape + context + qtype,
    }


FEATURE_SETS = feature_sets(60)  # default window


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character; 0 for an empty string."""
    if not text:
        return 0.0
    p = np.array(list(Counter(text).values())) / len(text)
    return float(-(p * np.log2(p)).sum())


def _shape_features(prep: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "name_bytes": prep["name_bytes"].to_numpy(),
        "longest_label": prep["labels_bytes"].map(lambda labels: max(map(len, labels))).to_numpy(),
        "entropy": prep["subdomain"].map(shannon_entropy).to_numpy(),
    }, index=prep.index)


def _context_features(prep: pd.DataFrame, window_s: int) -> pd.DataFrame:
    """One pass in time order. For each parent domain keep the names of the last `window_s` seconds
    (window = (ts - window_s, ts], current query included) and every name seen so far."""
    n = len(prep)
    uniq, ratio, cum, norepeat = np.empty(n), np.empty(n), np.empty(n), np.empty(n)

    recent = defaultdict(deque)      # parent -> deque[(ts, name)] inside the window
    in_window = defaultdict(Counter)  # parent -> name -> count inside the window
    seen = defaultdict(set)          # parent -> every name asked so far
    repeated = defaultdict(bool)     # parent -> has any name been asked twice so far?

    ts_all = prep["ts"].to_numpy()
    for i, (ts, name, parent) in enumerate(zip(ts_all, prep["name"], prep["parent"])):
        dq, counts = recent[parent], in_window[parent]
        while dq and dq[0][0] <= ts - window_s:
            _, old = dq.popleft()
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
        dq.append((ts, name))
        counts[name] += 1

        if name in seen[parent]:
            repeated[parent] = True
        seen[parent].add(name)

        uniq[i] = len(counts)
        ratio[i] = len(counts) / len(dq)
        cum[i] = np.log1p(len(seen[parent]))
        norepeat[i] = 0.0 if repeated[parent] else cum[i]

    return pd.DataFrame({
        f"uniq_names_{window_s}s": uniq,
        f"uniq_ratio_{window_s}s": ratio,
        "norepeat_evidence": norepeat,
        "log_cum_uniq": cum,
    }, index=prep.index)


def build_features(prep: pd.DataFrame, window_s: int = 60) -> pd.DataFrame:
    """prep: output of prepare(), sorted by ts. Returns META_COLUMNS + all feature columns."""
    if not prep["ts"].is_monotonic_increasing:
        raise ValueError("prep must be sorted by ts (use prepare())")
    out = prep[META_COLUMNS].copy()
    out = out.join(_shape_features(prep)).join(_context_features(prep, window_s))
    out["data_qtype"] = prep["qtype"].isin(DATA_QTYPES).astype(int)
    return out


def matrix_path(session: str = "second", window_s: int = 60) -> Path:
    """Default run (second, 60 s) is features.csv; other runs get their parameters in the name."""
    name = "features.csv" if (session, window_s) == ("second", 60) else f"features_{session}_{window_s}s.csv"
    return PROCESSED / name


def write_matrix(m: pd.DataFrame, session: str = "second", window_s: int = 60) -> Path:
    path = matrix_path(session, window_s)
    path.parent.mkdir(parents=True, exist_ok=True)
    m.to_csv(path, index=False)
    return path


def make_matrix(session: str = "second", cut=None, window_s: int = 60, write: bool = True) -> pd.DataFrame:
    """Load, prepare, build the features and (by default) write data/processed/*.csv.
    The whole pipeline with all outputs is `python main.py`."""
    m = build_features(prepare(load_raw(), session=session, cut=cut), window_s=window_s)
    if write:
        write_matrix(m, session, window_s)
    return m


def load_matrix(session: str = "second", window_s: int = 60) -> pd.DataFrame:
    return pd.read_csv(matrix_path(session, window_s))


def drift_table(m: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """How far does the test period move away from what training saw? For each feature: the training
    maximum, the test-benign maximum, the share of test benign rows above the training maximum, and the
    median of the tunnel rows."""
    train = m[m["split"] == "train"]
    test_benign = m[(m["split"] == "test") & (m["y"] == 0)]
    tunnel = m[m["y"] == 1]
    rows = {}
    for c in columns:
        rows[c] = {
            "train max": train[c].max(),
            "test benign max": test_benign[c].max(),
            "test benign above train max": (test_benign[c] > train[c].max()).mean(),
            "tunnel median": tunnel[c].median(),
        }
    return pd.DataFrame(rows).T.round(3)


if __name__ == "__main__":
    for session in ("second", "first"):
        m = make_matrix(session=session)
        fs = feature_sets(60)
        print(f"session={session}: {m.shape[0]} rows, wrote {matrix_path(session, 60).relative_to(ROOT)}")
        print(drift_table(m, fs["full"]), "\n")
