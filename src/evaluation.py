"""Evaluation: check the detector's alerts against the labels (basic results, for tweaking the detector).

Input: the `scored` table from run_detector (one row per DNS query, with y, score, alert and role).
Only the test rows are checked.

    from src.evaluation import summarize
    print(summarize(scored, info))

Slice 4 model checks (also here, because they use the labels):
    feature_importance   which features drive the isolation (permutation check)
    parameter_check      does the number of trees (n_estimators) or the sample size (max_samples) matter?
    plot_score_distribution   how the scores of normal and tunnel rows are spread, with the line
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score


def _clock(ts) -> str:
    """Unix time -> 'HH:MM:SS'."""
    return pd.to_datetime(ts, unit="s").strftime("%H:%M:%S")


def confusion(y, alert) -> dict:
    """TP/FP/FN/TN and precision, recall, F1, false-positive rate."""
    y, alert = np.asarray(y).astype(int), np.asarray(alert).astype(int)
    tp, fp = int(((alert == 1) & (y == 1)).sum()), int(((alert == 1) & (y == 0)).sum())
    fn, tn = int(((alert == 0) & (y == 1)).sum()), int(((alert == 0) & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall, f1=f1,
                fpr=fp / (fp + tn) if fp + tn else 0.0)


def recall_per_phase(t: pd.DataFrame) -> pd.DataFrame:
    """Per tunnel phase (ping, data, size_probe, handshake, encoding_test): how many queries, how many alerted."""
    tun = t[t["y"] == 1]
    return tun.groupby("phase")["alert"].agg(queries="size", detected="sum", recall="mean")


def threshold_table(t: pd.DataFrame, candidates: dict) -> pd.DataFrame:
    """What every candidate threshold would give on the test rows (compare only, do not choose on this)."""
    rows = {}
    for name, thr in candidates.items():
        c = confusion(t["y"], t["score"] > thr)
        rows[name] = {"threshold": thr, **{k: c[k] for k in ("precision", "recall", "f1", "fp", "fn")}}
    return pd.DataFrame(rows).T


def summarize(scored: pd.DataFrame, info: dict) -> str:
    t = scored[scored["role"] == "test"]
    c = confusion(t["y"], t["alert"])
    show = ["time", "parent", "score"] + info["features"]
    fp = t[(t["alert"] == 1) & (t["y"] == 0)].sort_values("score", ascending=False).assign(
        time=lambda d: d["ts"].map(_clock))
    fn = t[(t["alert"] == 0) & (t["y"] == 1)].assign(time=lambda d: d["ts"].map(_clock))

    out = [
        f"features: {info['features']}",
        f"threshold: {info['threshold_method']} = {info['threshold']:.4f}",
        "",
        f"ROC AUC {roc_auc_score(t['y'], t['score']):.3f} | PR AUC {average_precision_score(t['y'], t['score']):.3f}",
        f"precision {c['precision']:.3f} | recall {c['recall']:.3f} | F1 {c['f1']:.3f} | FPR {c['fpr']:.4f}",
        f"TP {c['tp']} | FP {c['fp']} | FN {c['fn']} | TN {c['tn']}",
        "",
        "recall per tunnel phase:\n" + recall_per_phase(t).round(3).to_string(),
        "",
        "false positives per domain:\n" + (fp["parent"].value_counts().to_string() if len(fp) else "none"),
        "",
        "top 10 false positives:\n" + (fp[show].head(10).round(3).to_string(index=False) if len(fp) else "none"),
        "",
        "missed tunnel queries:\n" + (fn[show].round(3).to_string(index=False) if len(fn) else "none"),
        "",
        "time-ordered folds (line = highest score of the held-back block):\n"
        + info["folds"].assign(start=lambda d: d["start"].map(_clock), end=lambda d: d["end"].map(_clock))
        .round(4).to_string(index=False),
        "",
        "every threshold method on the test rows (compare only, do not choose on this):\n"
        + threshold_table(t, info["candidates"]).round(3).to_string(),
    ]
    return "\n".join(out)


# ---------------------------------------------------------------- slice 4: model checks
def feature_importance(model, X: pd.DataFrame, y, n_repeats: int = 10, seed: int = 0) -> pd.Series:
    """Which features drive the isolation? Shuffle one feature at a time (10 times) and measure how much PR AUC
    drops. Big drop = the model leans on that feature. Uses labels, so it EXPLAINS the model only; never use it
    to choose features (that would be tuning on the test rows)."""
    rng = np.random.default_rng(seed)
    base = average_precision_score(y, -model.score_samples(X))
    out = {}
    for c in X.columns:
        drops = []
        for _ in range(n_repeats):
            Xp = X.copy()
            Xp[c] = rng.permutation(Xp[c].to_numpy())
            drops.append(base - average_precision_score(y, -model.score_samples(Xp)))
        out[c] = float(np.mean(drops))
    return pd.Series(out, name="PR AUC drop").sort_values(ascending=False)


def parameter_check(m: pd.DataFrame, features: list[str], threshold: str = "val_max") -> pd.DataFrame:
    """Does the number of trees or the sample size per tree matter? Changes one setting at a time, the rest
    stays at the defaults (300 trees, max_samples 'auto' = 256 rows per tree, seed 0)."""
    from src.detector import run_detector   # imported here: detector.py itself never imports this file at the top
    settings = [{"n_estimators": n} for n in (50, 100, 300, 1000)]
    settings += [{"max_samples": s} for s in (64, 128, 512, 1.0)]   # 1.0 = all fit rows per tree
    rows = []
    for params in settings:
        scored, info = run_detector(m, features, threshold=threshold, **params)
        t = scored[scored["role"] == "test"]
        c = confusion(t["y"], t["alert"])
        rows.append({"setting": ", ".join(f"{k}={v}" for k, v in params.items()), "threshold": info["threshold"],
                     "roc_auc": roc_auc_score(t["y"], t["score"]), "pr_auc": average_precision_score(t["y"], t["score"]),
                     "precision": c["precision"], "recall": c["recall"], "fp": c["fp"], "fn": c["fn"]})
    return pd.DataFrame(rows)


def plot_score_distribution(scored: pd.DataFrame, info: dict, path):
    """Histogram of the test scores, normal (grey) and tunnel (red), with the chosen line and the fold lines.
    Saved as a PNG; returns the path."""
    import matplotlib
    matplotlib.use("Agg")                    # save to file, no window needed
    import matplotlib.pyplot as plt
    t = scored[scored["role"] == "test"]
    bins = np.linspace(scored["score"].min(), scored["score"].max(), 60)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.hist(t.loc[t["y"] == 0, "score"], bins=bins, color="#95a5a6", label="normal (test)")
    ax.hist(t.loc[t["y"] == 1, "score"], bins=bins, color="#c0392b", alpha=0.85, label="tunnel (test)")
    ax.axvline(info["threshold"], color="black", ls="--", lw=1.5,
               label=f"line: {info['threshold_method']} = {info['threshold']:.3f}")
    for line in info["folds"]["line"]:
        ax.axvline(line, color="black", ls=":", lw=0.8, alpha=0.6)
    ax.plot([], [], color="black", ls=":", lw=0.8, label="fold lines")
    ax.set(xlabel="anomaly score (higher = stranger)", ylabel="number of queries", yscale="log",
           title="Isolation Forest score distribution (test rows)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path
