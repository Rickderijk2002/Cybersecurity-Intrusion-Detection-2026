"""Figures that explain the detector (for the report and the slides).

    python -m src.plots        # default detector run, writes notebooks/figures/isolation_forest_view.png

`plot_isolation_view` takes the `scored` table and `info` dict from `run_detector`. It only draws; it never
chooses anything, and it uses the labels only for colours.
"""
from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):  # started as a loose file: make `src` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from src.prepare import ROOT

FIGURES = ROOT / "notebooks" / "figures"


def average_cuts(score, n_samples: int = 256) -> np.ndarray:
    """Turn an anomaly score back into the average number of random cuts needed to isolate a row.

    Isolation Forest defines score = 2 ** (-E[h] / c(n)), with E[h] the average path length (cuts) over the trees
    and c(n) the average path length of an unsuccessful search in a binary tree of n rows. `score` is the detector's
    score (higher = more anomalous), so E[h] = -log2(score) * c(n)."""
    n = float(n_samples)
    c = 2 * (np.log(n - 1) + np.euler_gamma) - 2 * (n - 1) / n
    return -np.log2(np.asarray(score, dtype=float)) * c


def plot_isolation_view(scored, info, path, x="uniq_names_60s", y="norepeat_tol"):
    """Two panels. Left: where normal and tunnel queries sit in feature space (feature `x` on a log scale against
    feature `y`), with the false alerts ringed. Right: how many random cuts it takes to isolate a query, normal
    against tunnel, with the alert line. Saved as a PNG; returns the path."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    test = scored[scored["role"] == "test"].copy()
    fit = scored[scored["role"] != "test"]
    thr = info["threshold"]
    n_samples = getattr(info["model"], "max_samples_", 256)
    test["cuts"] = average_cuts(test["score"], n_samples)
    normal, tunnel = test[test["y"] == 0], test[test["y"] == 1]
    false_alerts = normal[normal["score"] > thr]

    fig, (a, b) = plt.subplots(1, 2, figsize=(13, 5.2))
    a.scatter(fit[x], fit[y], s=10, c="#bbbbbb", alpha=.35, linewidths=0, label="normal, training period")
    a.scatter(normal[x], normal[y], s=14, c="#2a78d6", alpha=.45, linewidths=0, label="normal, test period")
    a.scatter(false_alerts[x], false_alerts[y], s=40, facecolors="none", edgecolors="#e69f00", linewidths=1.4,
              label=f"false alerts ({len(false_alerts)})")
    a.scatter(tunnel[x], tunnel[y], s=16, c="#d6402a", alpha=.8, linewidths=0, label="tunnel")
    a.set_xscale("log")
    a.set_xlabel(f"{x} (log scale)")
    a.set_ylabel(y)
    a.set_title("Where the queries sit in feature space", fontsize=11)
    a.legend(fontsize=8, loc="lower right", frameon=True)

    bins = np.linspace(test["cuts"].min() - .2, test["cuts"].max() + .2, 45)
    b.hist(normal["cuts"], bins=bins, color="#2a78d6", alpha=.7, label="normal (test)")
    b.hist(tunnel["cuts"], bins=bins, color="#d6402a", alpha=.85, label="tunnel (test)")
    line = float(average_cuts(thr, n_samples))
    b.axvline(line, color="k", ls="--", lw=1.4, label=f"alert line ({line:.1f} cuts)")
    b.set_yscale("log")
    b.invert_xaxis()
    b.set_xlabel("average number of random cuts needed to isolate the query (fewer = stranger)")
    b.set_ylabel("number of queries")
    b.set_title("How Isolation Forest scores: few cuts = easy to isolate = anomaly", fontsize=11)
    b.legend(fontsize=8)

    fig.tight_layout()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_capture_timeline(m, path):
    """Queries per minute, normal against tunnel, with the train/test cut: what we investigate and how we split it."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    t = pd.to_datetime(m["ts"], unit="s").dt.floor("min")
    counts = m.assign(minute=t).groupby(["minute", "y"]).size().unstack(fill_value=0)
    counts = counts.reindex(columns=[0, 1], fill_value=0)
    cut = pd.to_datetime(m.loc[m["split"] == "test", "ts"].min(), unit="s").floor("min")

    fig, ax = plt.subplots(figsize=(9, 3.3))
    w = pd.Timedelta(seconds=50)
    ax.bar(counts.index, counts[0], width=w, color="#2a78d6", label="normal queries")
    ax.bar(counts.index, counts[1], width=w, bottom=counts[0], color="#d6402a", label="tunnel queries")
    ax.axvline(cut, color="k", ls="--", lw=1.2)
    ax.set_ylim(0, ax.get_ylim()[1] * 1.18)
    top = ax.get_ylim()[1]
    ax.axvspan(counts.index.min() - w, cut, color="#2a78d6", alpha=.07)
    ax.text(counts.index.min(), top * .93, "TRAIN: normal only", fontsize=9, va="top")
    ax.text(cut + pd.Timedelta(minutes=1), top * .93, "TEST: normal + tunnel", fontsize=9, va="top")
    ax.set_ylabel("queries per minute"); ax.set_xlabel("time (UTC)")
    ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%H:%M"))
    ax.legend(fontsize=8, loc="center left", bbox_to_anchor=(0.0, 0.62))
    ax.set_title("The capture: normal DNS and one tunnel session, split at the dashed line", fontsize=11)
    fig.tight_layout()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def main() -> None:
    from src.detector import run_detector
    from src.features import feature_sets, load_matrix, make_matrix

    scored, info = run_detector(load_matrix(), feature_sets(60)["forced"])
    out = plot_isolation_view(scored, info, FIGURES / "isolation_forest_view.png")
    print(f"wrote {out.relative_to(ROOT)}")
    
    # the report's final configuration: 300 s window, val_max threshold (seed 0)
    m300 = make_matrix(window_s=300, write=False)
    scored, info = run_detector(m300, feature_sets(300)["forced"], threshold="val_max")
    out = plot_isolation_view(scored, info, FIGURES / "isolation_forest_view_300s.png", x="uniq_names_300s")
    print(f"wrote {out.relative_to(ROOT)}")
    
    out = plot_capture_timeline(load_matrix(), FIGURES / "capture_timeline.png")
    print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
