"""Run the whole data-preparation pipeline: dns.log + labels -> prepared table -> feature matrix.

    python main.py                                  # default run: session second, cut 18:30 UTC, window 60 s
    python main.py --all                            # default run + strict variant (session first, cut 18:04:36)
    python main.py --session first --window 60 300 900
    python main.py --session second --cut "2023-01-07 18:20:00"
    python main.py --tests                          # run the acceptance tests after the pipeline

Outputs (data/processed/, see docs/data_dictionary.md):
    prepared.csv, prepared_<session>.csv     one row per query with the derived columns, to inspect
    features.csv, features_<session>_<w>s.csv   the feature matrix the models use
"""
from __future__ import annotations

import argparse
import subprocess
import sys

import pandas as pd

from src.features import build_features, drift_table, feature_sets, write_matrix
from src.prepare import ROOT, load_raw, prepare, write_prepared


def run(session: str, windows: list[int], cut: str | None, raw: pd.DataFrame) -> None:
    prep = prepare(raw, session=session, cut=cut)
    path = write_prepared(prep, session)
    print(f"\n=== session={session} ===")
    print(f"prepared: {len(prep)} rows -> {path.relative_to(ROOT)}")
    print(prep.groupby(["split", "label"]).size().unstack(fill_value=0).to_string())

    for window_s in windows:
        m = build_features(prep, window_s=window_s)
        path = write_matrix(m, session, window_s)
        fs = feature_sets(window_s)
        print(f"\nfeatures (window {window_s} s): {m.shape[0]} rows x {m.shape[1]} columns -> {path.relative_to(ROOT)}")
        print("test benign rows above the training maximum, per feature:")
        print(drift_table(m, fs["all"])[["train max", "test benign max", "test benign above train max"]].to_string())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--session", choices=["second", "first", "both"], default="second",
                    help="which copy of the tunnel session stays in the stream (default: second)")
    ap.add_argument("--all", action="store_true", help="run the default (second) and the strict (first) variant")
    ap.add_argument("--window", type=int, nargs="+", default=[60], help="window sizes in seconds (default: 60)")
    ap.add_argument("--cut", default=None, help="train/test cut, UTC, e.g. '2023-01-07 18:30:00' (default per session)")
    ap.add_argument("--tests", action="store_true", help="run the acceptance tests afterwards")
    args = ap.parse_args()

    if args.all and args.cut:
        ap.error("--cut cannot be combined with --all (each session has its own default cut)")

    raw = load_raw()
    print(f"loaded dns.log: {len(raw)} rows, labels joined by row_id: {raw['label'].value_counts().to_dict()}")
    for session in (["second", "first"] if args.all else [args.session]):
        run(session, args.window, args.cut, raw)

    if args.tests:
        print("\n=== tests ===")
        code = 0
        for test in ("tests/test_prepare.py", "tests/test_features.py", "tests/test_variants.py"):
            code |= subprocess.run([sys.executable, str(ROOT / test)], cwd=ROOT).returncode
        return code
    return 0


if __name__ == "__main__":
    sys.exit(main())
