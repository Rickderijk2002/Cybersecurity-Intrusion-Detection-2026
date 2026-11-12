# Handoff: data pipeline for modelling

**Date:** 2026-11-12 (first version 2026-11-11). Short overview for whoever builds the detectors. It explains how the data is set up, why, and how to get going. Definitions of every column are in `docs/data_dictionary.md`; background and numbers are in `docs/Baseline findings.md`.

## 0. Start here

1. Read this file, then `docs/data_dictionary.md` (every column, the feature sets, the limits).
2. Run `python main.py --all --tests`. **`data/processed/` is git-ignored, so `features.csv` does not exist until you run this.** It needs `data/raw/dns.log` (Canvas download); `data/labels.csv` is in the repo.
3. Open `notebooks/03_features.ipynb` (run it, about 3 minutes; figures are saved in `notebooks/figures/`). Its Observations and Decisions section records why each feature is in or out.

**What is done:** data preparation, the default feature set, the strict variant, stress-test variants (`src/variants.py`), 30 acceptance tests.
**What is yours:** the detector (`src/detector.py`), the evaluation (`src/evaluation.py`), thresholds, false-positive and false-negative analysis, and the comparison with a baseline and one alternative model.

**The feature set is a starting point, not frozen.** Notebook 03 compares feature sets with Isolation Forest, but only to choose a sensible default (threshold-free ROC and PR AUC on one tunnel event). If the modelling shows a feature should change, change it in `src/features.py`, keep the old column as an ablation, update `tests/test_features.py`, `docs/data_dictionary.md` and this file, rerun `python main.py --all --tests`, and tell the group. Do not change `src/prepare.py`, the split or the labels without agreeing: they define what every result means.

## 1. The data in one minute

- `dns.log`: 3,645 DNS queries over 95 minutes (17:35 to 19:10 UTC). Every row has a label in `data/labels.csv`.
- **Benign:** 3,201 queries from one home computer. Quiet most of the time, with two busy periods (about 18:05 to 18:15 and 18:50 to 18:55).
- **Tunnel:** one `iodine` session of 222 queries that lasts 25 seconds. It appears **twice** (18:04 and 18:50) because the second one is an exact replay of the first.
- Most tunnel queries are short pings that look like normal queries. What gives the tunnel away is **how many different names one domain gets in a short time**: at most 28 for normal domains in a minute, up to 222 for the tunnel.

## 2. The setup and why

| Choice | Why |
|---|---|
| **Use only one of the two tunnel copies** | They are identical, so keeping both would double the positives and let the "never repeated a name" feature see burst 2 as a repeat of burst 1. The unused copy is removed from the whole stream. |
| **Default keeps the second one (18:50)** | It happens during a busy benign period, so it is the harder, more realistic test. It also lets training include the first busy period. |
| **Train before 18:30, test from 18:30** | 18:30 is the middle of the quiet gap, so each half holds one busy period. Training comes before testing (lecture rule), and training has no tunnel at all, so the tunnel is unseen when we test. |
| **Training is benign only** | Isolation Forest needs no labels. It learns what normal looks like. Train: 1,592 benign rows. Test: 1,609 benign + 222 tunnel. |
| **Features only look backwards in time** | The same code could score a live stream. A test checks this. |
| **Names measured in wire bytes** | Zeek writes odd bytes as `\xNN`, which would inflate lengths up to 4 times. |

The strict variant (`first`) keeps the first copy instead and cuts at 18:04:36. Training is then only 244 quiet rows, so it mostly shows what happens when the load changes between training and test.

## 3. The features (updated 2026-11-12)

Each one follows from how any DNS tunnel has to behave, not from this particular tool or lab.

| Features | What they capture |
|---|---|
| `name_bytes` | Data travels in the name, so names are long. Catches the 37 data and probe queries, not the pings. `longest_label` and `entropy` say almost the same (correlation about 0.8) and are kept as ablation columns only. |
| `uniq_names_60s`, `uniq_ratio_60s` | Caching forces a new name for every query, so one machine gets many unique names from one domain in the last 60 s. Catches the whole session. Counted per (client, parent domain). |
| `norepeat_tol` | `log(distinct names so far)` scaled by the share of queries that were new names. A long memory that also works for slow tunnels, and one repeated name barely changes it. |
| `norepeat_evidence`, `log_cum_uniq` (ablation only, set `extra`) | `norepeat_evidence` is the same idea as `norepeat_tol` but one repeated name sets it to 0 for good (best score on clean data, brittle). `log_cum_uniq` drifts with time since the start of the capture. Run both as ablations. |
| `data_qtype` | 1 if the record type is NULL or TXT. An on/off switch for an ablation, because NULL is iodine's choice. |

Feature sets (`feature_sets(60)`): `shape`, `context`, `qtype`, `forced` (shape + context, **the default**: `name_bytes`, `uniq_names_60s`, `uniq_ratio_60s`, `norepeat_tol`), `full` (forced + qtype), `extra` (`longest_label`, `entropy`, `norepeat_evidence`, `log_cum_uniq`), `all` (everything).

**Why this default (2026-11-12):** it should hold for any DNS tunnel and not depend on how this iodine run behaves.
- **One shape feature:** `name_bytes`, `longest_label` and `entropy` correlate about 0.8, and Isolation Forest picks features at random, so three shape features crowd out the context features (strict PR AUC 0.974 with one, 0.658 with three; with 20 simulated hosts 0.987 against 0.70). The choice of `name_bytes` rests on redundancy; the numbers are mixed (see notebook 03).
- **`norepeat_tol` as default:** when a single tunnel name is repeated once, `norepeat_evidence` falls from PR AUC 0.997 to 0.956; `norepeat_tol` stays at 0.993. On clean data `norepeat_evidence` is slightly better, so report both.
- **`log_cum_uniq` out:** it drifts with time since the start of the capture.
- **Per (client, parent) counting:** changes no value in this capture (one benign client, one tunnel client) and the noisy-host simulation did not show a benefit; it is a design choice for networks with many hosts.

**Deliberately left out:** IPs, ports, AA/RA flags, TTL, EDNS0, `rtt`, NXDOMAIN, raw query volume and domain names. They separate the classes here only because of the lab set-up.

## 4. Running it and the different setups

```bash
uv pip install -r requirements.txt      # once
python main.py                          # default run: tunnel = 18:50, cut 18:30, window 60 s
python main.py --all --tests            # default + strict variant, and run the checks
python main.py --window 60 300 900      # several window sizes (for slow tunnels)
python main.py --session first          # only the first tunnel copy
python main.py --cut "2023-01-07 18:20:00"   # another train/test cut
```

Needs `data/raw/dns.log` (Canvas download). Output in `data/processed/`:

| File | Use |
|---|---|
| `features.csv` | **Start here.** Default run |
| `features_first_60s.csv` | Strict variant, for a robustness comparison |
| `features_second_300s.csv` and similar | Other window sizes |
| `prepared*.csv` | The readable table behind the features, to inspect names and parents |

```python
from src.features import load_matrix, feature_sets
m = load_matrix()                                  # features.csv
fs = feature_sets(60)
train, test = m[m.split == "train"], m[m.split == "test"]
X_train, X_test, y_test = train[fs["forced"]], test[fs["forced"]], test["y"]
```

The features are raw (not scaled) and all numeric. Isolation Forest does not need scaling; for LOF or one-class SVM, fit the scaler on the training rows only.

Never use `ts`, `label`, `y`, `split`, `burst`, `is_replay`, `phase`, `parent` or `client` as features. They are metadata, kept for evaluation and error analysis.

## 5. Suggested approach for the modelling

1. **Isolation Forest** on `forced`, fitted on the training rows only. No scaling needed.
2. **Choose the threshold without the test rows.** Options: a percentile of the scores on a benign validation slice (for example the last part of the training period), or Tukey (Q3 + 1.5 times the IQR) on the training scores as one baseline. Tukey on the training scores is poorly calibrated here (section 7), so compare. Do not tune on the test rows. Note that `contamination` isn't used; say why in the report.
3. **Evaluate on the test rows:** precision, recall, F1, FPR, ROC and PR AUC, recall per `phase`, and look at the top false positives (CDN and cloud names are likely).
4. **Compare with simple baselines**, as the lecture suggests: a length + entropy rule, and Tukey or MAD on `uniq_names_60s` alone. The simple one may do as well. If so, say so.
5. **Stress tests:** `forced` against `full` (does the record type matter?), window sizes, the strict variant, and a slow-tunnel simulation.

## 6. Things to be honest about in the report

- One tunnel session (shown twice), one tool, one benign client, 95 minutes. We can't claim it generalises to other tunnels.
- The tunnel is loud, so results will probably look strong. The slow-tunnel test is where limits show.
- The start of a session looks benign until evidence builds up (about 12% of the tunnel).
- 6.5% of rows are tunnel, far more than in a real network, so precision is optimistic.

## 7. Check these early (stress tests for the modelling)

- **Threshold risk:** a Tukey threshold from the training scores flags about 170 benign rows in the primary run (precision about 0.56), mostly `yahoo.com` and `yahoodns.net` in the 18:50 busy period, and about 1,170 in the strict run (precision about 0.16). The default ranks the tunnel better than before (see notebook 03) but the threshold from training scores is poorly calibrated, so this is the first thing to fix. Training is calm (at most 16 unique names in 60 s, against 28 in the benign test traffic). Choose thresholds on a benign validation slice at the end of the training period, never on the test rows.
- **A simple rule is a strong baseline:** `uniq_names_60s > 28` gives precision 1.0 and recall 0.87 on the test rows (the 28 was read off the test data, so this is optimistic).
- **Ablations:** `forced` against `forced` + `norepeat_evidence`, `log_cum_uniq`, `data_qtype`; windows 60, 300, 900.
- **Repeat injection (`inject_repeats`):** repeat one tunnel name once and compare `norepeat_evidence` with `norepeat_tol`.
- **Event-level metrics:** the 222 test positives are one correlated session. Report time to first alert next to row-level precision and recall.
- **Other cuts:** try `--cut` values besides 18:30.

## 8. Stress-test variants (built: `src/variants.py`)

`add_benign_clients(prep, n_extra)` (more benign hosts that share domains and partly ask host-specific names), `collapse_clients(prep)` (count per parent only, the behaviour before the per-client grouping), `slow_tunnel(prep, k)` (tunnel k times slower) and `inject_repeats(prep, n)`. Each returns a table in the `prepare()` format, with training still benign only; pass it to `build_features()`. Tested in `tests/test_variants.py`.

First results (primary run, ROC / PR AUC, Isolation Forest, simulated data): with 1 to 20 benign hosts, `name_bytes` + context stays at PR 0.986 to 0.993, while the three shape features + context fall from PR 0.980 to 0.699. Per-parent counting did not do worse than per-client counting here, because the tunnel domain is only asked by the tunnel host and `uniq_ratio` and `norepeat_tol` still separate it; the per-client grouping is a design choice that this simulation does not confirm. Slow tunnels up to 60 times slower (about 25 minutes) stay at ROC 0.99 or higher.

Simulations built from one capture: they test robustness, they do not prove generalisation. Still to build: short-name and long-name low-rate tunnels, other record types, a tunnel domain that other hosts also ask.

## 9. Not built yet

`src/detector.py` (train, score every row, write `scores.csv` for the evaluation) and `src/evaluation.py` (metrics, event-level metrics, false-positive and false-negative case studies). See `docs/Task division.md` for who owns what.
