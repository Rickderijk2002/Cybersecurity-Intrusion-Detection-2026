# Handoff: data pipeline for modelling

**Date:** 2026-11-11. Short overview for whoever builds the detectors. It explains how the data is set up, why, and how to get going. Definitions of every column are in `docs/data_dictionary.md`; background and numbers are in `docs/Baseline findings.md`.

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

## 3. The eight features

Each one follows from how any DNS tunnel has to behave, not from this particular tool or lab.

| Features | What they capture |
|---|---|
| `name_bytes`, `longest_label`, `entropy` | Data travels in the name, so names are long and random-looking. Catches the 37 data and probe queries, not the pings. |
| `uniq_names_60s`, `uniq_ratio_60s` | Caching forces a new name for every query, so one domain gets many unique names in the last 60 s. Catches the whole session. |
| `norepeat_evidence` | Grows while a domain has never asked the same name twice. A long memory that also works for slow tunnels. |
| `log_cum_uniq` | Total distinct names so far. Optional: it drifts with time, so check it. |
| `data_qtype` | 1 if the record type is NULL or TXT. An on/off switch for an ablation, because NULL is iodine's choice. |

Feature sets (`feature_sets(60)`): `shape`, `context`, `qtype`, `forced` (shape + context), `full` (forced + qtype).

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
2. **Threshold from the training scores** (Tukey: Q3 + 1.5 times the IQR), so no labels are used. Note that `contamination` isn't used; say why in the report.
3. **Evaluate on the test rows:** precision, recall, F1, FPR, ROC and PR AUC, recall per `phase`, and look at the top false positives (CDN and cloud names are likely).
4. **Compare with simple baselines**, as the lecture suggests: a length + entropy rule, and Tukey or MAD on `uniq_names_60s` alone. The simple one may do as well. If so, say so.
5. **Stress tests:** `forced` against `full` (does the record type matter?), window sizes, the strict variant, and a slow-tunnel simulation.

## 6. Things to be honest about in the report

- One tunnel session (shown twice), one tool, one benign client, 95 minutes. We can't claim it generalises to other tunnels.
- The tunnel is loud, so results will probably look strong. The slow-tunnel test is where limits show.
- The start of a session looks benign until evidence builds up (about 12% of the tunnel).
- 6.5% of rows are tunnel, far more than in a real network, so precision is optimistic.

## 7. Not built yet

`variants.py` (the slow-tunnel simulation) and `evaluate.py` (metrics helpers). Agree who writes them.
