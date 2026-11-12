# Data dictionary: feature matrix

**Date:** 2026-11-12 (updated: client grouping, `norepeat_tol`, new default sets, shape block trimmed to `name_bytes`). Describes `data/processed/features.csv` (and the variants) produced by `src/prepare.py` and `src/features.py`. Seeds report section 3.1 (features). Numbers come from the default run and were checked by `tests/test_prepare.py` and `tests/test_features.py`.

## How the matrix is made

| Setting | Default | Meaning |
|---|---|---|
| `session` | `"second"` | Which copy of the tunnel session stays. The capture holds the same 222-query session twice (a byte-for-byte replay). The other burst is removed from the whole stream, so it cannot distort windows or the "never repeated a name" feature. `"first"` is the strict variant, `"both"` is for an appendix only. |
| `cut` | 18:30 UTC (`second`), 18:04:36 (`first`) | Train = rows before the cut, test = rows from the cut on. Training is benign only in both runs. |
| `window_s` | 60 | Length in seconds of the rolling window in the context features. Column names carry it (`uniq_names_60s`, `uniq_names_300s`). |

Rows: 3,423 per single session (3,201 benign + 222 tunnel). Default run: train 1,592 rows (benign only), test 1,831 rows (1,609 benign + 222 tunnel). Strict run: train 244, test 3,179.

Conventions:
- **One row per query**, sorted by `ts`. `row_id` is the 0-based position in `dns.log` file order; labels were joined on it before sorting.
- **Per client and parent:** the context features are computed per (client, parent domain): one machine asking one domain. In this capture each parent has only one client behind it, so the values equal a per-parent count; the grouping matters in networks with many hosts. `client` splits the groups and is never a feature.
- **Causal:** a row's context features use only rows up to and including itself in time order. Tested by removing all later rows.
- **Wire bytes:** Zeek writes each non-printable byte as `\xNN`; it is turned back into one byte before any length is measured.
- **Lower case:** `dns.log` lower-cases every name (0 of 3,645 names contain an uppercase letter). Entropy is therefore measured on lower-cased names. For the data queries the median is 5.56 bits per character on the log, against 5.75 in the report, which was measured on the original packets.
- **Parent domain:** registered domain from the public suffix list (ICANN suffixes, offline snapshot), lower-cased, with the last two labels as fallback for names the list does not know (`pirate.sea`).

## Metadata columns (never features)

| Column | Meaning |
|---|---|
| `row_id` | 0-based position of the row in `dns.log`. Key to `data/labels.csv` |
| `ts` | Unix timestamp of the query (UTC) |
| `split` | `train` or `test`, by the cut |
| `label` | `benign` or `tunnel` (rule: the name ends in `pirate.sea`) |
| `y` | 1 for tunnel, 0 for benign |
| `burst` | 0 benign, 1 or 2 tunnel session copy |
| `is_replay` | True for burst 2 rows |
| `phase` | Tunnel rows: `handshake` (v, l, n), `encoding_test` (y, z, s, o), `size_probe` (r), `ping` (p), `data` (user-ID prefix). Benign rows: `benign`. Derived from iodine's prefix letters, so only for error analysis |
| `parent` | Parent (registered) domain, half of the grouping key of the context features |
| `client` | Source IP of the query, the other half of the grouping key. An identifier for alerts, not a feature |

Phase counts per tunnel session: 173 pings, 24 data, 13 size probes, 3 handshake, 9 encoding tests.

## Feature columns

The test for every feature: does it follow from how any DNS tunnel has to behave? Table 2.5 rows refer to the report. "Evidence" is benign against tunnel in the default run.

| Column | Definition | Table 2.5 row | Hypothesis it tests | Evidence |
|---|---|---|---|---|
| `name_bytes` | Wire length of the full name in bytes. **The default shape feature** | 2 | Data travels in the name, so names are long | Median 20 / 19, max 103 / 252. Only data and probe queries stand out |
| `longest_label` (ablation) | Longest label in bytes (DNS limit 63) | 2 | Payload fills labels up to the limit | Median 9 / 8, max 57 / 62 |
| `entropy` (ablation) | Shannon entropy (bits per character) of the subdomain, dots included; 0 if there is none | 3 | Compressed or encrypted data looks random | Median 2.50 / 2.75, max 4.53 / 6.30; data queries about 5.56 |
| `uniq_names_60s` | Distinct names under the parent in the last 60 s (window = `(ts - 60, ts]`, current query included) | 1, 4 | Caching forces a new name for every query | Median 1 / 111.5, max 28 / 222 |
| `uniq_ratio_60s` | `uniq_names_60s` divided by the number of queries in that window | 1 | A tunnel almost never repeats a name; normal clients ask the same name as A, AAAA and HTTPS | Median 0.40 / 1.0 |
| `norepeat_tol` | `log1p(distinct names so far)` times (distinct names so far / queries so far), per (client, parent). **Default.** | 1 | Same idea with a long memory (works for slow tunnels), but one repeated name only lowers it slightly | Median 0.40 / 4.72, max 2.05 / 5.41 |
| `norepeat_evidence` | `log1p(distinct names so far)` while the pair has never asked the same name twice, else 0. **Ablation only** | 1 | Same. Best score on clean data, but one repeated name (a retransmission, or an attacker) sets it to 0 for the rest of the capture | Median 0 / 4.72, max 1.61 / 5.41 |
| `log_cum_uniq` | `log1p(distinct names so far)`. **Ablation only** | 1 | Cumulative variety. Grows with time since capture start, so it drifts by construction | Median 1.39 / 4.72, max 3.58 / 5.41 |
| `data_qtype` | 1 if the record type is NULL (10) or TXT (16) | 5 | Downstream data needs a record type that can hold it | 0 for every benign row, 1 for every tunnel row. Ablation switch: NULL is iodine's choice |

### Feature sets (`feature_sets(window_s)`)

| Set | Columns |
|---|---|
| `shape` | `name_bytes` |
| `context` | `uniq_names_<w>s`, `uniq_ratio_<w>s`, `norepeat_tol` |
| `qtype` | `data_qtype` |
| `forced` | `shape` + `context`. **The default** |
| `full` | `forced` + `qtype` |
| `extra` | `longest_label`, `entropy`, `norepeat_evidence`, `log_cum_uniq`: kept for ablations, not in the default |
| `all` | every feature column (`full` + `extra`) |

Why `longest_label` and `entropy` are not in the default: they correlate about 0.8 with `name_bytes` on benign training rows, so they add little information, and with three shape features Isolation Forest puts about half of its splits on the block that carries the least signal here. One shape feature plus the context features ranked clearly better (primary PR AUC 0.993 against 0.975; strict 0.974 against 0.658) and stayed stable when the simulated network grew to 20 benign hosts (PR 0.987), where three shape features fell to 0.70. Note that this is about ranking; at a Tukey threshold taken from the training scores the trimmed set raises more alerts in the strict run (about 1,170 false positives against about 530), so choose thresholds on a validation slice. The choice of `name_bytes` rests on redundancy, not on the test numbers; recheck it in the slow-tunnel and long-name variants.

Why `norepeat_evidence` and `log_cum_uniq` are not in the default: the first breaks on a single repeated name (with one injected repeat in the tunnel, PR AUC fell from 0.997 to 0.956 and ROC AUC from 0.998 to 0.994; `norepeat_tol` stayed at 0.993 and 0.996), the second drifts with time. On clean data `norepeat_evidence` is slightly better (primary run, 10 seeds: ROC AUC 0.998 against 0.996, PR AUC 0.997 against 0.993; strict 0.991 against 0.974), so report both.

### Drift between training and test (default run)

Share of test benign rows above the training maximum: `uniq_names_60s` 3.2%, `log_cum_uniq` 7.6%, `longest_label` 0.7%, `norepeat_tol` 0.5%, `entropy` 0.2%, `norepeat_evidence` 0%. `log_cum_uniq` drifts the most. The strict run (244 quiet training rows) drifts more: 17.1% for `uniq_names_60s` and 19.6% for `log_cum_uniq`.

## Deliberately not features

| Column or signal | Why not |
|---|---|
| IPs, source and destination ports | Separate the classes perfectly only because of the lab set-up (one tunnel client, one benign client) |
| AA, RA flags; direct queries to the server | Easy to avoid by sending queries through the resolver (Table 2.5 row 7) |
| TTL, EDNS0 | Programming details; EDNS0 is not in Zeek (Table 2.5 row 8) |
| `rtt` | Tunnel 0.05 ms against 28 ms for the benign router: a lab artefact |
| NXDOMAIN, `rcode_name` | All 11 NXDOMAIN rows are benign; the tunnel never gets one |
| Raw query volume | Points at the wrong client (benign peak 598 per minute against 221) |
| Domain identity | Only about half of the benign domains seen in training come back in the test period (172 in training, 163 in test, 88 in both) |
| Base128 / non-ASCII bytes, iodine prefix letters | iodine specific (Table 2.5 row 6). The names are lower-cased in the log anyway |
| `phase`, `burst`, `is_replay`, `label`, `y`, `split`, `ts` | Metadata or ground truth |

## Limits to state in the report

- One tunnel session (shown twice in the capture), one tool, one benign client, 95 minutes. Nothing here shows generalisation to other tunnel tools.
- **The start of a session looks benign on the context features.** The first tunnel queries have `uniq_names_60s` of 1, 2, 3 ... and `norepeat_evidence` of 0.69, 1.10, 1.39 ..., the same as a new benign domain. The evidence builds up over the first dozen queries.
- A 60 s window is short for a slow tunnel: a domain that gets one query per window looks like a rarely used benign domain. Longer windows (`window_s` 300 or 900) and `norepeat_tol` address this.
- Parent domains use ICANN suffixes only, so subdomains of providers like `cloudfront.net` count as one domain.
- With one benign client, the per-client grouping cannot be tested on this capture; it is a design choice for networks with many hosts.
- 6.5% of the rows are tunnel (222 of 3,423), far above a real network, so precision measured here is optimistic.

## Files

| File | Content |
|---|---|
| `main.py` | Runs the whole pipeline and writes all files below: `python main.py` (default run), `python main.py --all` (default + strict), `--window 60 300 900`, `--cut "..."`, `--tests` |
| `data/processed/prepared.csv` | Prepared table of the default run, one row per query, to inspect (all derived columns except the list column `labels_bytes`) |
| `data/processed/prepared_first.csv` | Same for the strict run |
| `data/processed/features.csv` | Feature matrix, default run: `second`, cut 18:30, 60 s window |
| `data/processed/features_first_60s.csv` | Feature matrix, strict run: `first`, cut 18:04:36 |
| `src/prepare.py` | `load_raw()`, `prepare(df, session, cut)`, `write_prepared()` |
| `src/features.py` | `build_features()`, `make_matrix()`, `load_matrix()`, `write_matrix()`, `feature_sets()`, `drift_table()` |
| `src/variants.py` | Stress-test tables: `add_benign_clients()`, `collapse_clients()`, `slow_tunnel()`, `inject_repeats()` |
| `tests/test_prepare.py`, `tests/test_features.py`, `tests/test_variants.py` | Acceptance checks, run with `python tests/test_features.py` |

```python
from src.features import load_matrix, feature_sets
m = load_matrix()                      # features.csv
fs = feature_sets(60)
train, test = m[m.split == "train"], m[m.split == "test"]
X_train, X_test = train[fs["forced"]], test[fs["forced"]]   # default set
y_test = test["y"]
```
