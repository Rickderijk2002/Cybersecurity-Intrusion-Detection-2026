# Baseline findings: what normal DNS looks like, and what that means for the model

**Date:** 2026-11-10. **Source:** `notebooks/02_baseline.ipynb`, run on `dns.log` only (labels from `data/labels.csv`, joined by `row_id` before any sorting). Name lengths are in wire bytes (Zeek's `\xNN` escapes counted as one byte). Feeds step 2 (features) of `docs/tmp-phase-2-plan.md`.

## The conclusion in two sentences

A DNS tunnel does not stand out in any single query: most of its queries look like normal ones. It stands out in **how many different names one domain receives in a short time**, and that is the signal the model should be built around.

## The data we compare

| | Benign | Tunnel |
|---|---|---|
| Rows | 3,201 | 444 (222 distinct queries, each present twice because the second burst is a replay) |
| Client | one home computer (`192.168.179.21`) | `10.0.2.30` |
| Parent domains | 244 | 1 (`pirate.sea`) |
| Distinct names | 670 | 222 |

## What we found

### 1. Record types and response codes

| | Benign | Tunnel |
|---|---|---|
| Record types | A 1,199, AAAA 882, HTTPS 1,110, PTR 7, SVCB 3 | NULL 444 |
| NXDOMAIN | 11 | 0 |
| No answer | 1 | 20 |

- NULL only occurs in the tunnel, but that is iodine's behaviour. A tool that falls back to TXT, CNAME or A would not show it.
- NXDOMAIN does not mark this tunnel (all 11 are benign).

### 2. Shape of single names (per query)

| Measure | Benign | Tunnel |
|---|---|---|
| Name length, median (bytes) | 20 | 19 |
| Name length, 95th percentile | 51 | 252 |
| Name length, max | 103 | 252 |
| Longest label, 95th percentile | 17 | 62 (limit is 63) |
| Entropy, median (bits per character) | 2.52 | 2.75 |
| Entropy, max | 4.53 | 6.30 |
| Number of labels, median | 3 | 3 |

- The medians are almost the same because 173 of the 222 tunnel queries are short pings. Only the data and size-probe queries (37 of 222) have long, random-looking names.
- Number of labels does not separate the classes.

### 3. Benign look-alikes (where false positives will come from)

- 201 benign rows have entropy above 4 bits per character (56 tunnel rows do). An entropy threshold alone flags many normal queries.
- 16 benign rows are longer than 63 bytes; 12 have a label over 40 bytes.
- These are CDN and cloud names, for example `...cosmic.office.net` (103 bytes), `pe80430c73-...fastcast.semfs.engsvc.go.com`, `146-241-85-122_s-78-134-83-209_ts-...akamaihd.net` and `slyvk6sqincawy5zx5fa-...akamaihd.net`.

### 4. Unique names per domain: the strong signal

| | Benign | Tunnel |
|---|---|---|
| Most unique names under one domain, whole capture | 35 (`yahoo.com`), then `google.com` 27, `yahoodns.net` 20, `azure.com` 17 | 222 |
| Most unique names under one domain in one minute | 27 (`yahoo.com`, 18:50) | 221 |
| Benign (domain, minute) pairs reaching 10 / 20 unique names | 6 / 1 (of 711 pairs) | |

**A trap in this result.** The second tunnel burst falls across a minute boundary, so fixed one-minute bins give 26 names in the 18:50 bin and 196 in the 18:51 bin. The 26 is barely under the benign maximum of 27. A fixed bin makes the feature depend on where the edge falls. The feature has to use a **rolling window**.

### 5. Query volume

The benign client peaks at **598 queries per minute** (18:50, the same minute the second tunnel burst starts), the tunnel at 221. A volume rule points at the wrong client.

### 6. Is normal stable? (first half against second half of the benign traffic)

- Name length (median 20) and entropy (median 2.52) are the same in both halves; the record type mix is within a few points. KS tests do not reject for name length (p = 0.095) and entropy (p = 0.53); longest label differs slightly (p = 0.026).
- Only **86 of 244 parent domains appear in both halves**, so a feature built on the identity of a domain would not carry over. Features built on counts and shapes do.
- This is a rough check on 3,201 queries and 95 minutes, not a proof.

### 7. The naive parent domain breaks on `co.uk`

Taking the last two labels lumps 63 `co.uk` queries under one "domain". The other two-letter endings in the data (`cnn.io`, `spot.im`, `decrypt.co`) are real registered domains and are fine. `features.py` needs a public suffix list.

## What this means for the model

1. **Core feature: unique names per parent domain in a rolling window.** It separates the classes cleanly here (27 against 221).
2. **Supporting features: per-query shape.** Name length in bytes, longest label and entropy catch the data and probe queries and help separate the look-alikes.
3. **Leave out:** host identity (IP, resolver, source port), AA and RA flags, TTL, EDNS0, iodine's start-up letters, NXDOMAIN ratio and raw query volume.
4. **Open decision, unit of analysis:** one row per query (matches `labels.csv`, window features attached to each row; the plan) or one row per (domain, window) (a cleaner unit for the strongest signal, but labels and evaluation then work per window). Per query is simpler; per window could be a second variant.

## Caveats the report should state

- **The result may look too good.** One window feature nearly separates the classes. The reasons are one tunnel session, one benign client and a loud tunnel. A slow, low-volume tunnel would be harder (Nadler et al., cited in the report).
- **The baseline is one home client:** 3,201 queries, 95 minutes, 670 distinct names. It describes this client, not DNS in general, so false positive rates here will look better than in a real network.
- **Base rate:** 12.2% of rows are tunnel, and half of those are the replay. That is high for an anomaly detector, so the `contamination` choice needs a defended sweep.
- **Replay:** each tunnel name appears twice. Keep both copies on the same side of any split, or deduplicate.
