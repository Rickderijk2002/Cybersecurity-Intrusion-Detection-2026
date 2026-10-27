# Case and technique: proposal for the group

**Proposal: Case 1 (DNS tunneling) with Isolation Forest.**
Rick has already mentioned this preference in the group chat. To be decided together on 2026-10-28.

**Status:** open until the group agrees. The group name on Canvas must be a unique `[Case + Technique]`, first come first served, so check the Canvas group list before claiming it.

Source descriptions of the data: `assignment/Case 1 README.md` and `assignment/Case 2 README.md`.

## Why Case 1

1. **The attack type is known: DNS tunneling.** We do not spend the project guessing what happened. We spend it on what the grading rewards: analysis, features, detection and evaluation.
2. **The data is built for feature engineering.** `dns.log` (Zeek) already has one row per DNS transaction. The README tells us to derive features and statistics on unique subdomains and top level domains over time.
3. **The features are hard for an attacker to change.** Data is smuggled inside the query name, so the traffic is forced to show long names, high entropy labels, many unique subdomains under one parent domain, unusual record types (TXT, NULL, CNAME) and a high query rate to one domain. This matches the rubric line "core characterising features, hard for the attacker to change".
4. **We can compute real metrics.** There are no labels, but we can build a ground truth ourselves by identifying the tunnel domain manually (Wireshark on the PCAP, filters on `dns.log`). That gives precision, recall and F1, and lets us analyse false positives and false negatives. The rubric asks for exactly this at the top level.
5. **The manual step is itself report content.** The brief wants "how you discovered the incident from the PCAP". Finding the tunnel by hand is that section.

## Why not Case 2

- It is a raw PCAP of about 50 packets, with no labels and no hint about the attack.
- An outlier detector on 50 samples cannot give meaningful metrics, and the rubric's top level needs proper metrics and FP/FN analysis.
- The README mentions "differences between declared and observed message parameters", which suggests a length field mismatch in some protocol (a Heartbleed style flaw is plausible). This is a guess, not something we have verified.
- It is an interesting protocol puzzle, but it is the riskier route for the grade.

## Why Isolation Forest

- **Scales** to a large DNS log and needs little tuning.
- **Handles mixed features** (counts, ratios, lengths, entropy) without much preprocessing. No scaling is required.
- **Explainable enough:** we can inspect which features isolate the tunnel queries, which feeds the "attack mechanics" section.
- **Known weakness, which we turn into content:** the `contamination` parameter decides how many points are flagged. We report how precision and recall change across a range of values, and justify our final choice. That is a natural evaluation experiment.
- **Another weakness to discuss:** if tunnel traffic is a large share of the data, anomalies are no longer "few and different". We check this in the data and discuss it.

## Fallbacks if the combination is taken

| Order | Combination | Note |
|---|---|---|
| 1 | Case 1 with LOF | Use `novelty=True`, scale the features. Good when benign DNS forms dense clusters. Sensitive to `n_neighbors` and slower on big data |
| 2 | Case 1 with OCSVM | Only if we can train on a clean benign slice. Needs scaling, `nu` and `gamma` matter a lot, slow on large data |
| 3 | Case 1 with our own technique | Allowed by the brief if proposed by the group, for example a simple statistical baseline as comparison |

An alternative technique is also useful as a comparison in the "alternatives" part of the evaluation, whichever combination we claim.

## What the group should decide tomorrow

1. Case and technique, then claim the group name on Canvas straight away.
2. Who owns which workstream (see `Task division.md`).
3. How we label the ground truth (who finds the tunnel domain and how we document it).
4. Meeting rhythm until the 30 Nov / 1 Dec presentation and the 5 Dec deadline.

## Decision

- Case: _TBD (proposal: Case 1)_
- Technique: _TBD (proposal: Isolation Forest)_
- Claimed on Canvas on: _TBD_
