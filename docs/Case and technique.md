# Case and technique decision

**Status:** open. The group name on Canvas must be `[Case + Technique]`, first come first served, and no two groups may share the combination. Check the Canvas group list before claiming one.

## Cases

| | Case 1 | Case 2 |
|---|---|---|
| Data | Large PCAP plus Zeek `dns.log` (DNS only) | Tiny PCAP, about 50 packets, several protocols |
| Hint | Extra information that helps identify the attack with anomaly detection | None: no feature guidance, attack type unknown |
| Where the work is | Feature engineering over many DNS transactions, real outlier detection | Manual protocol analysis, the ML part is thin on 50 packets |
| Risk | Size and processing time | Too few samples for LOF, IForest or OCSVM to mean much |

## Techniques

| Technique | sklearn | Fit | Watch out for |
|---|---|---|---|
| Local Outlier Factor | `neighbors.LocalOutlierFactor` | Local density, good with clustered benign behaviour. `novelty=True` for scoring unseen data | Needs scaled features, sensitive to `n_neighbors`, quadratic in samples |
| Isolation Forest | `ensemble.IsolationForest` | Fast, scales to big logs, little tuning | Contamination parameter drives the result, weak on dense anomaly clusters |
| One-Class SVM | `svm.OneClassSVM` | Learns a boundary around benign data | Needs scaling, `nu` and `gamma` matter a lot, slow on large data |

Other techniques are allowed if proposed by the group.

## Recommendation (to be argued with the group)

**Case 1 is the stronger choice for the grade.** The rubric rewards metrics, false positive and false negative analysis, and theoretical evaluation, and a 50 packet PCAP cannot carry that. Case 2 is only attractive if the group wants low data volume and is confident in manual protocol work.

On technique, Isolation Forest is the safest default on a large DNS log. The more distinctive pick is to claim whichever combination is still free, then state in the report why that technique fits the chosen attack's features.

## Decision

- Case: _TBD_
- Technique: _TBD_
- Claimed on Canvas on: _TBD_
