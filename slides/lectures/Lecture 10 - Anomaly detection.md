# Lecture 10: anomaly-based detection

**Sources:** `docs/lectures/Cybersecurity_Lecture_10-AnomalyDetection_1-Engineering.pdf` (2 Nov) and `docs/lectures/Cybersecurity_Lecture_10-AnomalyDetection_2-Techniques.pdf` (3 Nov).

Part 1 is the workflow for building an anomaly detector. Part 2 is the four technique families and how to choose one. The slides mark the project-relevant guidelines explicitly. This note keeps those, plus the formulas and the assumptions each method needs.

The course frames anomaly detection as the complement of signature detection. A knowledge-based detector matches a known attack pattern, so it works when the attack, its variations, and enough test data are known. An anomaly detector models normal behaviour and flags deviations, which is how it can see zero-days and small variations of a known attack.

## The workflow

Four stages, in order. Each later stage checks the assumptions of the earlier one.

1. Domain analysis
2. Dataset construction
3. Detection development
4. Evaluation

### 1. Domain analysis

Three pieces: how the attack works, what the detector must do, and where the attack shows up in the data.

**Attack analysis.** Scope it so it is tractable and still general. The lecture's example is SQL injection: tractable if limited to SQL injection in HTTP data, general because it happens in more ways than a signature list can list. Read CTI for the general mechanism, then list the variations (tools, procedures) and group them so the common parts become visible. Detection should target those common parts.

**Detection requirements.**

| Kind | What to fix before building |
|---|---|
| Functional | Acceptable false-alert rate and missed-attack rate. Granularity: every instance, or a summary (a DDoS is a summary; a single injection is an instance). How precise the report must be for a response: an IP or username, or a generic alert an analyst can follow up. |
| Non-functional | Data volume, and whether detection is real-time or batch. |

**Data source analysis.** Find where the attack is visible, narrow the data to that, and write hypotheses for how attack rows differ from normal rows. Features exist to test those hypotheses. A feature is a dimension (host, user, command, time of day) plus a metric (count, min, max, entropy). One metric can be enough. Otherwise correlate several, for example a count of X that drops while a sum of Y rises. Each feature needs a reason. Adding features because they are available adds noise.

### 2. Dataset construction

**Benign data has to look like real use.** Collect long enough to include fluctuations over time. A simulated environment misses those fluctuations (flat usage where real users spike), so a detector tuned on it looks more accurate than it is. Benign outliers are part of the problem.

**The mix of attack and benign data changes the result.**

- An unnatural ratio misleads the detector. If attacks are rare in the environment, they should be rare in the set.
- Injected attacks can leave artefacts that change how hard the problem looks.
- One attack variant with far more samples than another makes the evaluation describe that variant.

In this project the data is given, so the collection step cannot be redone. The lecture still wants the consequences understood and stated.

**Split.**

| Split | Role |
|---|---|
| Training | Explore and fit. Large enough for the model to converge. It does not have to be free of attacks. It must come from before the test data, otherwise the model has seen the future. |
| Validation (optional) | Tune thresholds and other parameters. Keeps that tuning off the training fit and off the final test. |
| Testing | Data absent from training and validation: later normal behaviour, and attack variations. |

Before fitting, explore the data to confirm or revise the hypotheses, and label benign and attack samples. Labelling can be manual or semi-automatic (a signature is a valid way to build the ground truth).

### 3. Detection development

**Choosing a technique.**

1. Pick a family whose assumptions match the hypothesis and the data (distribution, whether a clean training set exists, one variable or many).
2. If that is unclear, try several families on a small representative sample.
3. Prefer the simpler method when it does the job, and prefer a method whose alerts can be explained.
4. Combine methods when one is not enough.

The family test from both lectures:

| The anomaly is... | Family |
|---|---|
| Something you can write down in advance as a check on normal behaviour | Heuristics or a specification |
| A value missing from a set learned earlier | Whitelisting |
| An outlier on one variable, or on several variables that are not combined | Statistical |
| An outlier in a combination of features | Unsupervised or semi-supervised machine learning |

**Preparing the data.**

- Categorical features: ordinal encoding when the values have an order (high = 3, medium = 2, low = 1). One-hot encoding for nominal values (TCP, UDP). Target encoding only for high cardinality, and the lecture's version stores the fraction of malicious rows per value, so it uses the label.
- Numerical features: scaling puts features on a comparable range so one column does not dominate because its numbers are larger. Distance methods and gradient methods need this (kNN, SVM, LOF). Interval data (no true zero, such as Celsius) is scaled to normalise the range. Ratio data (a true zero, such as a count or a length) is often scaled for the same reason.
- Derived features are where domain knowledge enters: a metric over a rolling time window, a grouping of similar values, a reputation score, the entropy of a string or payload (how random it is).

**Tuning.** Most methods need at least a threshold, set on the validation set or, failing that, the training set.

| Method | When |
|---|---|
| Manual | Few parameters, and the model is understood |
| Grid search | Every combination of a small grid |
| Random search | Often reaches a near-optimal setting faster than a full grid |

Parameters the lecture lists for the three algorithms in scikit-learn:

| Model | Parameters |
|---|---|
| Isolation Forest | `n_estimators`, `max_samples`, `contamination`, `max_features` |
| Local Outlier Factor | `n_neighbors`, `contamination`, `metric`, `leaf_size` |
| One-class SVM | `kernel`, `nu`, `gamma` |

### 4. Evaluation

Confusion matrix of predicted label against ground truth.

| Metric | Definition | What it answers |
|---|---|---|
| Precision | TP / (TP + FP) | Of the alerts, how many are attacks |
| Recall (TPR, coverage) | TP / (TP + FN) | Of the attacks, how many are alerted |
| F1 | 2 * precision * recall / (precision + recall) | Balance of the two |
| Accuracy | (TP + TN) / (TP + FP + TN + FN) | Share of rows labelled correctly |
| FPR | FP / (FP + TN) | Share of benign rows alerted |
| TNR (specificity) | TN / (FP + TN) | Share of benign rows left alone |

Accuracy is a weak summary when almost every row is benign.

**Read the errors, and read them in context.** Investigating false negatives and false positives can show that a hypothesis is wrong or that the technique is not robust. Changing the threshold is one response, and it is not the only one.

The same two numbers mean different things depending on how the set was built. The lecture's examples:

- An FPR of 0.01 on 1 million benign samples a day is 10,000 false alerts a day. That is alert fatigue.
- A precision of 0.90 on a 50/50 benign/attack split looks strong. At a realistic base rate of one attack in a million samples, the lecture states that precision falls to about 2e-7. This is the base-rate fallacy: a metric from a balanced set does not transfer to a set where attacks are rare.

## The four technique families

### Heuristics and specifications

A heuristic is expert knowledge ("a server should not open hundreds of connections in one second"). A specification is the protocol ("a server should answer only certain HTTP requests").

Use this when normal behaviour is known in advance, globally or for one environment, and can be checked against the audit trail. The assumptions: the attack violates that statement of normal behaviour, and the statement stays valid without constant edits as the environment changes.

The knowledge comes from protocol specifications or from organisational policy. The check can be a rule (a signature language, or a Zeek script) or a model (a state diagram of a network conversation).

Two limits. The statement of normal behaviour can be imprecise or out of date. Benign traffic can violate it, for example because an implementation is sloppy.

### Whitelisting (allowlisting)

Only activity that was learned as safe is allowed: executables, IPs, commands, and on the network side flows (source, destination, protocol), routers, access points, protocol commands and parameters, and domain names.

Use this when normal behaviour is a set or a range of values. It is semi-supervised: the training set is treated as entirely normal, so it has to be clean. The learned values have to stay valid. Learning can stop once the model goes a set time without updates. High-cardinality values can be stored lossily (a Bloom filter stores membership, not the value).

Detection looks the new value up. Missing means alert. A variant alerts when the value was seen but rarely.

Limits:

- It only catches attacks that introduce something unused in normal operations. Living off the land (legitimate tools) passes.
- Specificity drops quickly when the environment changes or when "normal" is a sparse set of values.
- It works better on classes of values than on raw values, which takes domain knowledge (group similar users, group similar commands).

### Statistical methods

For one continuous feature, or for a univariate time series. Three univariate scores, then window methods for time.

**Z-score.** Distance from the mean in standard deviations.

```text
z = (x - mean) / stddev
```

Flag `x` when `z` exceeds a threshold. Typical thresholds are 3 to 4.5. This assumes a normal distribution, and it is unreliable when the distribution is unknown. The mean and the standard deviation both move when extreme values are present, so the outliers can pull the threshold with them and stop being flagged.

**Tukey (interquartile range).** No distribution assumed, and more stable than the z-score when a few extreme values are present. On the ordered sample, Q1 is the value at the first quarter and Q3 at the third quarter.

```text
IQR = Q3 - Q1
outlier if x < Q1 - t * IQR  or  x > Q3 + t * IQR
```

`t` is 1.5, or above 3 for the points the lecture calls serious anomalies.

**Median absolute deviation (MAD).** No distribution assumed, and more robust than the z-score when a few extreme values are present.

```text
MAD(X) = median(|x - median(X)|)
outlier if x > median(X) + t * MAD(X)  or  x < median(X) - t * MAD(X)
```

Worked example from the lecture. `X = (1, 1, 2, 2, 4, 6, 90)`, median 2, absolute deviations `(1, 1, 0, 0, 2, 4, 88)`, MAD = 1. With `t = 3` the band is -1 to 5, so 6 and 90 are the anomalies.

**Two sliding windows, local spikes.** A spike or a dip can be anomalous only relative to its recent past. Take a long window W1 (the recent past) and a short window W2 (the spike; W2 can be a single point). Build a new series `mean(W1) - mean(W2)`, or use the median, and run an outlier test on that series. The assumption: the ordinary difference between the windows is smaller than the anomaly you want. Tune the two sizes, the aggregation, and the threshold.

**Two sliding windows, level shift.** Same construction, with the two windows of similar size, to catch a change in level or in spread (swap the mean for the standard deviation to catch a change in volatility). The assumption: the windows can be sized so the shift becomes a global outlier in the difference series.

**Extreme Studentized Deviate (ESD).** For a sample that contains up to `k` anomalous values. The seasonal variant is in the resources below.

### Machine learning

For anomalous combinations of quantitative features. Steps: choose the features, fit an outlier model, take a score per point, compare the score with a threshold (Tukey's method is one option for that threshold), alert above the threshold.

Algorithms named: Local Outlier Factor, Isolation Forest, one-class SVM, and also autoencoders, PCA, vector-autoregression residuals, DBSCAN and HDBSCAN.

Limits that apply to the whole family. More features make points harder to tell apart (the curse of dimensionality). A few outliers inside the training set are acceptable, because attack data is supposed to be rare.

**Isolation Forest.** No distribution assumed. Build many trees. In each tree, pick a feature at random, pick a split at random between that feature's min and max, and send the rows to the two sides. Repeat until the tree is done or each leaf holds at most `k` rows. The anomaly score of a point is its average path length across the trees. A short path means the point was easy to isolate, so the score is high. Points that sit outside the normal region but are surrounded by normal points can still look normal. A hybrid Isolation Forest (2017) combines the score with a second detector or with rules.

**One-class SVM.** Draws a boundary around the normal points: a hyperplane as far from the origin as possible. The kernel trick maps points so a linear boundary works. The usual kernel is the Gaussian RBF, and a larger `gamma` makes a tighter boundary. The score is the distance from the origin to the point. No distribution assumed. Unlike Isolation Forest, it benefits from scaling.

**Local Outlier Factor.** Flags points that are isolated relative to the density around them. For each point, take its `k` nearest neighbours, estimate the local density, and compare that density with the average density of the neighbours. LOF near 1 means the point matches its neighbourhood. LOF above 1 means it is sparser than its neighbours, and a higher score is a stronger anomaly. Scaling matters, because the score is built from distances.

## Libraries and references from the slides

| Tool | What the lecture points it at |
|---|---|
| [scikit-learn, novelty and outlier detection](https://scikit-learn.org/stable/modules/outlier_detection.html) | Multivariate outliers: Isolation Forest, LOF, one-class SVM |
| [ADTK](https://adtk.readthedocs.io/en/stable/index.html) | Univariate and time-series anomalies with the statistical methods above. The sliding-window figures come from its user guide |
| [seasonal-esd-anomaly-detection](https://github.com/nachonavarro/seasonal-esd-anomaly-detection) | Seasonal hybrid ESD |
| [PyOD](https://pyod.readthedocs.io/en/latest/) | A larger collection of statistical and ML detectors for multivariate outliers |
| [Optuna](https://optuna.org) | Hyperparameter search |

Papers listed on the closing slide, with the ones closest to a network detector marked:

- Verkerken et al., *Unsupervised machine learning techniques for network intrusion detection on modern data*, CSNet 2020. Compares unsupervised detectors on network data.
- Hochenbaum, Vallis, Kejariwal, *Automatic anomaly detection in the cloud via statistical learning*, arXiv:1704.07706, 2017. The seasonal ESD method.
- Wang, Parekh, Stolfo, *Anagram: a content anomaly detector resistant to mimicry attack*, RAID 2006. Content n-grams, relevant to payload randomness.
- Siris and Papagalou, *Application of anomaly detection algorithms for detecting SYN flooding attacks*, GLOBECOM 2004.
- Jung et al., *Fast portscan detection using sequential hypothesis testing*, IEEE S&P 2004.
- Guo et al., *Peek inside the closed world: evaluating autoencoder-based detection of DDoS to cloud*, arXiv:1912.05590, 2019.
- Cheung et al., *Using model-based intrusion detection for SCADA networks*, 2007. The specification-based reference.
- Hubert, Debruyne, Rousseeuw, *Minimum covariance determinant and extensions*, WIREs Computational Statistics, 2018.

## What this means for our detector

Case 1, DNS tunnelling, Isolation Forest. Read with `docs/Baseline findings.md` and `docs/handoff-2026-11-10-1230.md`.

**The workflow is the report.** Domain analysis is done (iodine, the eight characteristics, labels). Dataset construction is where the given PCAP has to be discussed honestly. Detection development is the feature matrix and the forest. Evaluation is precision, recall, F1, and a written account of the false positives and false negatives, including the base rate.

**Feature derivation in the lecture is the feature plan we already have.** Entropy of the query name, and counts over a rolling window, are the two derivations the slides name. The slides also say each feature needs a reason and that extra features add noise, which supports keeping host identity, NXDOMAIN, raw volume, and the iodine-only signals out. Record type is nominal, so if it enters the matrix it is one-hot encoded. Target encoding is off the table: the lecture's version stores the malicious rate, which copies the label into the feature.

**The family test says the forest is justified, and it names the alternative.** The strong signal (unique names per parent domain) is one variable, so a statistical test on that series is the simple method the lecture says to try first. The supporting per-query features matter only in combination with it, which is the multivariate case, and that is the machine-learning branch. A Tukey or MAD threshold, or the two-window difference, on the rolling unique-name count is the natural simple baseline to put next to the forest. A length-plus-entropy rule is a heuristic, and the baseline already shows it misses the 173 short ping queries and flags CDN names.

**The window methods describe the feature, not only the model.** W1 is the recent history of a parent domain and W2 is the short burst. The lecture's series is the difference between the two, and the assumption is that ordinary differences stay smaller than the burst. Fixed calendar bins are the thing this construction avoids. That matches the finding that a minute boundary splits the second tunnel burst into 26 and 196 names.

**Whitelisting domains is a poor fit on this capture, and the lecture says why.** Only 86 of 244 parent domains appear in both halves, so a learned set of domain names goes stale inside one afternoon. The lecture's limit is the same: specificity falls when the environment changes and when normal values are sparse. A tunnel also uses a legitimate protocol, which is the living-off-the-land case a whitelist of protocol commands cannot see.

**A heuristic on the NULL record type fails the generality test.** The lecture requires the rule to describe the attack in general and to survive variations. NULL is iodine's choice. A tunnel over TXT, CNAME, or A would not trip it, and benign exceptions are exactly the second limit the lecture names.

**Training does not have to be clean, and ours is not "a few outliers".** The lecture allows attack rows in the training set for unsupervised models, and it says a few outliers are fine because attacks are rare. It also says an unnatural share of attack traffic misleads the detector. At 444 of 3,645 rows (12.2%), or about half of that once the replay is counted once, this capture is the case the warning describes. `contamination` is the parameter that states the assumed share, so the sweep has to be reported against that share. One-class SVM and a whitelist need a clean training slice. Isolation Forest does not.

**The split has to respect time, and the replay breaks a naive time split.** Training data must precede test data, and test rows must be absent from training. The second burst is a byte-for-byte copy of the first, so a split on the clock puts the same queries on both sides: the model has seen the future. Keep both copies of a name on the same side, or deduplicate, and say that this is done to satisfy the lecture's rule.

**Scaling only matters for the comparison models.** Isolation Forest splits inside one feature's own min and max, so it does not need scaling. LOF and one-class SVM do. A comparison that skips scaling is not a fair reading of those two.

**The base-rate paragraph is required, and the lecture gives the numbers to use.** Report precision, recall, F1, and FPR on this set, then say what an FPR of that size means per day of traffic, and that the 12.2% attack share makes precision look better than it would on a network where tunnels are rare. The false-positive write-up should cover the benign look-alikes (long CDN names, high entropy) and ask whether they refute a hypothesis or only the threshold. The lecture's point is that parameter tuning is not the whole analysis.

**Parameters to report for the forest:** `n_estimators`, `max_samples`, `contamination`, `max_features`. With four of them and a model we can explain, manual tuning on a validation slice fits the lecture's guidance. Optuna is the tool the slides name if the sweep grows. The score threshold can be set with Tukey on the scores, which is the lecture's own suggestion for turning a score into an alert.
