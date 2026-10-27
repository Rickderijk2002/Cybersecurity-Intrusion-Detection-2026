# Final Project: Intrusion Detection (JM2030 Cybersecurity)

Copied from Canvas by Rick, 2026-10-27. Source of truth for what is graded.

- **Due:** 5 Dec 2026 by 23:59, 10 points, submitted as a file upload
- **Presentation:** 30 Nov or 1 Dec (assigned randomly). 20 minutes plus 5 minutes of questions
- **Group:** 6 people, defined by 4 Nov. Four groups in total

## Purpose

Apply the theory of cybersecurity and monitoring with data science to practical intrusion detection. The group receives a file with benign and malicious data (communicated through a specific protocol), uses data science techniques to find the malicious data, and reports it.

1. Study and document the attacked protocol
2. Derive a threat model from real-world attack data and its related security goals
3. Build detection procedures fitting a given threat model
4. Create a Threat Report and present the approach

A LaTeX template is provided (kept in `report/_template-original/`). Overleaf is allowed, TU/e account gives premium access.

## Deliverables

Upload one zip file (folders allowed) containing:

1. **Technical Report (Threat Report)** as PDF
2. **Presentation slides** as PPTX or PDF
3. **Code/scripts** (not graded, but mandatory). A Python notebook is fine

## Group formation, case and technique

- Pick a unique combination of **[Case + Technique]** per group and write it as the group name on Canvas ("Groups Final Project - Intrusion Detection"). First come, first served, no repeated combinations. All groups may choose the same case with different techniques.
- **Case 1:** a bigger dataset with a PCAP file and a DNS transactions log `dns.log` collected with the Zeek network monitor, filtered to DNS only. Additional information is provided that helps identify the attack with anomaly detection.
- **Case 2:** a very small PCAP file (around 50 packets). Small, but contains more than one protocol, with no explanation of feature selection or attack type.
- **Techniques (non-exhaustive, others may be proposed):** Local Outlier Factor (`sklearn.neighbors.LocalOutlierFactor`), Isolation Forest (`sklearn.ensemble.IsolationForest`), One-Class SVM (`sklearn.svm.OneClassSVM`).

## Tasks

### 1. Analyse the attack scenario

- Study the protocol, the vulnerability, relevant features, and how it could be exploited in this scenario.
- Correlate with relevant Tactics, Techniques and Procedures (TTPs), including ones that facilitate it or stem from it.
- In the report, first describe what was investigated and how.
- **Important:** explain how protocol features were investigated to find the incident data in the PCAP. Cite resources such as open Cyber Threat Intelligence (CTI) reports or papers, related to the incident so the reader sees similarities and differences.
- Detail how the incident happened and which actions could be observed (for example data exfiltration, propagation). Classify evidence by TTPs following MITRE ATT&CK, contextualised and combined.
- Identify affected assets and discuss impact in context. Consider who is responsible, but attribution is complex: make no claims that cannot be supported.
- Give an overview of the attack scenario with the relevant information found in the data. Individual attacker actions in chronological order, with the information that correlates one step with the next.

### 2. Threat reporting

- Analyse and evaluate the technical aspects of the attack: mechanics, affected security goals, how data can help identify it. Correlate with threat intelligence.
- Describe the technical characteristics of the attack and how they can be used for detection. For each characteristic, discuss:
  - Its specificity to the (type of) incident, malware or attacker
  - Whether other incidents, malware or attackers also produce it
  - Whether benign behaviour also produces it
  - How easy it is for an adversary to mount a similar attack without this characteristic
  - How easy it is to check for it automatically
  - The stage of the incident in which it can be observed
- Focus on core characteristics that are hard to adjust. Characteristics not covered by the detection part (3) are welcome too.

### 3. Describe and evaluate the detection strategy

- Document the detection technique and approach. Explain how it succeeds or fails to detect the attack and how the implementation tried to achieve it.
- Derive detection methods from the characteristics identified above. Ideally they cover various stages of an attack and make evasion difficult (not strictly necessary here).
- Report the steps taken to develop and test the methods.
- **Empirical evaluation:** mainly on the available data. Create proper metrics and interpret them with the dataset's context. Optional extras: variations of the attack, other datasets.
- **Theoretical evaluation:** relate the methods to characteristics of typical environments. Discuss advantages and disadvantages, and alternatives that justify why the approach is viable.

### 4. Present the work

20 minutes presentation plus 5 minutes questions. Format is free.

## Criteria for success

| Criterion | Weak | Developing | Accomplished |
|---|---|---|---|
| **Attack scenario well analysed** | Protocol and scenario incorrectly described or missing. TTPs wrong or missing, or combined incoherently | Relevant protocol info described. Scenario correctly described. Relevant TTPs identified | Relevant protocol info described. Scenario correctly identified. TTPs correctly identified, contextualised and combined. Impact and affected assets thoroughly discussed |
| **Attack mechanics well understood** | Wrong understanding of characterising features. Identified features are not observable in the data | Understanding of some characterising features. Features can be observed in the data | Understanding of the core characterising features, observable in the data and hard for the attacker to change |
| **Technical implementation fits the scenario** | Detection strategies incompatible with the mechanics and observable data. No evaluation (for example advantages and disadvantages) | Insufficient coverage or specificity for what the data allows. Basic evaluation, metrics and discussion | Strategies and their coverage and specificity adequate for the data. Thorough evaluation with proper metrics, investigation of false positives and false negatives, discussion of advantages and disadvantages, and proposed alternatives |

## Datasets

Download links for Case 1 and Case 2 are on the Canvas assignment page. Put the files in `data/raw/` (git-ignored, PCAPs can contain sensitive traffic and are large).
