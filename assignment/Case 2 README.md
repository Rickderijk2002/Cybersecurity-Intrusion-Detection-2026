# Case 2

### Dataset Summary

The input data file provided for this case is a PCAP capture `case2.pcap` of network traffic exchanged between a client and a server.
Within this traffic, it is known that an attacker attempts to exploit a vulnerability in one of the communication protocols used in the exchange.


This dataset includes no additional explanations about the feature selection or the specific type of attack it contains. Therefore, the analysis must examine the captured packets to identify potential anomalies and derive meaningful features.

### Objective

The objective is to study the protocol, understand how legitimate exchanges should behave, and then design an anomaly‐detection approach capable of highlighting deviations that may indicate malicious behavior.

This case tests your ability to design a feature engineering process when no pre-parsed log data is given. You’re simulating a lower-level intrusion detection workflow (starting from raw packet captures). That means your role in Case 2 is also to decide what to measure in the traffic.

### Dataset Preparation

Since you do not know what is the attack beforehand, the first step involves constructing a suitable representation of the network traffic for anomaly detection.

This may include:

- Analysing the PCAP file using tools such as Wireshark

- Extracting relevant protocol‐level information (e.g., packet types, message lengths, timing, and flow direction).

- Identifying protocol fields or message properties that can be expressed numerically and may reveal deviations from normal behavior.

- Deriving additional metrics that describe the internal consistency of communication patterns, such as differences between declared and observed message parameters, or irregular timing between exchanges.

- Constructing a feature matrix suitable for unsupervised anomaly detection techniques, while noting that ground truth labels are unavailable and that anomalies must be inferred from context.

The emphasis in this case is not on reproducing specific known attacks but on applying a methodical, data‐driven approach to discover abnormal patterns in raw network traffic.

The analysis should therefore combine protocol knowledge with data‐science techniques to build a plausible model of normal behavior and highlight deviations that could represent exploitation attempts.