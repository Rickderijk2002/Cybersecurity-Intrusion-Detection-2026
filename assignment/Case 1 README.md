# Case 1

### Dataset Summary

The input data for Case 1 includes:
- `case1.pcap`: raw network traffic capture containing DNS queries and responses, including signs of DNS tunneling.
- `dns.log`: DNS transaction logs extracted using the Zeek network monitor, comprising only DNS exchanges.

This case focuses on detecting DNS tunneling, a technique where data is covertly transmitted using DNS queries, often to bypass firewalls or exfiltrate data. You may use the first file for manual analysis, while the second is easier for feature extraction. Try to identify DNS tunnelling by analysing the dataset.

### Objective

The goal is to understand the normal behavior of DNS traffic, derive features that capture potential tunneling activity, and apply anomaly detection methods to highlight malicious queries.

At the end of the analysis, you should be able to:
- Identify suspicious DNS queries that indicate tunneling activity.
- Build an anomaly detection model.
- Evaluate the model performance and interpret the results in terms of security impact.
- Document your threat report linking anomalies to malicious activity.

### Dataset Preparation

Not all features in Zeek DNS logs are useful for detecting tunneling. You should:

1 - Retain relevant primary features from the log file.
2 - Derive additional analytical features, and statistics on unique subdomains or top-level domains over time.
3 - Connect protocol behavior to security insights — study DNS protocol characteristics to identify abnormal query patterns, and discuss how those anomalies could relate to attacker tactics in your threat report.