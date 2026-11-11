# Assignment tasks

You must complete the following tasks in this project, divided into three main parts for the report and one for the presentation. In case you are unsure if each part of your report is clearly documenting all of these tasks, refer to the section below called "Criteria for Success".

There are three main parts for this project (which you can follow to structure your report):

## 1. Analyse the attack scenario

Study the protocol, the vulnerability, relevant features, and how this could be exploited for this specific attack scenario.

Correlate it with relevant Tactics, Techniques and Procedures (TTPs), including the ones that could facilitate it or stem from it.

When documenting this in the report, you should first describe what you investigated and how you did this.

**Important:** Explain how you investigated protocol features to discover the data related to the incident from the available PCAP file. You should also refer to (cite) any resources, such as open Cyber Threat Intelligence (CTI) reports or papers that you used to understand the attack type better. External sources should be related to the incident in a way that allows the reader to understand similarities and differences where relevant.

You can detail how the incident happened and what actions could be observed (i.e., such as data exfiltration, or propagation). It is convenient to classify attack evidence based on Tactics, Techniques, and Procedures (TTPs) following the MITRE ATT&CK taxonomy. Different TTPs should be contextualised and combined. Finally, you should identify affected assets and discuss the impact of the incident in the context in which it occurred (based on the available data). Consider whether you can say anything about who is responsible for the incident. Please note that attribution is very complex and multifaceted; it is best not to make any claims you cannot support.

Then, document an overview of the attack scenario, highlighting relevant information you found in the data. It might be convenient to present individual attacker actions in chronological order, presenting the relevant information that allows to correlate one step with the next.

## 2. Threat reporting

Analyse and evaluate the technical aspects of the attack, including its mechanics, affected security goals, and how data can help identify it. You can correlate it with relevant threat intelligence.

Describe the technical characteristics of the attack, and how these observations may be used for detection. For each characteristic, you may discuss:

- The specificity of the characteristic to the (type of) incident, malware, or attacker.
- Can this characteristic also be observed due to other (types) of incidents, malware, or attackers?
- Can this characteristic also be observed due to benign behavior?
- How easy it is for an adversary to mount a similar attack without this characteristic.
- How easy it is to check for the presence of this characteristic in an automated way.
- The stage of the incident in which this characteristic can be observed.

Although you should focus on the core characteristics of the incident, which are difficult to adjust, you are also encouraged to include characteristics that are not covered in your detection description (part 3).

## 3. Describe and evaluate your detection strategy

Document your detection technique and approach.

Explain how the detection technique succeeds or even fails to detect the attack, and how your technical implementation tried to achieve it.

Derive detection methods from the characteristics identified in the previous tasks. Ideally, the detection methods should cover various stages of an attack and make it difficult for an adversary to evade detection altogether, but that might not be necessary here.

Make sure you report the steps you took to develop and test the proposed detection methods. Detection methods should be evaluated both empirically and theoretically:

- **Empirically,** you may carry out the evaluation mainly on the available data.
  - Create proper metrics to evaluate the effectiveness of the detection method.
  - Interpret the metrics by taking into account contextual information of the dataset on which they are calculated.
  - Note: feel free to extend the evaluation beyond this, e.g. by testing the ability of the method to detect variations of the attack, or by testing the detection method on other datasets, but keep in mind that this is not necessary.
- **Theoretically,** evaluate the detection method beyond the available data by relating the detection methods to characteristics of typical environments.

The advantages and disadvantages of the detection methods should be discussed, alongside alternatives to justify why your approach is viable, given potential alternatives.

## 4. Present your work

Make a presentation that summarises your work (you are free to do it as you like).

- **Available time:** 25 min
  - 20 min presentation
  - 5 min questions
- The date of your presentation will be either 30 Nov or 01 Dec.
- These will be randomly assigned.



## Criteria for Success

Below, you can see a set of criteria that will be used to evaluate your report. You can use it as a guide in case you are unsure if you have everything in place.


| Criteria                                          | Weak                                                                                                                                                                           | Developing                                                                                                                                                                                                                                      | Accomplished                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Attack scenario well analysed                     | The protocol and attack scenario are incorrectly described or not at all. TTPs are incorrectly identified or not at all. TTPs are non-coherently combined.                     | Relevant protocol information is described. The attack scenario is correctly described. Relevant TTPs are identified.                                                                                                                           | **Relevant protocol** information is described. **Attack scenario** is correctly identified. **Relevant TTPs** are correctly identified, contextualized and combined. **Impact of the attack** scenario and **affected assets** are thoroughly discussed.                                                      |
| Attack mechanics are well understood              | Wrong understanding of characterising features of the attack; identified characterising features are not observable in the data.                                               | Understanding of some characterising features of the attack; features can be observed in the data.                                                                                                                                              | Understanding of **the core characterizing features** of the attack observable in the data; hard for the attacker to change these features.                                                                                                                                                                       |
| Technical implementation fits the attack scenario | The proposed detection strategies are incompatible with attack mechanics and observable data. No evaluation (e.g., advantages/disadvantages) of the proposed detection method. | The proposed detection strategies have insufficient coverage/specificity with respect to what the available data allows one to do. Basic evaluation, metrics and discussion (e.g., advantages/disadvantages) of the proposed detection methods. | The proposed detection strategies and their coverage/specificity are adequate for what the available data allows. Thorough evaluation, with proper **metrics, investigation of FPs and FNs, discussion** (e.g., advantages and disadvantages) of the proposed detection methods, with **proposed alternatives.** |


