# Sentinel2ATTACKv2

Sentinel2ATTACKv2 is a Python script designed for cybersecurity professionals and organizations utilizing Microsoft Sentinel as their SIEM (Security Information and Event Management) solution. This tool addresses a pivotal need within the cybersecurity ecosystem: the extraction of Techniques, Tactics, and Procedures (TTPs) from alerts generated by Microsoft Sentinel and the subsequent generation of a MITRE ATT&CK navigation layer. This functionality fills a significant gap in current capabilities, providing users with actionable insights into their security posture relative to the comprehensive threat models defined by the MITRE ATT&CK framework.

![](https://i.imgur.com/lrHiuNC.png)

### Key Features

- **TTP Extraction**: Automatically extracts TTPs from Microsoft Sentinel alerts, leveraging the detailed information within alerts to map to corresponding MITRE ATT&CK TTPs.
- **MITRE ATT&CK Navigation Layer Generation**: Creates a customized MITRE ATT&CK navigation layer based on the extracted TTPs, offering an intuitive visualization of the organization's threat detection capabilities and potential vulnerabilities.

### Use Cases

SentinelTTPMapper is an essential tool for:
- Security Analysts seeking to enhance their understanding of the threats their organization faces and how well they are detected by their current Sentinel rules.
- Threat Intelligence Teams looking to map real-time alert data against established TTPs for better threat hunting and reporting.
- Security Operations Centers (SOCs) aiming to improve their defensive measures by identifying gaps in their detection capabilities.

