# SOC Home Lab — Phishing to Persistence Attack Simulation

## Overview

This project demonstrates a complete end-to-end phishing attack simulation in a Windows 11 home lab. The objective was to understand how attackers abuse legitimate Windows utilities (Living-off-the-Land Binaries), generate endpoint telemetry using Sysmon and Windows Event Logs, and detect each stage of the attack using custom Elastic SIEM detection rules.

Unlike a CTF walkthrough, this project focuses on realistic attacker behavior, detection engineering, threat detection, and incident investigation.

---

## Objectives

- Simulate a realistic phishing attack chain in a controlled lab.
- Generate Windows telemetry using Sysmon and Windows Event Logs.
- Create custom Elastic SIEM detection rules.
- Investigate alerts using Kibana Discover.
- Correlate individual alerts into a complete attack story.
- Map detections to the MITRE ATT&CK Framework.
- Practice the SOC analyst investigation workflow from detection to response.

---

## Attack Chain

```text
Phishing Email
      ↓
MSHTA Execution
      ↓
PowerShell Execution
      ↓
Encoded PowerShell Command
      ↓
PowerShell Download Activity
      ↓
Scheduled Task Persistence
      ↓
Registry Run Key Persistence
```

Every stage successfully generated telemetry and triggered custom Elastic SIEM detection rules.

---

## Detection Coverage

| Detection | MITRE ATT&CK Technique |
|-----------|------------------------|
| MSHTA Execution | T1218.005 – Mshta |
| PowerShell Execution | T1059.001 – PowerShell |
| Encoded PowerShell Command | T1027 – Obfuscated Files or Information |
| PowerShell Download Activity | T1105 – Ingress Tool Transfer |
| Scheduled Task Creation | T1053.005 – Scheduled Task |
| Registry Run Key Creation | T1547.001 – Registry Run Keys / Startup Folder |

---

## Lab Environment

- Windows 11 Virtual Machine
- VirtualBox
- Sysmon (SwiftOnSecurity Configuration)
- Elastic Agent / Winlogbeat
- Elasticsearch
- Kibana (Elastic SIEM)
- Custom KQL Detection Rules

---

## Skills Demonstrated

- Security Monitoring
- Detection Engineering
- SIEM Rule Development
- Elastic Security
- Kibana Investigation
- Windows Event Log Analysis
- Sysmon Log Analysis
- Process Tree Analysis
- PowerShell Detection
- Threat Hunting
- Alert Triage
- Incident Investigation
- MITRE ATT&CK Mapping
- Windows Persistence Analysis

---

## Repository Structure

```text
SOC-Home-Lab-Phishing-to-Persistence/
│
├── README.md
├── INVESTIGATION.md
├── DETECTION_RULES.md
├── MITRE_MAPPING.md
├── screenshots/
│   ├── alerts/
│   ├── dashboards/
│   ├── logs/
│   └── timeline/
└── rules/
```

---

## Investigation

The complete investigation is documented in **INVESTIGATION.md**, including:

- Attack execution
- Commands used
- Detection rules
- Sysmon evidence
- Elastic SIEM investigation
- Alert validation
- Incident response workflow
- Containment recommendations
- Eradication steps
- Recovery process
- Lessons learned

---

## Screenshots

This repository contains screenshots demonstrating:

- Elastic SIEM Alerts
- Detection Rules
- Kibana Discover Investigations
- Sysmon Events
- Process Relationships
- Dashboards
- Timeline Analysis

---

## Key Learning Outcomes

Through this project, I gained hands-on experience with:

- Simulating attacker behavior using legitimate Windows binaries (LOLBins)
- Understanding how endpoint telemetry is generated
- Writing and validating custom Elastic SIEM detection rules
- Investigating alerts using Sysmon and Windows Event Logs
- Correlating multiple alerts into a single attack chain
- Mapping detections to the MITRE ATT&CK Framework
- Following a structured SOC investigation workflow

---

## Future Improvements

- Add additional attack scenarios (Credential Access, Lateral Movement, Defense Evasion)
- Develop more advanced detection rules
- Create dashboards for attack visualization
- Expand MITRE ATT&CK coverage
- Automate attack simulations using Atomic Red Team

---

## Disclaimer

This project was created for educational and defensive cybersecurity purposes only.

All attack simulations were executed inside an isolated Windows virtual machine using safe and non-malicious commands. No real malware was used during this project.
