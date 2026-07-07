# Phishing to Persistence

## Overview

This project demonstrates a complete phishing-to-persistence attack simulation performed inside my Windows 11 SOC home lab using Sysmon, Winlogbeat, and Elastic SIEM.

The objective was to understand how attackers abuse legitimate Windows binaries to establish persistence and to build custom Elastic detection rules capable of identifying each stage of the attack.

Unlike a CTF walkthrough, this project focuses on understanding attacker behavior, validating detections with real telemetry, investigating generated alerts, and documenting the incident from a SOC analyst perspective.

---

## Attack Chain

```text
Phishing Email
        ↓
MSHTA
        ↓
PowerShell
        ↓
Encoded PowerShell Command
        ↓
PowerShell Download Activity
        ↓
Scheduled Task Creation
        ↓
Registry Run Key Persistence
```

---

## Lab Environment

- Windows 11 VM (VirtualBox)
- Sysmon (SwiftOnSecurity Configuration)
- Winlogbeat
- Elasticsearch
- Kibana (Elastic SIEM)

---

## Detection Rules Developed

| Detection Rule | Severity |
|----------------|----------|
| MSHTA Execution | High |
| PowerShell Execution | Medium |
| Encoded PowerShell Command | High |
| PowerShell Download Activity | High |
| Scheduled Task Creation | High |
| Registry Run Key Creation | High |

---

## Skills Demonstrated

- Attack Simulation
- Detection Engineering
- Windows Event Log Analysis
- Sysmon Analysis
- Elastic SIEM
- KQL Detection Rules
- Alert Investigation
- MITRE ATT&CK Mapping
- Incident Response Analysis

---

## MITRE ATT&CK Mapping

| Attack Stage | Technique |
|--------------|-----------|
| MSHTA | T1218.005 |
| PowerShell | T1059.001 |
| Encoded PowerShell | T1027 |
| Download Payload | T1105 |
| Scheduled Task | T1053.005 |
| Registry Run Key | T1547.001 |

---

## Evidence

The **evidence/** directory contains screenshots of:

- Attack execution
- Detection rules
- Elastic SIEM alerts
- Discover queries
- Timeline investigation
- Generated Windows events

---

## Documentation

For the complete technical investigation, including attack execution, detection logic, alert analysis, incident response, and lessons learned, see:

**📄 investigation.md**
