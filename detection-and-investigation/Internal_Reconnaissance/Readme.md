# Internal Reconnaissance Detection using Elastic SIEM

## Overview

This project simulates a realistic post-compromise internal reconnaissance attack against a Windows endpoint. The objective is to generate attacker-like telemetry, detect the activity in Elastic SIEM, and investigate it from a SOC analyst's perspective.

Unlike traditional reconnaissance using legacy CMD utilities, this simulation uses PowerShell cmdlets and WMI queries that are commonly observed in modern enterprise attacks.

---

## Attack Flow

```
Compromise
      ↓
Administrator Enumeration
      ↓
Credential Discovery
      ↓
Security Patch Enumeration
      ↓
Network Connection Discovery
      ↓
Elastic SIEM Detection
      ↓
SOC Investigation
```

---

## Commands Executed

```powershell
Get-LocalGroupMember -Group "Administrators"
```

```cmd
cmdkey /list
```

```cmd
wmic qfe get HotFixID,Description,InstalledOn
```

```powershell
Get-NetTCPConnection -State Established
```

---

## Detection Highlights

- PowerShell Activity
- Local Administrator Enumeration
- Credential Discovery
- WMI Enumeration
- Network Discovery
- Process Creation Monitoring (Sysmon)

---

## MITRE ATT&CK

- T1087 – Account Discovery
- T1555 – Credentials from Password Stores
- T1047 – Windows Management Instrumentation
- T1049 – System Network Connections Discovery

---

## Technologies

- Windows 11
- Sysmon
- Elastic Agent
- Elasticsearch
- Kibana
- PowerShell
- WMI

---

> **A detailed investigation report (`REPORT.md`) is included in this repository, covering the attack methodology, command explanations, detection logic, SOC investigation, MITRE mapping, and incident response process.
