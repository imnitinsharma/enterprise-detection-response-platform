# Credential Access Detection using Elastic SIEM

## Overview

This project simulates a realistic credential access attack against a Windows endpoint using techniques commonly observed during post-compromise activity.

The attack includes exporting the Windows Security Account Manager (SAM) database and dumping the Local Security Authority Subsystem Service (LSASS) process memory. Sysmon telemetry is collected, ingested into Elastic SIEM, detected using custom detection rules, and investigated from a SOC analyst's perspective.

---

## Attack Flow

```
Initial Access
      ↓
SAM Hive Export
      ↓
LSASS Memory Dump
      ↓
Elastic SIEM Detection
      ↓
SOC Investigation
```

---

## Commands Executed

```cmd
reg save HKLM\SAM C:\Windows\Temp\sam.bak /y
```

```cmd
tasklist | findstr lsass
```

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\lsass.dmp full
```

---

## MITRE ATT&CK

- T1003.001 – LSASS Memory
- T1003.002 – Security Account Manager (SAM)

---

## Technologies

- Windows 11
- Sysmon
- Elastic Agent
- Elasticsearch
- Kibana

---

## Repository Contents

- Attack Simulation
- Detection Rules
- Evidence
- Kibana Alerts
- SOC Investigation
- Incident Response
- MITRE ATT&CK Mapping

> 📄 A detailed **REPORT.md** is included explaining every attack step, command, detection logic, investigation, and incident response.
