# Phishing to Persistence

## Objective

Demonstrate how an attacker can execute code, abuse PowerShell, download content, and establish persistence while generating telemetry that can be detected and investigated.

## Attack Chain

1. MSHTA Execution
2. PowerShell Execution
3. Encoded PowerShell Execution
4. PowerShell Download Activity
5. Scheduled Task Creation (Persistence)
6. Registry Run Key Persistence

## Attack Flow

```text
MSHTA Execution
        ↓
PowerShell Execution
        ↓
Encoded PowerShell
        ↓
Download Activity
        ↓
Scheduled Task Creation
        ↓
Registry Run Key Persistence
```

## Status

* ✅ Attack Simulated
* ✅ Sysmon Events Validated
* ✅ Logs Ingested into Elastic
* ✅ Alerts Triggered
* ✅ Screenshots Collected

## Investigation

This investigation documents:

* Attack lifecycle
* Generated telemetry
* Sysmon events
* Elastic detections
* Alert validation
* Evidence collection
* MITRE ATT&CK mapping
* Analyst findings

## Key Learning Outcomes

* Understanding attacker execution techniques
* Understanding PowerShell abuse and obfuscation
* Understanding persistence mechanisms
* Validating detection coverage
* Correlating telemetry with alerts
* Performing security investigations using Elastic SIEM

