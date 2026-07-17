# Internal Reconnaissance Attack Simulation

---

# Objective

The objective of this project is to simulate a realistic post-compromise reconnaissance phase performed by an attacker after obtaining access to a Windows endpoint.

Rather than relying on legacy Windows commands, this simulation uses PowerShell cmdlets and Windows Management Instrumentation (WMI), techniques frequently observed during real-world enterprise intrusions.

The generated activity is collected using Sysmon, ingested into Elastic SIEM, detected through custom detection rules, and investigated from the perspective of a Security Operations Center (SOC) analyst.

---

# Lab Environment

| Component | Purpose |
|-----------|----------|
| Windows 11 VM | Victim Machine |
| Sysmon | Endpoint Telemetry |
| Elastic Agent | Log Collection |
| Elasticsearch | Data Storage |
| Kibana | Detection & Investigation |

---

# Attack Scenario

After successfully compromising a workstation, the attacker wants to understand the environment before attempting privilege escalation or lateral movement.

The attacker performs targeted reconnaissance to identify privileged accounts, discover stored credentials, determine missing security patches, and identify active network connections.

---

# Attack Steps

---

## Step 1 — Enumerate Local Administrators

### Command

```powershell
Get-LocalGroupMember -Group "Administrators"
```

### What does it do?

Displays every account that belongs to the local Administrators group.

### Why does the attacker run it?

Administrators have elevated privileges.

Knowing these accounts helps the attacker:

- Target privileged users
- Plan privilege escalation
- Identify high-value accounts

### MITRE

T1087 – Account Discovery

---

## Step 2 — Search Stored Credentials

### Command

```cmd
cmdkey /list
```

### What does it do?

Lists credentials saved inside Windows Credential Manager.

These may include:

- RDP passwords
- Network credentials
- Domain credentials
- Cached authentication tokens

### Why does the attacker run it?

If credentials already exist, the attacker may gain access to additional systems without needing to crack passwords.

This can significantly speed up lateral movement.

### MITRE

T1555 – Credentials from Password Stores

---

## Step 3 — Enumerate Installed Security Updates

### Command

```cmd
wmic qfe get HotFixID,Description,InstalledOn
```

### What does it do?

Displays installed Windows security patches (Hotfixes).

### Why does the attacker run it?

Attackers compare installed patches against publicly known vulnerabilities.

Missing patches may indicate exploitable weaknesses.

This helps them decide whether privilege escalation exploits are likely to succeed.

### MITRE

T1047 – Windows Management Instrumentation

---

## Step 4 — Discover Active Network Connections

### Command

```powershell
Get-NetTCPConnection -State Established
```

### What does it do?

Lists currently established TCP connections.

It displays:

- Local IP
- Local Port
- Remote IP
- Remote Port

### Why does the attacker run it?

This reveals systems the victim is already communicating with.

These may include:

- Domain Controllers
- File Servers
- SQL Servers
- Application Servers

The information is useful for planning lateral movement.

### MITRE

T1049 – System Network Connections Discovery

---

# Telemetry Generated

Sysmon Process Creation Events

- PowerShell execution
- cmdkey execution
- wmic execution
- Command-line arguments
- Parent process
- User context
- Process GUID
- Host information

These logs are forwarded to Elastic SIEM through Elastic Agent.

---

# Detection Strategy

Custom detection rules were created to identify reconnaissance activity.

Example detections include:

- PowerShell Administrator Enumeration
- Credential Manager Access
- WMIC Hotfix Enumeration
- Network Discovery via PowerShell

---

# Investigation

SOC analysts validated:

- Process Name
- Full Command Line
- Parent Process
- Executing User
- Hostname
- Timestamp
- Alert Severity
- Timeline Correlation

Multiple reconnaissance commands executed within a short period indicate likely post-compromise activity.

---

# MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Account Discovery | T1087 |
| Credentials from Password Stores | T1555 |
| Windows Management Instrumentation | T1047 |
| System Network Connections Discovery | T1049 |

---

# Indicators of Compromise (IOCs)

Observed process executions:

```text
powershell.exe
cmdkey.exe
wmic.exe
```

Suspicious command lines:

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

# Incident Response

Upon detecting this reconnaissance activity, the SOC team should perform the following actions:

## 1. Validate the Alert

- Confirm whether the commands were executed by an authorized administrator or an unknown user.
- Review the full process command line and execution context.

## 2. Investigate the Timeline

- Identify preceding events such as suspicious logins, PowerShell execution, or script downloads.
- Correlate related alerts to determine whether the activity is part of a larger attack.

## 3. Assess the Endpoint

- Examine running processes and persistence mechanisms.
- Check for newly created user accounts, scheduled tasks, registry modifications, or malicious services.

## 4. Determine Impact

- Identify whether privileged accounts or cached credentials were accessed.
- Review network connections for signs of lateral movement or communication with sensitive systems.

## 5. Contain the Threat

- Isolate the affected endpoint from the network if malicious activity is confirmed.
- Disable compromised accounts and revoke exposed credentials where necessary.

## 6. Eradicate

- Remove malicious scripts, tools, and persistence mechanisms.
- Apply missing security patches and harden system configurations.

## 7. Recovery

- Restore the endpoint to a trusted state if required.
- Continue monitoring for recurring reconnaissance or follow-on attack activity.

## 8. Lessons Learned

- Enhance detection rules for PowerShell, WMIC, and credential discovery activity.
- Review administrative privileges and restrict unnecessary local administrator access.
- Conduct threat hunting to identify similar behavior across the environment.

---

# Conclusion

This project demonstrates how modern attackers perform focused internal reconnaissance using PowerShell and WMI after gaining access to a Windows endpoint. The generated telemetry was successfully collected, detected, and investigated within Elastic SIEM, providing hands-on experience in detection engineering, endpoint monitoring, MITRE ATT&CK mapping, and SOC incident response.
