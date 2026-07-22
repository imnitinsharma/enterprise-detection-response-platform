# Credential Access Detection using Elastic SIEM

## Objective

The objective of this project was to simulate a realistic Windows credential access attack using native Windows utilities and validate custom Elastic SIEM detection rules.

The attack demonstrates how an attacker can obtain sensitive credential data by exporting the Security Account Manager (SAM) database and dumping the Local Security Authority Subsystem Service (LSASS) process memory. Sysmon telemetry was collected, forwarded to Elastic SIEM, detected using custom detection rules, and investigated from a SOC analyst's perspective.

---

# Lab Setup

| Component | Description |
|-----------|-------------|
| Operating System | Windows 11 Virtual Machine |
| Endpoint Monitoring | Sysmon |
| Log Forwarding | Elastic Agent |
| SIEM Platform | Elasticsearch + Kibana |
| Detection Method | Custom KQL Detection Rules |

---

# Attack Scenario

After gaining initial access to a Windows system, attackers often attempt to steal credentials before moving further into the network.

Instead of exploiting another vulnerability immediately, they try to collect password hashes and authentication material already stored on the compromised machine.

Two of the most valuable targets are:

- Security Account Manager (SAM)
- Local Security Authority Subsystem Service (LSASS)

If successful, the attacker can obtain credential information that may later be used for privilege escalation, lateral movement, or persistence.

---

# Understanding the Attack

## What is the Security Account Manager (SAM)?

The Security Account Manager (SAM) is a protected Windows registry database that stores information about local user accounts.

It contains:

- Usernames
- Security Identifiers (SIDs)
- Password hashes

Windows compares the stored password hash with the hash of the password entered during login to verify user authentication.

The SAM database does **not** store plaintext passwords.

---

## Why do attackers target SAM?

If attackers obtain a copy of the SAM database, they can:

- Extract password hashes
- Perform offline password cracking
- Conduct Pass-the-Hash attacks
- Recover administrator credentials

Stealing password hashes is often easier than attempting to guess passwords directly.

---

## What is LSASS?

LSASS stands for **Local Security Authority Subsystem Service**.

It is a critical Windows process responsible for:

- User authentication
- Security policy enforcement
- Creating access tokens
- Managing Windows logon sessions

Whenever a user logs into Windows, LSASS temporarily stores authentication information in memory.

This memory may contain:

- NTLM hashes
- Kerberos tickets
- Cached credentials
- Authentication tokens
- Sometimes plaintext passwords (depending on system configuration)

---

## Why do attackers target LSASS?

LSASS contains some of the most valuable credential information on a Windows system.

By dumping its memory, attackers can recover authentication data without knowing the user's password.

These credentials are commonly used for:

- Privilege Escalation
- Lateral Movement
- Persistence
- Domain Compromise

For this reason, monitoring access to LSASS is a high priority for SOC teams.

---

# Attack Execution

## Step 1 - Export the SAM Registry Hive

### Command Used

```cmd
reg save HKLM\SAM C:\Windows\Temp\sam.bak /y
```

### Command Breakdown

**reg save**

Exports a registry hive into a backup file.

**HKLM\SAM**

Specifies the Security Account Manager registry hive.

**C:\Windows\Temp\sam.bak**

Location where the exported registry hive will be saved.

**/y**

Overwrites the file if it already exists.

---

### What happens inside Windows?

Windows reads the protected SAM registry hive and creates a copy of it on disk.

The original registry remains unchanged.

A new file named:

```

C:\Windows\Temp\sam.bak

```

is created.

---

### Why do attackers use this command?

Instead of stealing passwords directly, attackers first collect password hashes.

These hashes can later be extracted offline using forensic or offensive security tools such as:

- Mimikatz
- Impacket
- Hashcat
- John the Ripper

This allows attackers to attempt credential recovery without interacting with the victim system again.

---

## Step 2 - Locate the LSASS Process

### Command Used

```cmd
tasklist | findstr lsass
```

---

### Command Breakdown

**tasklist**

Displays all running Windows processes.

**findstr lsass**

Filters the output to display only the LSASS process.

---

### What happens inside Windows?

Windows lists every active process.

The command filters the list and returns:

- lsass.exe
- Process ID (PID)

Example:

```

lsass.exe 748

```

---

### Why do attackers perform this step?

The next command requires the Process ID (PID).

Without the PID, Windows cannot dump the memory of the LSASS process.

---

## Step 3 - Dump LSASS Memory

### Command Used

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 748 C:\Windows\Temp\lsass.dmp full
```

*(Replace **748** with the actual PID returned by your system.)*

---

### Command Breakdown

**rundll32.exe**

A legitimate Microsoft utility used to execute functions inside DLL files.

---

**comsvcs.dll**

A legitimate Windows DLL.

It contains the **MiniDump()** function.

---

**MiniDump**

Creates a memory dump of the specified process.

---

**748**

The Process ID (PID) of LSASS.

---

**C:\Windows\Temp\lsass.dmp**

Destination where the memory dump is stored.

---

**full**

Creates a full memory dump.

---

### What happens inside Windows?

Windows opens the LSASS process.

The MiniDump function copies its memory contents.

A complete memory dump is written to:

```

C:\Windows\Temp\lsass.dmp

```

---

### Why do attackers use this technique?

The dump file may contain:

- NTLM password hashes
- Kerberos tickets
- Authentication tokens
- Cached credentials

Attackers can later analyze this file offline to recover credentials and gain higher privileges within the environment.

---

# Detection in Elastic SIEM

Sysmon Process Creation (Event ID 1) recorded each command execution.

Elastic Agent forwarded the logs into Elasticsearch.

Custom detection rules generated security alerts inside Kibana.

---

## Detecting SAM Registry Export

### KQL Query

```kql
process.name : "reg.exe" and process.command_line : *SAM*
```

### Detection Purpose

This query identifies execution of **reg.exe** where the command line references the SAM registry hive.

Because exporting the SAM database is uncommon during normal system administration, this activity is considered suspicious and may indicate credential theft.

---

## Detecting LSASS Memory Dump

### KQL Query

```kql
process.name : "rundll32.exe" and process.command_line : *comsvcs.dll*
```

### Detection Purpose

This query detects abuse of **rundll32.exe** executing the MiniDump function inside **comsvcs.dll**.

This is a well-known Windows LOLBin technique frequently used by attackers to dump LSASS memory while attempting to blend into legitimate system activity.

---

# Evidence

The following evidence was collected during the investigation.

### Evidence 1

SAM Registry Hive Export detected inside Kibana Discover.

---

### Evidence 2

Execution of the LSASS memory dump command on the Windows endpoint.

---

### Evidence 3

Sysmon process creation event showing the complete LSASS dump command line inside Kibana Discover.

---

### Evidence 4

Elastic Security dashboard displaying generated security alerts.

---

### Evidence 5

Custom Elastic detection rule successfully triggering on LSASS memory dumping activity.

---

# SOC Investigation

During the investigation, the following observations were made.

- reg.exe exported the Security Account Manager registry hive.
- rundll32.exe executed the MiniDump function from comsvcs.dll.
- A full memory dump of the LSASS process was created.
- Sysmon generated Process Creation events for each command.
- Elastic Agent successfully forwarded the telemetry.
- Custom detection rules generated security alerts.
- Kibana Discover confirmed raw process execution logs.
- Elastic Security Alerts confirmed successful detection.

No persistence mechanisms or lateral movement activity were performed as this project focused solely on credential access techniques.

---

# MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| OS Credential Dumping: LSASS Memory | T1003.001 |
| OS Credential Dumping: Security Account Manager | T1003.002 |

---

# Indicators of Compromise (IOCs)

## Processes

- reg.exe
- tasklist.exe
- rundll32.exe

---

## Files Created

```
C:\Windows\Temp\sam.bak
```

```
C:\Windows\Temp\lsass.dmp
```

---

## Registry Hive Accessed

```
HKLM\SAM
```

---

## Suspicious Command Lines

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

# Incident Response

A SOC analyst should perform the following actions after detecting this activity:

1. Immediately isolate the affected endpoint from the network.

2. Verify whether the execution was authorized by a system administrator.

3. Preserve forensic evidence including memory dumps, registry hives, and relevant log files.

4. Investigate the parent process responsible for launching `reg.exe` and `rundll32.exe`.

5. Review additional Sysmon and Windows Event Logs for signs of persistence or lateral movement.

6. Reset passwords for affected accounts and invalidate any compromised credentials.

7. Block or restrict unauthorized access to sensitive utilities capable of dumping LSASS memory.

8. Continue monitoring the environment for additional credential theft or post-exploitation activity.

---

# Conclusion

This project successfully demonstrated two common Windows credential access techniques used by attackers after gaining access to a system.

The simulation showed how exporting the Security Account Manager (SAM) registry hive and dumping LSASS memory generate endpoint telemetry that can be detected using Sysmon and Elastic SIEM.

By creating custom detection rules, validating alerts, and performing a structured SOC investigation, the project demonstrates practical experience in endpoint monitoring, threat detection, and incident response within an enterprise security environment.
