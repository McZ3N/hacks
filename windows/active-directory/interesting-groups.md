---
description: AD | Groups | Privileges | Permissions | LDAP |
---

# Interesting Groups

Active Directory (AD) contains several built-in groups that grant extensive privileges to their members. These groups can be leveraged by attackers to escalate privileges and compromise the entire domain. Here are some of the most critical groups:

<table data-header-hidden><thead><tr><th width="247">Group</th><th>Description</th></tr></thead><tbody><tr><td>Default Administrators</td><td>Domain Admins and Enterprise Admins "super" groups.</td></tr><tr><td>Server Operators</td><td>Members can modify services, access SMB shares, and backup files.</td></tr><tr><td>Backup Operators</td><td>Can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. </td></tr><tr><td>Print Operators</td><td>Logon to DCs locally and "trick" Windows into loading a malicious driver.</td></tr><tr><td>Hyper-V Administrators</td><td>If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.</td></tr><tr><td>Account Operators</td><td>Can modify non-protected accounts and groups in the domain.</td></tr><tr><td>Remote Desktop Users</td><td>Often granted additional rights such as <em>Allow Login Through Remote Desktop Services.</em></td></tr><tr><td>Remote Management Users</td><td>Members are allowed to logon to DCs with PSRemoting.</td></tr><tr><td>Group Policy Creator Owners</td><td>Members can create new GPOs but would need to be delegated additional permissions to link GPOs.</td></tr><tr><td>Schema Admins</td><td>Members can modify the Active Directory schema structure and can backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.</td></tr><tr><td>DNS Admins</td><td>They can load a malicious DLL and wait for a reboot as a persistence mechanism. </td></tr></tbody></table>

#### Enumerate

```powershell
# Get group detail
Get-ADGroup -Identity "Schema Admins" -Properties *
```

