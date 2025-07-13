# MSSQL Studio

MSSQL has tight integration with Active Directory and .NET. MSSQL Server is similar to SQL but is more of a dialect [Transact-SQL (T-SQL)](https://learn.microsoft.com/en-us/sql/t-sql/language-reference?view=sql-server-ver16), which extends it with programming, local variable and support functions.

Basic Connect

```sql
# Connect
impacket-mssqlclient mczen:'pass@123'@10.10.15.129

# Check user
SELECT SYSTEM_USER;
```

{% hint style="info" %}
Connecting to and managing `MSSQL Server` instances is done with [Microsoft SQL Server Management Studio (SSMS)](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16) or sqlcmd.
{% endhint %}

### <mark style="color:yellow;">Enumerating Server logins</mark>

There are logins and users, both types of security principals. Logins are server-level and users are database-level.&#x20;

```sql
# Enumerate logins and server roles
SELECT r.name, r.type_desc, r.is_disabled, sl.sysadmin, sl.securityadmin, sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin
FROM master.sys.server_principals r
LEFT JOIN master.sys.syslogins sl ON sl.sid = r.sid
WHERE r.type IN ('S','E','X','U','G');
```

### <mark style="color:yellow;">Enumerating Database</mark>

Check databases and what principals owns them.

```sql
SELECT a.name AS 'database', b.name AS 'owner', is_trustworthy_on
FROM sys.databases a
JOIN sys.server_principals b ON a.owner_sid = b.sid;
```

### <mark style="color:yellow;">Enumerating Database Users</mark>

```sql
USE webshop;
EXECUTE sp_helpuser;
```
