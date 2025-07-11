---
description: Various tools and commands I've needed during solving boxes and or pentesting.
---

# Windows

#### RPC (Remote Procedure Call)

```bash
# Connect
rpcclient -U "" -N 10.10.10.161

# Enumerate users
rpcclient $> enumdomusers

# Enumberate groups
enumdomgroups

# Check group members
querygroup 0x200

# Check user account
queryuser 0x1f4 
```

#### Check rights file

```powershell
icacls C:\Windows\System32\cmd.exe
```

#### RDP

```powershell
# Connect to RDP
xfreerdp /u:devtest /p:password /v:172.16.139.175 /drive:linux,/home/user /dynamic-resolution

# Enable RDP adding a new registry key
crackmapexec smb 192.168.0.1 -u "username" -H "NT_HASH" -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

#### Enable running scripts

```powershell
Set-ExecutionPolicy Unrestricted
```

#### Check rights file

```powershell
icacls C:\Windows\System32\cmd.exe
```

Mounting SMB share in linux

```bash
mount -t cifs //10.10.10.134/backups /mnt -o user=,password=
```

Mounting .vdh file

```bash
# Install guestmount
apt install libguestfs-tools

# Mount the vhd file
guestmount --add /mnt/WindowsImageBackup/test/Backup\ 2019-02-22\ 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt2/
```

###
