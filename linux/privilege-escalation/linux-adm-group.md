---
description: Members of the adm group are able to read all logs stored in /var/log.
---

# Linux ADM group

### ADM or administration group

Users in the `adm` group have read permissions on all logs in `/var/log`. This could allow them to access sensitive information such as passwords, error messages, and system activity. This could lead to finding credentials or other sensitive information.

```bash
$ id
uid=1002(auser) gid=1002(auser) groups=1002(auser),4(adm)
```

### Aureport

Aureport is a command-line utility which can be used to create reports from audit log files stored in `/var/log/audit/`. It can create crypto reports or reports from tty keystrokes.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
In Linux, TTY (TeleTypewriter) refers to a text-based interface that allows you to interact with the system, aureport can log TTY using the --tty flag.
{% endhint %}
